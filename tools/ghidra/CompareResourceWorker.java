// Adapted worker node region; explicit lower models and separate original I/O probes.
// @category SMT4
import ghidra.pcode.emu.PcodeThread;
import ghidra.pcode.utils.Utils;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.pcode.PcodeOp;
import java.nio.file.*;
import java.security.MessageDigest;
import java.util.*;
import java.io.*;

public class CompareResourceWorker extends CompareResourceSync {
    static final long BEGIN=0x113de8, BOUNDARY=0x113dd4, GLOBAL=0x465000;
    static final long PREV=DESC+0x200, NEXT=DESC+0x400, ALT=DESC+0x600;
    static final long ACQUIRE=0x2c4350, UNLOCK=0x2c54a4, CHECK=0x2c54bc, FREE=0x2c43b4;
    static final long PRE=0x720000, CALLBACK=0x720004, CALLBACK2=0x720008, IO=0x710000;
    static final long MASK=0xffffffffL;
    int cases, probes;
    boolean probeMode;
    Set<Long> probeVisited=new TreeSet<>();
    @Override boolean originalCode(long pc) {
        return within(pc,4,BEGIN,0x113e70) || within(pc,4,0x114070,0x114098) ||
            within(pc,4,0x114134,0x1142e8) || (probeMode && within(pc,4,0x113e80,0x114134));
    }
    class WorkerMachine extends SyncMachine {
        List<String> trace=new ArrayList<>();
        List<Long> stateWrites=new ArrayList<>();
        boolean freed;
        int locks;
        WorkerMachine(byte[] mapped,byte[] binary) { super(mapped,binary); }
        @Override public void beforeStore(PcodeThread<byte[]> t,PcodeOp op,AddressSpace space,
                byte[] offset,int size,byte[] value) {
            long a=Utils.bytesToLong(offset,offset.length,false);
            require(within(a,size,STACK-0x1000,STACK) || within(a,size,DESC,DESC+0x800) ||
                    a==GLOBAL+12 || (probeMode && (a==GLOBAL+4 || within(a,size,0x903000,0x903040))),
                    "Unexpected worker store "+Long.toHexString(a));
            require(!freed || !within(a,size,DESC,DESC+0x144),"Write after descriptor free");
            if(probeMode && a==DESC && size==4) stateWrites.add(Utils.bytesToLong(value,4,false)&MASK);
        }
        @Override public void beforeLoad(PcodeThread<byte[]> t,PcodeOp op,AddressSpace space,
                byte[] offset,int size) {
            long a=Utils.bytesToLong(offset,offset.length,false);
            require(within(a,size,DESC,DESC+0x800) || within(a,size,0x100000,0x477000) ||
                    within(a,size,BUILD,BUILD+codeSize) || within(a,size,STACK-0x1000,STACK) ||
                    (probeMode && within(a,size,0x903000,0x903100)),"Unexpected worker read "+Long.toHexString(a));
            require(!freed || !within(a,size,DESC,DESC+0x144),"Read after descriptor free");
        }
        long get(long address) { return word(memory(address,4),0); }
        void init(boolean rebuiltPath,byte[] initial,byte[] globals) {
            freed=false; locks=0; trace.clear(); initialize(rebuiltPath,0,new byte[0x144]);
            memory(DESC,initial); memory(GLOBAL,globals);
            if(rebuiltPath) { register("r0",DESC); thread.overrideCounter(toAddr(entries[0])); }
            else {
                register("r7",DESC); register("r8",GLOBAL+16); register("r9",GLOBAL);
                register("r10",0); register("r11",1); register("sp",STACK-0x300);
                thread.overrideCounter(toAddr(BEGIN));
            }
            executing=true;
        }
        void event(String name) {
            // Snapshots at external boundaries detect publication/release ordering.
            trace.add(name+":"+HexFormat.of().formatHex(memory(DESC,0x800))+":"+
                HexFormat.of().formatHex(memory(GLOBAL,0x20)));
        }
        void lockCall(long pc,int effect) {
            require((register("sp")&7)==0,"Stack alignment");
            if(pc==ACQUIRE) {
                require(register("r2")==1 && register("r3")==0,"Acquire count/wait-all");
                require(get(register("r1"))==get(GLOBAL+16),"Acquire handle snapshot");
                require(get(register("sp"))==MASK && get(register("sp")+4)==MASK,"Acquire timeout");
                require(within(register("r0"),4,STACK-0x1000,STACK),"Acquire out pointer");
                writeWord(register("r0"),0);
                event("acquire"); locks++;
                // Change dispatch fields between precheck and locked reload.
                if(effect==2 && locks==1) {
                    writeWord(DESC+0x130,CALLBACK2); writeWord(DESC+0x134,0x87654320L);
                }
                writeWord(GLOBAL+16,(get(GLOBAL+16)+1)&MASK);
            } else {
                require(register("r1")==get(GLOBAL+16) && register("r2")==1,"Unlock handle/count");
                require(within(register("r0"),4,STACK-0x1000,STACK),"Unlock out pointer");
                writeWord(register("r0"),7); event("unlock");
            }
            externalReturn(effect==3 ? 0x80000042L : 0);
        }
        long call(boolean rebuiltPath,byte[] initial,byte[] globals,int effect,long preState,long ioState) throws Exception {
            init(rebuiltPath,initial,globals);
            int steps=0;
            while(thread.getCounter().getOffset()!=(rebuiltPath ? RETURN : BOUNDARY)) {
                long pc=thread.getCounter().getOffset();
                if(pc==ACQUIRE || pc==UNLOCK) { lockCall(pc,effect); continue; }
                if(pc==CHECK) {
                    require(effect==3 && register("r0")==0x80000042L && register("r1")==1,"Result checker args");
                    event("check"); externalReturn(0xf1234567L); continue;
                }
                if(pc==PRE || pc==CALLBACK || pc==CALLBACK2) {
                    long arg=pc==PRE ? DESC+0x2c : get(DESC+0x134)==0 ? DESC : get(DESC+0x134);
                    require(register("r0")==arg,"Callback argument/fallback");
                    event("callback:"+pc+":"+arg);
                    writeWord(GLOBAL+16,(get(GLOBAL+16)^0x12345678L)&MASK);
                    if(pc==PRE) {
                        writeWord(DESC,preState); writeWord(DESC+0x138,PRE);
                    } else if(effect==1) {
                        writeWord(DESC+8,(get(DESC+8)+1)&MASK); writeWord(DESC+12,0);
                        writeWord(DESC+0x13c,ALT); writeWord(DESC+0x130,CALLBACK2);
                    }
                    externalReturn(0xdeadbeefL); continue;
                }
                if(pc==FREE) {
                    long arg=register("r0");
                    require(arg==DESC || arg==get(DESC+12),"Release argument");
                    if(arg==DESC) { require(get(DESC+12)==0,"Data clear before descriptor release"); freed=true; }
                    event("free:"+arg); writeWord(GLOBAL+16,(get(GLOBAL+16)+7)&MASK);
                    externalReturn(0xfedcba98L); continue;
                }
                if(pc==(rebuiltPath ? IO : 0x113e80)) {
                    if(rebuiltPath) require(register("r0")==DESC,"I/O block argument");
                    event("io"); writeWord(DESC,ioState); writeWord(DESC+0x12c,0x903000);
                    if(rebuiltPath) externalReturn(0); else thread.overrideCounter(toAddr(0x114070));
                    continue;
                }
                step(rebuiltPath,++steps);
            }
            if(rebuiltPath) finish(steps); else {
                require(register("sp")==STACK-0x300,"Region SP"); maxSteps=Math.max(maxSteps,steps);
            }
            for(byte value:memory(STACK-0x1000,0x800)) require(value==(byte)0x96,"Stack lower guard");
            return register(rebuiltPath ? "r0" : "r7");
        }
        void probe(long openResult,long readResult,long handle,int flags,boolean supplied) throws Exception {
            byte[] initial=new byte[0x800]; put(initial,12,supplied ? 0x904000 : 0); put(initial,36,flags);
            put(initial,40,0x80); byte[] global=new byte[0x20]; put(global,16,0x4567);
            init(false,initial,global); stateWrites.clear(); thread.overrideCounter(toAddr(0x113e80));
            memory(0x903000,new byte[0x100]); writeWord(0x465124,0x4444);
            // Fixture vtable and construction table. No original SDK object code executes.
            writeWord(0x420870,0x903080); writeWord(0x42087c,0x903080);
            writeWord(0x903050,0); writeWord(0x903084,0x730000);
            writeWord(0x90308c,0x730004); writeWord(0x9030a4,0x730008); writeWord(0x9030a8,0x73000c);
            List<Long> calls=new ArrayList<>(); List<Long> states=new ArrayList<>();
            int steps=0;
            while(thread.getCounter().getOffset()!=0x114084) {
                long pc=thread.getCounter().getOffset(), result=0;
                boolean ext=true;
                if(pc==0x2c244c) { require(register("r0")==24,"Object size"); result=0x903000; }
                else if(pc==0x2b9486 || pc==0x2b9468) { result=0; } // empty converted path fixture
                else if(pc==0x2bb944) {
                    require(register("r0")==0x903004 && register("r2")==1,"Open args");
                    writeWord(0x903004,handle); result=openResult;
                } else if(pc==0x730008) { require(register("r0")==0x903000,"Size object"); result=0x321; }
                else if(pc==0x730004) { require(register("r2")==0 && register("r3")==0 && get(register("sp"))==0,"Seek args"); }
                else if(pc==0x2bf7ec) {
                    require(register("r0")==((flags==1 || flags==17) ? 0x10000 : 0x100),"Allocation type");
                    require(register("r1")==0x100 && register("r2")==0 && register("r3")==0x321,"Allocation args");
                    require(get(register("sp"))==0x80 && get(register("sp")+4)==((flags==16 || flags==17) ? 0 : 1),"Allocation stack args");
                    result=0x904000;
                } else if(pc==0x2c3afc || pc==0x2c3a78) { require(register("r0")==0x4444,"I/O lock"); }
                else if(pc==0x73000c) {
                    require(get(GLOBAL+4)==1 && register("r0")==0x903000 && register("r2")==0x904000 && register("r3")==0x321,"Read args/busy");
                    writeWord(register("r1"),0x111); result=readResult;
                } else if(pc==0x2bce9c) { require(register("r0")==handle,"Handle preclose"); }
                else if(pc==0x2b9450) { require(register("r0")== (handle & ~1L),"Close handle"); }
                else if(pc==0x730000) { require(register("r0")==0x903000 && get(GLOBAL+4)==0,"Destructor object/busy"); }
                else ext=false;
                if(ext) {
                    calls.add(pc); states.add(get(DESC)); externalReturn(result); continue;
                }
                long before=thread.getCounter().getOffset(); step(false,++steps); probeVisited.add(before);
            }
            require(get(DESC)==4 && get(DESC+0x12c)==0 && get(DESC+24)==0x321 && get(GLOBAL+4)==0,"State-0 final state");
            List<Long> expected=new ArrayList<>(List.of(0x2c244cL,0x2b9486L,0x2b9468L,0x2bb944L,0x730008L,0x730004L));
            if(!supplied) expected.add(0x2bf7ecL);
            expected.addAll(List.of(0x2c3afcL,0x73000cL,0x2c3a78L));
            if((handle & ~1L)!=0) { if((handle&1)!=0) expected.add(0x2bce9cL); expected.add(0x2b9450L); }
            expected.add(0x730000L);
            require(calls.equals(expected),"State-0 dependency sequence");
            require(states.get(calls.indexOf(0x730008L))==((openResult&0x80000000L)!=0 ? 5 : 0),"Negative open intermediate state");
            require(states.get(states.size()-1)==(((openResult|readResult)&0x80000000L)!=0 ? 5 : 0),"Negative read intermediate state");
            List<Long> expectedStates=new ArrayList<>();
            if((openResult&0x80000000L)!=0) expectedStates.add(5L);
            if((readResult&0x80000000L)!=0) expectedStates.add(5L);
            expectedStates.addAll(List.of(3L,4L));
            require(stateWrites.equals(expectedStates),"State-0 store sequence");
            probes++;
        }
    }
    void compare(WorkerMachine a,WorkerMachine b,byte[] initial,byte[] globals,int effect,long preState,long ioState,PrintWriter log) throws Exception {
        try {
            long x=a.call(false,initial,globals,effect,preState,ioState), y=b.call(true,initial,globals,effect,preState,ioState);
            require(x==y,"Next descriptor difference");
            require(a.trace.equals(b.trace),"Dependency trace/snapshot difference");
            require(Arrays.equals(a.memory(DESC,initial.length),b.memory(DESC,initial.length)),"Descriptor/neighbors difference");
            require(Arrays.equals(a.memory(GLOBAL,globals.length),b.memory(GLOBAL,globals.length)),"Globals difference");
            // Independent expected final bytes, including all opaque fields/guards.
            byte[] expected=initial.clone(); long state=word(initial,0), next=word(initial,0x13c);
            if(effect==2) { put(expected,0x130,CALLBACK2); put(expected,0x134,0x87654320L); }
            boolean terminal=state==4 || state==5;
            if(terminal) {
                long remaining=(word(initial,4)-word(initial,8))&MASK; put(expected,4,remaining);
                boolean remove=remaining==0 || (remaining&0x80000000L)!=0;
                if(remove) {
                    long previous=word(initial,0x140);
                    if(previous!=0) put(expected,(int)(previous-DESC)+0x13c,next);
                    if(next!=0) put(expected,(int)(next-DESC)+0x140,previous);
                    put(expected,12,0);
                }
                require(a.freed==remove,"Signed retention oracle");
            } else {
                if(word(initial,0x138)!=0) { state=preState; put(expected,0x138,0); }
                if(state==0) { state=4; put(expected,0x12c,0); }
                else if(state==3) state=4;
                put(expected,0,state);
                if((state==4 || state==5) && word(expected,0x130)!=0 && effect==1) {
                    put(expected,8,(word(initial,8)+1)&MASK); put(expected,12,0);
                    put(expected,0x13c,ALT); put(expected,0x130,CALLBACK2); next=ALT;
                }
                require(!a.freed,"New terminal node must not be cleaned in same step");
            }
            require(x==next,"Next descriptor oracle");
            require(Arrays.equals(expected,a.memory(DESC,expected.length)),"Independent memory oracle");
        } catch(Exception ex) { throw new IllegalStateException("Worker case "+cases+" state="+word(initial,0)+" effect="+effect+" pre="+preState,ex); }
        log.printf("%d\t%d\t%d\t%d\t%d%n",++cases,word(initial,0),effect,preState,ioState);
    }
    @Override public void run() throws Exception {
        Path out=Path.of(getScriptArgs()[0]); require(!Files.exists(out.resolve("comparison.json")),"Output exists");
        byte[] mapped=new byte[0x377000];
        require(currentProgram.getMemory().getBytes(toAddr(0x100000),mapped)==mapped.length,"Map");
        require(HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(mapped)).equals(
            "834938d18d2b7c688311c46c27bed813d0d7a9f8e3cbb61da8a6a3f23d360ebd"),"Hash");
        byte[] binary=Files.readAllBytes(out.resolve("resource-worker.bin")); codeSize=binary.length;
        require(codeSize>0 && codeSize<=0x2000,"Binary size");
        entries[0]=Long.parseLong(Files.readAllLines(out.resolve("entries.txt")).get(0));
        WorkerMachine a=new WorkerMachine(mapped,binary),b=new WorkerMachine(mapped,binary);
        Random rng=new Random(BEGIN);
        try(PrintWriter log=new PrintWriter(Files.newBufferedWriter(out.resolve("results.tsv")))) {
            log.println("case\tstate\teffect\tpre_state\tio_state");
            for(long state:new long[]{0,1,2,3,4,5,6,0x80000000L,MASK})
            for(int links=0;links<4;links++) for(int effect=0;effect<4;effect++)
            for(int variant=0;variant<24;variant++) {
                byte[] initial=new byte[0x800],globals=new byte[0x20]; rng.nextBytes(initial); rng.nextBytes(globals);
                long[] counters={0,1,2,0x7fffffffL,0x80000000L,MASK};
                put(initial,0,state); put(initial,4,counters[variant%6]); put(initial,8,counters[(variant/4)%6]);
                put(initial,12,variant%2==0 ? 0 : 0x904000); put(initial,16,variant%3==0 ? 0 : 1);
                put(initial,0x138,variant%2==0 ? 0 : PRE); put(initial,0x130,variant%3==0 ? 0 : CALLBACK);
                put(initial,0x134,variant%2==0 ? 0 : 0x87654320L);
                put(initial,0x140,(links&1)==0 ? 0 : PREV); put(initial,0x13c,(links&2)==0 ? 0 : NEXT);
                put(initial,0x200+0x13c,DESC); put(initial,0x400+0x140,DESC);
                put(globals,12,(links&1)==0 ? DESC : PREV);
                compare(a,b,initial,globals,effect,new long[]{0,1,3,4,5,6}[(variant/2)%6],variant%2==0 ? 0 : 5,log);
            }
            // Completion followed by three later passes: cleanup count is cumulative,
            // and a still-installed callback is not invoked again on terminal entry.
            for(int links=0;links<4;links++) {
                byte[] initial=new byte[0x800],globals=new byte[0x20];
                rng.nextBytes(initial); rng.nextBytes(globals);
                put(initial,0,3); put(initial,4,3); put(initial,8,0); put(initial,12,0x904000); put(initial,16,0);
                put(initial,0x138,0); put(initial,0x130,CALLBACK); put(initial,0x134,0);
                put(initial,0x140,(links&1)==0 ? 0 : PREV); put(initial,0x13c,(links&2)==0 ? 0 : NEXT);
                put(initial,0x200+0x13c,DESC); put(initial,0x400+0x140,DESC); put(initial,0x600+0x140,DESC);
                put(globals,12,(links&1)==0 ? DESC : PREV);
                for(int pass=0;pass<4;pass++) {
                    compare(a,b,initial,globals,pass==0 ? 1 : 0,0,0,log);
                    require(a.freed==(pass==3),"Repeated-pass cleanup timing");
                    initial=a.memory(DESC,0x800); globals=a.memory(GLOBAL,0x20);
                }
            }
        }
        int regionInstructions=visited.size();
        StringBuilder listing=new StringBuilder();
        for(long[] range:new long[][]{{BEGIN,0x113e70},{0x114070,0x114098},{0x114134,0x1142e8}})
            for(long pc=range[0];pc<range[1];pc+=4) {
                require(visited.contains(pc),"Unvisited region instruction "+Long.toHexString(pc));
                var instruction=currentProgram.getListing().getInstructionAt(toAddr(pc));
                require(instruction!=null,"Missing Ghidra instruction");
                listing.append(String.format("%08x %s%n",pc,instruction));
            }
        Files.writeString(out.resolve("original-region-ghidra.txt"),listing);
        Files.writeString(out.resolve("region-addresses.txt"),visited.toString());
        probeMode=true;
        try(PrintWriter log=new PrintWriter(Files.newBufferedWriter(out.resolve("state0-probes.tsv")))) {
            log.println("open_result\tread_result\thandle\tflags\tsupplied\tstate_stores");
            for(long open:new long[]{0,0x80000001L}) for(long read:new long[]{0,0xffffffffL})
            for(long handle:new long[]{0,1,0x4560,0x4561}) for(int flags:new int[]{0,1,16,17,2})
            for(boolean supplied:new boolean[]{false,true}) {
                a.probe(open,read,handle,flags,supplied);
                log.printf("%d\t%d\t%d\t%d\t%b\t%s%n",open,read,handle,flags,supplied,a.stateWrites);
            }
        }
        Files.writeString(out.resolve("probe-addresses.txt"),probeVisited.toString());
        Files.writeString(out.resolve("comparison.json"),String.format(Locale.ROOT,
            "{\"worker_cases\":%d,\"state0_probes\":%d,\"region_original_instruction_addresses\":%d,\"state0_original_instruction_addresses\":%d,\"binary_bytes\":%d,\"max_steps\":%d,\"full_worker_recovered\":false,\"state0_block_modeled_in_comparison\":true,\"live_verified\":false}\n",
            cases,probes,regionInstructions,probeVisited.size(),codeSize,maxSteps));
        println("SMT4_WORKER_COMPARE_OK");
    }
}
