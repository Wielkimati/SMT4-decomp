// Adapted state-zero block with lower file/conversion/allocation models.
// @category SMT4
import ghidra.pcode.emu.PcodeThread;
import ghidra.pcode.utils.Utils;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.pcode.PcodeOp;
import java.nio.file.*;
import java.security.MessageDigest;
import java.util.*;
import java.io.*;

public class CompareResourceWorkerIo extends CompareResourceSync {
    static final long BEGIN=0x113e80, END=0x114070, OBJ=0x903000, VT=0x903100;
    static final long GLOBAL=0x465000, LOCK=0x465124, TABLE=0x420870, MASK=0xffffffffL;
    int cases;
    boolean recoveredAllocation;
    IoMachine makeMachine(byte[] mapped,byte[] binary) { return new IoMachine(mapped,binary); }
    void preChecks(byte[] mapped,byte[] binary,Path out) throws Exception {}
    String extraChecks(byte[] mapped,byte[] binary,Path out) throws Exception { return ""; }
    @Override boolean originalCode(long pc) {
        return within(pc,4,BEGIN,END) || within(pc,4,0x114098,0x114134);
    }
    class IoMachine extends SyncMachine {
        List<String> trace=new ArrayList<>();
        List<Long> calls=new ArrayList<>(), states=new ArrayList<>();
        boolean destroyed;
        IoMachine(byte[] mapped,byte[] binary) { super(mapped,binary); }
        long get(long a) { return word(memory(a,4),0); }
        void setupAllocation(byte[] initial,long length,long allocation) {}
        boolean allocationStep(long pc,boolean rebuiltPath) throws Exception { return false; }
        void finishAllocation() {}
        int convertedUnit(int index) { return 0x8100+index; }
        int pathCount(int profile) { return new int[]{0,1,4,2,4,120}[profile]; }
        int pathFailure(int profile) { return profile==3 ? 0 : profile==4 ? 2 : -1; }
        int pathStride(int index) { return 1+index%3; }
        long pathTarget(boolean path,int kind) { return path ? 0x710000+4*kind : new long[]{0x2b9486,0x2b9468,0x2c63dc}[kind]; }
        long initializePath(boolean path,long state) throws Exception {
            writeWord(state,0xfeed1234L); writeWord(state+4,0x98760000L); return 0;
        }
        void checkPathState(long state,int converted) {
            require(get(state)==0xfeed1234L+converted && get(state+4)==0x98760000L+converted,"Conversion state continuity");
        }
        void advancePathState(long state,int converted) {
            writeWord(state,0xfeed1234L+converted); writeWord(state+4,0x98760000L+converted);
        }
        long measurePath(boolean path,long expected) throws Exception { return expected; }
        long convertPath(boolean path,long expected,int ch) throws Exception {
            memory(register("r0"),new byte[]{(byte)ch,(byte)(ch>>8)}); return expected;
        }
        long openTarget(boolean path) { return 0x2bb944; }
        long closeTarget(boolean path) { return 0x2b9450; }
        long precloseTarget(boolean path) { return 0x2bce9c; }
        long releasePayload() { return 0xdeadbeefL; }
        long executePreclose(boolean path,int effect) throws Exception {
            if(effect==2) writeWord(OBJ+4,precloseReplacement());
            return 0;
        }
        long precloseReplacement() { return 0x81234561L; }
        void executeClose(boolean path,long handle) throws Exception {}
        void executeDestroy(boolean path) throws Exception {}
        long executeOpen(boolean path,long result,long handle,long pathPointer,int units) throws Exception {
            writeWord(OBJ+4,handle); return result;
        }
        void expectedFileState(byte[] expectedObject) {} // Optional recovered cache/cursor oracle.
        @Override public void beforeStore(PcodeThread<byte[]> t,PcodeOp op,AddressSpace space,
                byte[] offset,int size,byte[] value) {
            long a=Utils.bytesToLong(offset,offset.length,false);
            require(within(a,size,STACK-0x1000,STACK) || within(a,size,DESC,DESC+0x144) ||
                within(a,size,OBJ,OBJ+24) || (a==GLOBAL+4 && size==4),"Unexpected I/O store "+Long.toHexString(a));
            require(!destroyed || !within(a,size,OBJ,OBJ+24),"Object write after destruction");
            if(a==DESC && size==4) states.add(Utils.bytesToLong(value,4,false)&MASK);
        }
        @Override public void beforeLoad(PcodeThread<byte[]> t,PcodeOp op,AddressSpace space,
                byte[] offset,int size) {
            long a=Utils.bytesToLong(offset,offset.length,false);
            require(within(a,size,STACK-0x1000,STACK) || within(a,size,DESC,DESC+0x144) ||
                within(a,size,OBJ,OBJ+0x200) || within(a,size,0x100000,0x477000) ||
                within(a,size,BUILD,BUILD+codeSize),"Unexpected I/O load "+Long.toHexString(a));
            require(!destroyed || !within(a,size,OBJ,OBJ+24),"Object read after destruction");
        }
        void event(long pc) {
            calls.add(pc); dependencyCalls++;
            trace.add(pc+":"+HexFormat.of().formatHex(memory(DESC,0x144))+":"+
                HexFormat.of().formatHex(memory(OBJ,24))+":"+get(GLOBAL+4)+":"+get(LOCK));
        }
        void call(boolean rebuiltPath,byte[] initial,long open,long read,long handle,
                long length,long allocation,int profile,int effect) throws Exception {
            initialize(rebuiltPath,0,initial); destroyed=false; calls.clear(); states.clear(); trace.clear();
            byte[] obj=new byte[0x200]; Arrays.fill(obj,(byte)0xa6); memory(OBJ,obj);
            memory(GLOBAL,new byte[0x20]); writeWord(GLOBAL+4,0x1234); writeWord(LOCK,0x4567);
            int adjustment=effect%2==0 ? 0 : 20;
            writeWord(TABLE,VT); writeWord(TABLE+12,adjustment==0 ? VT+0x80 : 0xabcddcbaL);
            writeWord(VT-48,adjustment);
            for(long v:new long[]{VT,VT+0x80}) {
                writeWord(v+4,0x730000); writeWord(v+12,0x730004);
                writeWord(v+36,0x730008); writeWord(v+40,0x73000c);
            }
            setupAllocation(initial,length,allocation);
            if(rebuiltPath) register("r0",DESC);
            else {
                register("r7",DESC); register("r9",GLOBAL); register("r10",0); register("r11",1);
                register("sp",STACK-0x300); thread.overrideCounter(toAddr(BEGIN));
            }
            int count=pathCount(profile);
            int failure=pathFailure(profile);
            int converted=0, cursor=0, measures=0, conversions=0, steps=0;
            long statePtr=0, pathPtr=0;
            List<Long> expectedCalls=new ArrayList<>(List.of(0x2c244cL,0x2b9486L));
            int successful=failure>=0 ? failure : count;
            for(int i=0;i<successful;i++) expectedCalls.addAll(List.of(0x2b9468L,0x2c63dcL));
            expectedCalls.add(0x2b9468L);
            if(failure>=0) expectedCalls.add(0x2c63dcL);
            expectedCalls.addAll(List.of(0x2bb944L,0x730008L,0x730004L));
            if(word(initial,12)==0) expectedCalls.add(0x2bf7ecL);
            expectedCalls.addAll(List.of(0x2c3afcL,0x73000cL,0x2c3a78L));
            boolean closes=(handle & ~1L)!=0;
            if(closes) {
                if((handle&1)!=0) expectedCalls.add(0x2bce9cL);
                expectedCalls.add(0x2b9450L);
            }
            boolean destroy=!(effect==3 && closes);
            if(destroy) expectedCalls.add(0x730000L);
            executing=true;
            while(thread.getCounter().getOffset()!=(rebuiltPath ? RETURN : END)) {
                long pc=thread.getCounter().getOffset(),result=0;
                if(allocationStep(pc,rebuiltPath)) continue;
                if(rebuiltPath) {
                    if(pc==precloseTarget(true)) pc=0x2bce9c;
                    else if(pc==openTarget(true)) pc=0x2bb944;
                    else if(pc==closeTarget(true)) pc=0x2b9450;
                    else if(pc==pathTarget(true,0)) pc=0x2b9486;
                    else if(pc==pathTarget(true,1)) pc=0x2b9468;
                    else if(pc==pathTarget(true,2)) pc=0x2c63dc;
                }
                boolean ext=true;
                if(pc==0x2c244c) { require(register("r0")==24,"Object allocation size"); result=OBJ; }
                else if(pc==0x2b9486) {
                    byte[] expected=new byte[24]; put(expected,0,adjustment==0 ? VT+0x80 : VT);
                    if(adjustment!=0) put(expected,adjustment,0xabcddcbaL);
                    require(Arrays.equals(expected,memory(OBJ,24)) && get(DESC+0x12c)==OBJ,"Object construction oracle");
                    statePtr=register("r0"); require(get(statePtr)==0 && get(statePtr+4)==0,"Initial conversion state");
                    result=initializePath(rebuiltPath,statePtr);
                } else if(pc==0x2b9468) {
                    require(register("r0")==DESC+0x2c+cursor && register("r1")==0x105 && register("r2")==statePtr,"Measure arguments");
                    checkPathState(statePtr,converted);
                    result=measurePath(rebuiltPath,converted==count ? 0 : pathStride(converted)); measures++;
                } else if(pc==0x2c63dc) {
                    if(conversions==0) pathPtr=register("r0");
                    require(register("r0")==pathPtr+2*converted && register("r1")==DESC+0x2c+cursor &&
                        register("r2")==pathStride(converted) && register("r3")==statePtr,"Convert arguments");
                    require(within(pathPtr,2*(successful+1),register("sp"),STACK-16),"Path scratch bounds");
                    int ch=convertedUnit(converted);
                    result=convertPath(rebuiltPath,converted==failure ? 0 : converted%2==0 ? 1 : MASK,ch);
                    conversions++;
                    if(converted!=failure) {
                        cursor+=pathStride(converted); converted++;
                        advancePathState(statePtr,converted);
                    }
                } else if(pc==0x2bb944) {
                    require(register("r0")==OBJ+4 && register("r2")==1,"Open arguments");
                    if(pathPtr==0) pathPtr=register("r1");
                    require(register("r1")==pathPtr,"Open path pointer");
                    byte[] expected=new byte[2*(successful+1)];
                    for(int i=0;i<successful;i++) { int ch=convertedUnit(i); expected[2*i]=(byte)ch; expected[2*i+1]=(byte)(ch>>8); }
                    require(Arrays.equals(expected,memory(pathPtr,expected.length)),"Converted path/terminator oracle");
                    for(int off=4;off<24;off+=4) require(get(OBJ+off)==0,"Open object reset");
                    result=executeOpen(rebuiltPath,open,handle,pathPtr,successful);
                } else if(pc==0x730008) { require(register("r0")==OBJ,"Size receiver"); result=length; }
                else if(pc==0x730004) {
                    require(register("r0")==OBJ && register("r2")==0 && register("r3")==0 && get(register("sp"))==0,"Seek arguments");
                } else if(pc==0x2bf7ec) {
                    long flags=word(initial,36);
                    require(register("r0")==((flags==1 || flags==17) ? 0x10000 : 0x100) &&
                        register("r1")==0x100 && register("r2")==0 && register("r3")==length,"Data allocation registers");
                    require(get(register("sp"))==word(initial,40) && get(register("sp")+4)==((flags==16 || flags==17) ? 0 : 1),"Data allocation stack arguments");
                    result=allocation;
                } else if(pc==0x2c3afc || pc==0x2c3a78) {
                    require(register("r0")==get(LOCK),"I/O lock handle reload");
                    require(get(GLOBAL+4)==(pc==0x2c3afc ? 0x1234 : 0),"Busy flag at lock boundary");
                    writeWord(LOCK,(get(LOCK)+0x101)&MASK);
                } else if(pc==0x73000c) {
                    long data=word(initial,12)==0 ? allocation : word(initial,12);
                    require(register("r0")==OBJ && register("r2")==data && register("r3")==length && get(GLOBAL+4)==1,"Read arguments and busy flag");
                    require(within(register("r1"),4,register("sp"),STACK-16),"Read count out pointer");
                    writeWord(register("r1"),length^MASK); writeWord(LOCK,0x81234567L); result=read;
                } else if(pc==0x2bce9c) {
                    require(register("r0")==handle,"Preclose handle");
                    result=executePreclose(rebuiltPath,effect);
                } else if(pc==0x2b9450) {
                    long expected=effect==2 && (handle&1)!=0 ? precloseReplacement()&~1L : handle&~1L;
                    require(register("r0")==expected,"Close handle reload/mask");
                    executeClose(rebuiltPath,expected);
                    if(effect==3) writeWord(DESC+0x12c,0);
                } else if(pc==0x730000) {
                    require(register("r0")==OBJ && get(GLOBAL+4)==0,"Destructor receiver/busy");
                    executeDestroy(rebuiltPath);
                    destroyed=true;
                } else ext=false;
                if(ext) {
                    require((register("sp")&7)==0,"Lower call alignment");
                    event(pc); externalReturn(result);
                    if(pc==0x2c3a78) register("r2",releasePayload());
                    continue;
                }
                require(rebuiltPath ? within(pc,4,BUILD,BUILD+codeSize) : originalCode(pc),"Unexpected PC "+Long.toHexString(pc));
                if(!rebuiltPath) visited.add(pc);
                require(++steps<=5000,"I/O instruction budget"); monitor.checkCancelled(); thread.stepInstruction();
            }
            require(calls.equals(expectedCalls),"I/O dependency sequence");
            require(converted==successful && measures==successful+1 && conversions==successful+(failure>=0 ? 1 : 0),"Conversion count");
            List<Long> expectedStates=new ArrayList<>();
            if((open&0x80000000L)!=0) expectedStates.add(5L);
            if((read&0x80000000L)!=0) expectedStates.add(5L);
            require(states.equals(expectedStates),"State write sequence");
            byte[] expected=initial.clone();
            if(!expectedStates.isEmpty()) put(expected,0,5);
            put(expected,12,word(initial,12)==0 ? allocation : word(initial,12));
            put(expected,24,length); put(expected,0x12c,destroy ? OBJ : 0);
            require(Arrays.equals(expected,memory(DESC,0x144)),"Final descriptor oracle");
            byte[] expectedObj=new byte[24]; put(expectedObj,0,adjustment==0 ? VT+0x80 : VT);
            put(expectedObj,4,closes ? 0 : handle);
            expectedFileState(expectedObj);
            require(Arrays.equals(expectedObj,memory(OBJ,24)),"Final object oracle");
            require(destroyed==destroy && get(GLOBAL+4)==0 && get(LOCK)==0x81234668L,"Final lower state");
            finishAllocation();
            for(byte value:memory(STACK-0x1000,0x800)) require(value==(byte)0x96,"Lower stack guard");
            if(rebuiltPath) finish(steps); else {
                require(register("sp")==STACK-0x300,"Original region stack"); maxSteps=Math.max(maxSteps,steps);
            }
        }
    }
    @Override public void run() throws Exception {
        Path out=Path.of(getScriptArgs()[0]); require(!Files.exists(out.resolve("comparison.json")),"Output exists");
        byte[] mapped=new byte[0x377000];
        require(currentProgram.getMemory().getBytes(toAddr(0x100000),mapped)==mapped.length,"Map");
        require(HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(mapped)).equals(
            "834938d18d2b7c688311c46c27bed813d0d7a9f8e3cbb61da8a6a3f23d360ebd"),"Reference hash");
        byte[] binary=Files.readAllBytes(out.resolve("resource-worker-io.bin")); codeSize=binary.length;
        require(codeSize>0 && codeSize<=0x2000,"Binary size");
        entries[0]=Long.parseLong(Files.readAllLines(out.resolve("entries.txt")).get(0));
        IoMachine a=makeMachine(mapped,binary),b=makeMachine(mapped,binary);
        preChecks(mapped,binary,out);
        Random rng=new Random(BEGIN); long[] sizes=recoveredAllocation ? new long[]{0,1,68,69,127,128,129,0x321} : new long[]{0,1,0x80000000L,MASK,0x321};
        try(PrintWriter log=new PrintWriter(Files.newBufferedWriter(out.resolve("results.tsv")))) {
            log.println("case\topen\tread\thandle\tflags\tbuffer\tprofile\teffect\tlength\tallocation");
            for(long open:new long[]{0,0x80000001L}) for(long read:new long[]{0,MASK})
            for(long handle:new long[]{0,1,0x4560,0x4561,0x80000000L,MASK})
            for(long flags:new long[]{0,1,16,17,2,0x101,0x80000011L,MASK})
            for(long buffer:recoveredAllocation ? new long[]{0,0x908000} : new long[]{0,0x904000,0x81234560L}) for(int profile=0;profile<6;profile++) {
                int effect=cases%4; long length=sizes[(cases/4)%sizes.length];
                long allocation=recoveredAllocation ? 0x908000 : new long[]{0,0x904000,0x81234560L}[(cases/20)%3];
                byte[] initial=new byte[0x144]; rng.nextBytes(initial);
                put(initial,0,0); put(initial,12,buffer); put(initial,36,flags); put(initial,40,Integer.toUnsignedLong(rng.nextInt()));
                if(recoveredAllocation) put(initial,40,new long[]{0,127,128,256,512,4096}[(cases/24)%6]);
                try {
                    a.call(false,initial,open,read,handle,length,allocation,profile,effect);
                    b.call(true,initial,open,read,handle,length,allocation,profile,effect);
                    require(a.trace.equals(b.trace),"Original/rebuilt dependency snapshots");
                    require(a.states.equals(b.states),"Original/rebuilt state stores");
                } catch(Exception ex) { throw new IllegalStateException("Worker I/O case "+cases+" profile="+profile+" flags="+flags+" effect="+effect,ex); }
                log.printf("%d\t%d\t%d\t%d\t%d\t%d\t%d\t%d\t%d\t%d%n",++cases,open,read,handle,flags,buffer,profile,effect,length,allocation);
            }
        }
        String extra=extraChecks(mapped,binary,out);
        StringBuilder listing=new StringBuilder();
        for(long[] range:new long[][]{{BEGIN,END},{0x114098,0x114134}})
            for(long pc=range[0];pc<range[1];pc+=4) {
                require(visited.contains(pc),"Unvisited I/O instruction "+Long.toHexString(pc));
                var instruction=currentProgram.getListing().getInstructionAt(toAddr(pc));
                require(instruction!=null,"Missing original instruction");
                listing.append(String.format("%08x %s%n",pc,instruction));
            }
        Files.writeString(out.resolve("original-io-ghidra.txt"),listing);
        Files.writeString(out.resolve("comparison.json"),String.format(Locale.ROOT,
            "{\"io_cases\":%d,\"original_instruction_addresses\":%d,\"binary_bytes\":%d,\"max_steps\":%d,\"dependency_calls_both_paths\":%d,\"lower_file_calls_modeled\":true,\"full_worker_recovered\":false,\"live_verified\":false%s}\n",
            cases,visited.size(),codeSize,maxSteps,dependencyCalls,extra));
        println("SMT4_WORKER_IO_COMPARE_OK");
    }
}
