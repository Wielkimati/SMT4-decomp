// Original/rebuilt lock instructions, with a separate event-plan oracle.
// Exclusive monitor, competing writes and arbitration are explicit models.
// @category SMT4
import ghidra.program.model.lang.RegisterValue;
import ghidra.program.model.listing.Instruction;
import ghidra.pcode.emu.PcodeThread;
import ghidra.pcode.exec.*;
import ghidra.pcode.exec.PcodeExecutorStatePiece.Reason;
import ghidra.pcode.utils.Utils;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.pcode.PcodeOp;
import java.math.BigInteger;
import java.nio.file.*;
import java.security.MessageDigest;
import java.util.*;
import java.io.*;

public class CompareResourceLock extends CompareResourceLifecycle {
    static final long ACQUIRE=0x1464f8, ACQUIRE_END=0x1465d4;
    static final long RELEASE=0x138fc0, RELEASE_END=0x139010;
    static final long DATA=0x900020, HANDLE=0x471b58, ARBITRATE=0x2a88fc, MASK=0xffffffffL;
    static final long[] STATES={0,1,2,0x7fffffffL,0x80000000L,0xfffffffdL,0xfffffffeL,MASK};
    int acquireCases, releaseCases, pendingCases;
    long attempts, clears, boundaryCalls;
    record Event(String kind,long value,boolean success) {}
    // -1 means leave memory unchanged; other inputs are competing writes just
    // before the load. Failure pattern repeats; arbitration changes both word
    // and handle. These schedules make no kernel or hardware timing claim.
    class Plan {
        List<Event> events=new ArrayList<>();
        long current, handle, response, returnedR2;
        boolean pending;
        int loads, stores, calls;
        void add(String kind,long value) { events.add(new Event(kind,value,false)); }
        Plan(boolean release,long initial,long[] reads,boolean[] failures,int limit,
                long response,long seed,boolean mutate) {
            current=initial; handle=seed&MASK; this.response=response;
            int phase=release ? 4 : 0;
            boolean done=false;
            while(!done) {
                // Phases: fast positive claim; register waiter; slow positive
                // claim; post-wait claim; release. Arithmetic uses 32-bit wrap.
                if(loads==limit) { pending=true; break; }
                long input=loads<reads.length ? reads[loads] : 2;
                if(input!=-1) current=input;
                add("load",current); loads++;
                boolean positive=(int)current>0, negative=(int)current<0;
                boolean store=phase==4 || (phase==1 ? negative : positive);
                if(!store) {
                    add("clear",0);
                    if(phase==0 || phase==2) phase=1;
                    else if(phase==1) phase=2;
                    else arbitrate(1,mutate);
                    continue;
                }
                long value=(phase==1 ? current-1 : phase==3 ? 1-current : -current)&MASK;
                boolean success=!failures[stores++%failures.length];
                events.add(new Event("store",value,success));
                if(!success) continue;
                current=value; add("write",value);
                if(phase==4)returnedR2=value;
                else if(phase!=1)returnedR2=phase==0?DATA:0;
                if(phase==1) { phase=3; arbitrate(1,mutate); }
                else {
                    if(phase==4 && (int)value>1) arbitrate(0,mutate);
                    done=true;
                }
            }
        }
        void arbitrate(int operation,boolean mutate) {
            add("handle",handle); add("arbitrate",operation); calls++;if(operation==0)returnedR2=0xdeadbeefL;
            if(mutate) current=(0x89abcdefL+calls)&MASK;
            handle=(handle+0x1020304L)&MASK;
        }
    }
    class LockMachine extends Machine {
        Plan plan;
        byte[] expected;
        int cursor, loads, calls;
        long handle;
        boolean reservation, exclusiveLoad, success, storePending;
        Event store;
        LockMachine(byte[] mapped,byte[] binary) { super(mapped,binary); }
        Event take(String kind) {
            require(cursor<plan.events.size(),"Extra event "+kind);
            Event e=plan.events.get(cursor++);
            require(e.kind().equals(kind),"Expected "+e+" got "+kind+" at event "+cursor);
            return e;
        }
        @Override public void beforeExecuteInstruction(PcodeThread<byte[]> t,Instruction instruction,PcodeProgram program) {
            String mnemonic=instruction.getMnemonicString().toLowerCase(Locale.ROOT);
            exclusiveLoad=mnemonic.equals("ldrex");
            if(mnemonic.equals("strex")) {
                require(reservation && !storePending,"STREX reservation");
                store=take("store");
                long bits=word(memory(instruction.getAddress().getOffset(),4),0);
                require(register("r"+(bits&15))==store.value(),"Exclusive store attempted value");
                storePending=true;
            }
        }
        @Override public void beforeLoad(PcodeThread<byte[]> t,PcodeOp op,AddressSpace space,byte[] offset,int size) {
            long a=Utils.bytesToLong(offset,offset.length,false);
            require((a==DATA && size==4) || (a==HANDLE && size==4) ||
                    within(a,size,0x100000,0x477000) || within(a,size,BUILD,BUILD+codeSize) ||
                    within(a,size,STACK-0x1000,STACK),"Unexpected read "+Long.toHexString(a));
            if(a==DATA) {
                require(exclusiveLoad && !reservation,"Nonexclusive/repeated lock load");
                Event e=take("load"); put(expected,32,e.value()); memory(DATA-32,expected);
                reservation=true; loads++;
            }
            if(a==HANDLE) require(take("handle").value()==handle,"Handle reload");
        }
        @Override public boolean handleMissingUserop(PcodeThread<byte[]> t,PcodeOp op,PcodeFrame frame,
                String name,PcodeUseropLibrary<byte[]> library) {
            if(name.equals("ClearExclusiveLocal")) {
                require(reservation && !storePending,"CLREX reservation");
                take("clear"); reservation=false; clears++; return true;
            }
            require(name.equals("hasExclusiveAccess"),"Unexpected userop "+name);
            byte[] arg=t.getState().getVar(op.getInput(1),Reason.INSPECT);
            require(Utils.bytesToLong(arg,arg.length,false)==DATA && reservation && storePending,"STREX address/order");
            reservation=false; storePending=false; success=store.success(); attempts++;
            t.getState().setVar(op.getOutput(),machine.getArithmetic().fromConst(success ? 1 : 0,op.getOutput().getSize()));
            return true;
        }
        @Override public void beforeStore(PcodeThread<byte[]> t,PcodeOp op,AddressSpace space,
                byte[] offset,int size,byte[] value) {
            long a=Utils.bytesToLong(offset,offset.length,false);
            if(within(a,size,STACK-0x1000,STACK)) return;
            require(a==DATA && size==4 && success,"Unexpected nonexclusive write");
            long v=word(value,0); require(take("write").value()==v,"Stored value");
            put(expected,32,v); success=false;
        }
        void call(boolean rebuiltPath,boolean release,Plan schedule,long seed,boolean mutate) throws Exception {
            executing=false; plan=schedule; cursor=loads=calls=0;
            reservation=exclusiveLoad=success=storePending=false;
            expected=new byte[96]; new Random(seed).nextBytes(expected);
            // First load schedule always provides the initial observed word.
            put(expected,32,plan.events.get(0).value()); memory(DATA-32,expected);
            handle=seed&MASK; writeWord(HANDLE,handle);
            byte[] stack=new byte[0x1000]; Arrays.fill(stack,(byte)0x96); memory(STACK-0x1000,stack);
            for(var r:currentProgram.getLanguage().getRegisters())
                if(r.isBaseRegister() && !r.isProcessorContext()) register(r,0);
            for(int r=0;r<=12;r++) register("r"+r,0x12340000L+r);
            register("cpsr",0x10); register("sp",STACK); register("lr",RETURN); register("r0",DATA);
            thread.overrideContext(new RegisterValue(currentProgram.getProgramContext().getBaseContextRegister(),BigInteger.ZERO));
            thread.overrideCounter(toAddr(rebuiltPath ? rebuilt[release ? 1 : 0] : release ? RELEASE : ACQUIRE));
            executing=true;
            int steps=0;
            while(thread.getCounter().getOffset()!=RETURN) {
                long pc=thread.getCounter().getOffset();
                if(pc==ARBITRATE) {
                    Event e=take("arbitrate");
                    require(!reservation && (register("sp")&7)==0,"Arbitration reservation/alignment");
                    require(register("r0")==handle && register("r1")==DATA && register("r2")==e.value()
                            && register("r3")== (e.value()==1 ? 0 : 1),"Arbitration arguments");
                    require(Arrays.equals(memory(register("sp"),8),new byte[8]),"Timeout words");
                    require(Arrays.equals(memory(DATA-32,96),expected),"Boundary guards");
                    calls++; boundaryCalls++;
                    if(mutate) put(expected,32,(0x89abcdefL+calls)&MASK);
                    memory(DATA-32,expected); handle=(handle+0x1020304L)&MASK; writeWord(HANDLE,handle);
                    long lr=register("lr");
                    for(String r:new String[]{"r0","r1","r2","r3","r12"}) register(r,0xdeadbeefL);
                    register("r0",plan.response); register("cpsr",0xa0000010L);
                    thread.overrideContext(new RegisterValue(currentProgram.getProgramContext().getBaseContextRegister(),BigInteger.ZERO));
                    thread.overrideCounter(toAddr(lr)); continue;
                }
                require(rebuiltPath ? within(pc,4,BUILD,BUILD+codeSize) :
                        release ? within(pc,4,RELEASE,RELEASE_END) : within(pc,4,ACQUIRE,ACQUIRE_END),"Unexpected PC "+Long.toHexString(pc));
                long bits=word(memory(pc,4),0);
                if(plan.pending && cursor==plan.events.size() && (bits&0x0ff00fffL)==0x01900f9fL) break;
                if(!rebuiltPath) visited.add(pc);
                require(++steps<=8192,"Instruction budget"); monitor.checkCancelled(); thread.stepInstruction();
            }
            require(cursor==plan.events.size(),"Missing events: "+cursor+"/"+plan.events.size());
            require(!reservation && !storePending && !success,"Unconsumed exclusive state");
            require(word(memory(DATA,4),0)==plan.current && word(memory(HANDLE,4),0)==plan.handle,"Final oracle words");
            require(Arrays.equals(memory(DATA-32,96),expected),"Final lock/guard bytes");
            if(!plan.pending) {
                require(register("r2")==plan.returnedR2,"Base lock r2 return");
                require(register("sp")==STACK,"SP restoration");
                for(int r=4;r<=11;r++) require(register("r"+r)==0x12340000L+r,"Callee saved");
            } else require(thread.getCounter().getOffset()!=RETURN,"Pending path returned");
            maxSteps=Math.max(maxSteps,steps);
        }
    }
    void compare(LockMachine a,LockMachine b,PrintWriter log,boolean release,long[] reads,
            boolean[] failures,int limit,long response,boolean mutate) throws Exception {
        long seed=ACQUIRE+(acquireCases+releaseCases)*0x10001L;
        Plan plan=new Plan(release,reads[0],reads,failures,limit,response,seed,mutate);
        try { a.call(false,release,plan,seed,mutate); b.call(true,release,plan,seed,mutate); }
        catch(Exception ex) { throw new IllegalStateException("Case "+(acquireCases+releaseCases)+" release="+release+" reads="+Arrays.toString(reads)+" failures="+Arrays.toString(failures),ex); }
        require(Arrays.equals(a.memory(DATA-32,96),b.memory(DATA-32,96)),"Original/rebuilt memory");
        if(release) releaseCases++; else acquireCases++;
        if(plan.pending) pendingCases++;
        log.printf("%d\t%b\t%b\t%s\t%s\t%x\t%b\t%s%n",acquireCases+releaseCases,release,plan.pending,
                Arrays.toString(reads),Arrays.toString(failures),response,mutate,plan.events);
    }
    @Override public void run() throws Exception {
        Path out=Path.of(getScriptArgs()[0]); require(!Files.exists(out.resolve("comparison.json")),"Existing output");
        byte[] mapped=new byte[0x377000];
        require(currentProgram.getMemory().getBytes(toAddr(0x100000),mapped)==mapped.length,"Map");
        require(HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(mapped)).equals(
            "834938d18d2b7c688311c46c27bed813d0d7a9f8e3cbb61da8a6a3f23d360ebd"),"Hash");
        byte[] binary=Files.readAllBytes(out.resolve("resource-lock.bin")); codeSize=binary.length;
        require(codeSize>0 && codeSize<=0x1000,"Binary size");
        List<String> lines=Files.readAllLines(out.resolve("entries.txt")); require(lines.size()==2,"Entries");
        for(int i=0;i<2;i++) { rebuilt[i]=Long.parseLong(lines.get(i)); require(within(rebuilt[i],4,BUILD,BUILD+codeSize),"Entry extent"); }
        LockMachine a=new LockMachine(mapped,binary),b=new LockMachine(mapped,binary);
        boolean[][] patterns={{false},{true,false},{true,true,false},{false,true,true,true,false}};
        try(PrintWriter log=new PrintWriter(Files.newBufferedWriter(out.resolve("results.tsv")))) {
            log.println("case\trelease\tpending\treads\tfailures\tresponse\tmutate\tevents");
            for(long x:STATES) for(long y:STATES) for(long z:STATES) for(boolean[] pattern:patterns)
                compare(a,b,log,false,new long[]{x,y,z,-1,-1},pattern,64,z,true);
            for(long x:STATES) for(boolean[] pattern:patterns)
                compare(a,b,log,true,new long[]{x,-1,-1,-1,-1},pattern,64,x,true);
            Random random=new Random(ACQUIRE);
            for(int i=0;i<1024;i++) {
                long[] reads=new long[16];
                for(int j=0;j<reads.length;j++) reads[j]=j%3==0 ? STATES[random.nextInt(STATES.length)] : Integer.toUnsignedLong(random.nextInt());
                for(boolean release:new boolean[]{false,true})
                    compare(a,b,log,release,reads,patterns[i%4],64,Integer.toUnsignedLong(random.nextInt()),i%2==0);
            }
            for(int n:new int[]{1,2,7,31}) {
                long[] zeros=new long[n];
                long[] positives=new long[n]; Arrays.fill(positives,2);
                long[] negatives=new long[n]; Arrays.fill(negatives,MASK);
                for(boolean release:new boolean[]{false,true}) {
                    compare(a,b,log,release,positives,new boolean[]{true},n,0,false);
                    compare(a,b,log,release,negatives,new boolean[]{true},n,MASK,false);
                }
                compare(a,b,log,false,zeros,new boolean[]{false},n,0,false);
                compare(a,b,log,false,negatives,new boolean[]{false},n,MASK,true);
                compare(a,b,log,false,new long[]{0,0,2},new boolean[]{true},n,0,false);
            }
        }
        for(long[] range:new long[][]{{ACQUIRE,ACQUIRE_END},{RELEASE,RELEASE_END}})
            for(long pc=range[0];pc<range[1];pc+=4) require(visited.contains(pc),"Unvisited instruction "+Long.toHexString(pc));
        Files.writeString(out.resolve("visited.txt"),String.join("\n",visited.stream().map(v->String.format("%08x",v)).toList())+"\n");
        Files.writeString(out.resolve("comparison.json"),String.format(Locale.ROOT,
            "{\"acquire_cases\":%d,\"release_cases\":%d,\"pending_prefix_cases\":%d,\"original_instruction_addresses\":%d,\"max_steps\":%d,\"arbitration_calls_both_paths\":%d,\"exclusive_attempts_both_paths\":%d,\"clear_exclusives_both_paths\":%d,\"arbitration_intercepted\":true,\"exclusive_outcomes_scheduled\":true,\"live_verified\":false}\n",
            acquireCases,releaseCases,pendingCases,visited.size(),maxSteps,boundaryCalls,attempts,clears));
        println("SMT4_LOCK_COMPARE_OK");
    }
}
