// Integrated signal/acquire/release instructions. Only arbitration is intercepted.
// Exclusive outcomes and competing writes are scheduled, not hardware emulation.
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

public class CompareResourceSignalLock extends CompareResourceLifecycle {
    static final long SIGNAL=0x2c4298, SIGNAL_END=0x2c434c;
    static final long ACQUIRE=0x1464f8, ACQUIRE_END=0x1465d4;
    static final long RELEASE=0x138fc0, RELEASE_END=0x139010;
    static final long DATA=0x900020, LOCK=DATA+4, HANDLE=0x471b58, ARBITRATE=0x2a88fc, MASK=0xffffffffL;
    static final long[] STATES={0,1,2,0x7fffffffL,0x80000000L,0xfffffffdL,0xfffffffeL,MASK};
    int cases, pendingCases;
    boolean recoverArbitration;
    long attempts, clears, boundaryCalls;
    record Event(String kind,long address,long value,long extra) {}

    // Independent transition plan: observable reads, attempted writes (including
    // failed stores), clears, successful writes and ordered arbitration calls.
    class Plan {
        List<Event> events=new ArrayList<>();
        long signal, lock, handle, response, initialSignal, initialLock, initialHandle;
        int calls, variant;
        boolean pending;
        void add(String kind,long address,long value,long extra) {
            events.add(new Event(kind,address,value,extra));
        }
        void arbitrate(long address,int operation,long count) {
            add("handle",HANDLE,handle,0); add("arbitrate",address,operation,count);
            calls++;
            if(variant!=0) {
                signal=(0x89abcdefL+calls)&MASK;
                add("effect",DATA,signal,0);
            }
            if(variant==2) {
                lock=STATES[(calls+4)%STATES.length];
                add("effect",LOCK,lock,0);
            }
            handle=(handle+0x1020304L)&MASK;
            add("effect",HANDLE,handle,0);
        }
        boolean store(long address,long value,boolean failed) {
            add("store",address,value,failed ? 0 : 1);
            if(failed) return false;
            add("write",address,value,0);
            if(address==LOCK) lock=value; else signal=value;
            return true;
        }
        void lock(boolean release,long[] reads,boolean[] failures,int limit) {
            int phase=release ? 4 : 0, loads=0, stores=0;
            while(true) {
                if(loads==limit) { pending=true; return; }
                long input=loads<reads.length ? reads[loads] : 2;
                if(input!=-1) lock=input;
                add("load",LOCK,lock,0); loads++;
                boolean claim=phase==4 || (phase==1 ? (int)lock<0 : (int)lock>0);
                if(!claim) {
                    add("clear",LOCK,0,0);
                    if(phase==0 || phase==2) phase=1;
                    else if(phase==1) phase=2;
                    else arbitrate(LOCK,1,0);
                    continue;
                }
                long value=(phase==1 ? lock-1 : phase==3 ? 1-lock : -lock)&MASK;
                if(!store(LOCK,value,failures[stores++%failures.length])) continue;
                if(phase==1) { phase=3; arbitrate(LOCK,1,0); }
                else {
                    if(phase==4 && (int)value>1) arbitrate(LOCK,0,1);
                    return;
                }
            }
        }
        Plan(long first,long second,long[] acquireReads,boolean[] acquireFailures,
                long[] releaseReads,boolean[] releaseFailures,int exchangeFailures,
                int stopPhase,int limit,int variant,long response,long seed) {
            signal=initialSignal=first; lock=initialLock=acquireReads[0];
            handle=initialHandle=seed&MASK; this.variant=variant; this.response=response;
            add("read",DATA,first,0);
            int mode=first==MASK ? 1 : second==MASK-1 ? 2 : 0;
            if(first!=MASK) { signal=second; add("read",DATA,second,0); }
            if(mode==0) return;
            if(mode==2) {
                lock(false,acquireReads,acquireFailures,stopPhase==1 ? limit : 64);
                if(pending) return;
            }
            for(int i=0;;i++) {
                if(stopPhase==2 && i==limit) { pending=true; return; }
                if(variant!=0) signal=(i%2==0 ? 0x80000000L+i : MASK-i)&MASK;
                add("load",DATA,signal,0);
                if(store(DATA,mode==1 ? 0 : 1,stopPhase==2 || i<exchangeFailures)) break;
            }
            arbitrate(DATA,0,mode==1 ? 1 : MASK);
            if(mode==2) lock(true,releaseReads,releaseFailures,stopPhase==3 ? limit : 64);
        }
    }
    class IntegratedMachine extends Machine {
        Plan plan;
        byte[] expected;
        int cursor;
        long reservationAddress, handle;
        boolean reservation, exclusiveLoad, success, storePending;
        Event store;
        IntegratedMachine(byte[] mapped,byte[] binary) { super(mapped,binary); }
        Event take(String kind,long address) {
            require(cursor<plan.events.size(),"Extra event "+kind);
            Event e=plan.events.get(cursor++);
            require(e.kind().equals(kind) && e.address()==address,
                    "Expected "+e+" got "+kind+" at "+Long.toHexString(address)+" event "+cursor);
            return e;
        }
        @Override public void beforeExecuteInstruction(PcodeThread<byte[]> t,Instruction instruction,PcodeProgram program) {
            String mnemonic=instruction.getMnemonicString().toLowerCase(Locale.ROOT);
            exclusiveLoad=mnemonic.equals("ldrex");
            if(mnemonic.equals("strex")) {
                require(reservation && !storePending,"STREX reservation");
                long bits=word(memory(instruction.getAddress().getOffset(),4),0);
                long address=register("r"+((bits>>>16)&15));
                require(address==reservationAddress,"STREX target changed");
                store=take("store",address);
                require(register("r"+(bits&15))==store.value(),"Exclusive store attempted value");
                storePending=true;
            }
        }
        @Override public void beforeLoad(PcodeThread<byte[]> t,PcodeOp op,AddressSpace space,byte[] offset,int size) {
            long a=Utils.bytesToLong(offset,offset.length,false);
            require(((a==DATA || a==LOCK || a==HANDLE) && size==4) ||
                    within(a,size,0x100000,0x477000) || within(a,size,BUILD,BUILD+codeSize) ||
                    within(a,size,STACK-0x1000,STACK),"Unexpected read "+Long.toHexString(a));
            if(a==DATA || a==LOCK) {
                require(!reservation,"Load before consuming reservation");
                Event e=take(exclusiveLoad ? "load" : "read",a);
                put(expected,(int)(a-DATA+32),e.value()); memory(DATA-32,expected);
                if(exclusiveLoad) { reservation=true; reservationAddress=a; }
            }
            if(a==HANDLE) require(take("handle",a).value()==handle,"Handle reload");
        }
        @Override public boolean handleMissingUserop(PcodeThread<byte[]> t,PcodeOp op,PcodeFrame frame,
                String name,PcodeUseropLibrary<byte[]> library) {
            if(name.equals("ClearExclusiveLocal")) {
                require(reservation && !storePending,"CLREX reservation");
                take("clear",reservationAddress); reservation=false; clears++; return true;
            }
            require(name.equals("hasExclusiveAccess"),"Unexpected userop "+name);
            byte[] arg=t.getState().getVar(op.getInput(1),Reason.INSPECT);
            require(Utils.bytesToLong(arg,arg.length,false)==reservationAddress && reservation && storePending,
                    "STREX address/order");
            reservation=false; storePending=false; success=store.extra()==1; attempts++;
            t.getState().setVar(op.getOutput(),machine.getArithmetic().fromConst(success ? 1 : 0,op.getOutput().getSize()));
            return true;
        }
        @Override public void beforeStore(PcodeThread<byte[]> t,PcodeOp op,AddressSpace space,
                byte[] offset,int size,byte[] value) {
            long a=Utils.bytesToLong(offset,offset.length,false);
            if(within(a,size,STACK-0x1000,STACK)) return;
            require(a==reservationAddress && size==4 && success,"Unexpected nonexclusive write");
            long v=word(value,0); require(take("write",a).value()==v,"Stored value");
            put(expected,(int)(a-DATA+32),v); success=false;
        }
        void call(boolean rebuiltPath,Plan schedule,long seed) throws Exception {
            executing=false; plan=schedule; cursor=0;
            reservation=exclusiveLoad=success=storePending=false;
            expected=new byte[96]; new Random(seed).nextBytes(expected);
            put(expected,32,plan.initialSignal); put(expected,36,plan.initialLock); memory(DATA-32,expected);
            handle=plan.initialHandle; writeWord(HANDLE,handle);
            byte[] stack=new byte[0x1000]; Arrays.fill(stack,(byte)0x96); memory(STACK-0x1000,stack);
            for(var r:currentProgram.getLanguage().getRegisters())
                if(r.isBaseRegister() && !r.isProcessorContext()) register(r,0);
            for(int r=0;r<=12;r++) register("r"+r,0x12340000L+r);
            register("cpsr",0x10); register("sp",STACK); register("lr",RETURN); register("r0",DATA);
            thread.overrideContext(new RegisterValue(currentProgram.getProgramContext().getBaseContextRegister(),BigInteger.ZERO));
            thread.overrideCounter(toAddr(rebuiltPath ? rebuilt[0] : SIGNAL)); executing=true;
            int steps=0;
            while(thread.getCounter().getOffset()!=RETURN) {
                long pc=thread.getCounter().getOffset();
                long bits=word(memory(pc,4),0);
                boolean svc=recoverArbitration && (bits&0x0f000000L)==0x0f000000L;
                if(svc) require(bits==0xef000022L && (rebuiltPath ? within(pc,4,BUILD,BUILD+codeSize) : pc==ARBITRATE+12),"Unexpected SVC");
                if(svc || (!recoverArbitration && pc==ARBITRATE)) {
                    Event e=take("arbitrate",register("r1"));
                    require(!reservation && (register("sp")&7)==0,"Arbitration reservation/alignment");
                    require(register("r0")==handle && register("r2")==e.value() && register("r3")==e.extra(),
                            "Arbitration arguments");
                    if(svc) require(register("r4")==0 && register("r5")==0,"SVC timeout words");
                    else require(Arrays.equals(memory(register("sp"),8),new byte[8]),"Timeout words");
                    require(Arrays.equals(memory(DATA-32,96),expected),"Boundary guards");
                    while(cursor<plan.events.size() && plan.events.get(cursor).kind().equals("effect")) {
                        Event effect=plan.events.get(cursor++);
                        if(effect.address()==HANDLE) { handle=effect.value(); writeWord(HANDLE,handle); }
                        else put(expected,(int)(effect.address()-DATA+32),effect.value());
                    }
                    memory(DATA-32,expected); boundaryCalls++;
                    long lr=register("lr");
                    for(String r:new String[]{"r0","r1","r2","r3","r12"}) register(r,0xdeadbeefL);
                    register("r0",plan.response); register("cpsr",0xa0000010L);
                    if(svc) {
                        register("r4",0xcafebabeL); register("r5",0xfeedfaceL);
                        if(!rebuiltPath) visited.add(pc);
                        require(++steps<=8192,"Instruction budget");
                    }
                    thread.overrideContext(new RegisterValue(currentProgram.getProgramContext().getBaseContextRegister(),BigInteger.ZERO));
                    thread.overrideCounter(toAddr(svc ? pc+4 : lr)); continue;
                }
                require(rebuiltPath ? within(pc,4,BUILD,BUILD+codeSize) :
                        within(pc,4,SIGNAL,SIGNAL_END) || within(pc,4,ACQUIRE,ACQUIRE_END) ||
                        within(pc,4,RELEASE,RELEASE_END) ||
                        (recoverArbitration && within(pc,4,ARBITRATE,ARBITRATE+24)),"Unexpected PC "+Long.toHexString(pc));
                if(plan.pending && cursor==plan.events.size() && (bits&0x0ff00fffL)==0x01900f9fL) break;
                if(!rebuiltPath) visited.add(pc);
                require(++steps<=8192,"Instruction budget"); monitor.checkCancelled(); thread.stepInstruction();
            }
            require(cursor==plan.events.size(),"Missing events: "+cursor+"/"+plan.events.size());
            require(!reservation && !storePending && !success,"Unconsumed exclusive state");
            require(word(memory(DATA,4),0)==plan.signal && word(memory(LOCK,4),0)==plan.lock &&
                    word(memory(HANDLE,4),0)==plan.handle,"Final oracle words");
            require(Arrays.equals(memory(DATA-32,96),expected),"Final object/guard bytes");
            if(!plan.pending) {
                require(register("sp")==STACK,"SP restoration");
                for(int r=4;r<=11;r++) require(register("r"+r)==0x12340000L+r,"Callee saved");
            } else require(thread.getCounter().getOffset()!=RETURN,"Pending path returned");
            maxSteps=Math.max(maxSteps,steps);
        }
    }
    void compare(IntegratedMachine a,IntegratedMachine b,PrintWriter log,long first,long second,
            long[] acquireReads,boolean[] acquireFailures,long[] releaseReads,boolean[] releaseFailures,
            int exchangeFailures,int stopPhase,int limit,int variant,long result) throws Exception {
        long seed=SIGNAL+cases*0x10001L;
        Plan plan=new Plan(first,second,acquireReads,acquireFailures,releaseReads,releaseFailures,
                exchangeFailures,stopPhase,limit,variant,result,seed);
        try { a.call(false,plan,seed); b.call(true,plan,seed); }
        catch(Exception ex) { throw new IllegalStateException("Case "+cases+" mode="+Long.toHexString(first)+
                "/"+Long.toHexString(second)+" acquire="+Arrays.toString(acquireReads)+" stop="+stopPhase,ex); }
        require(Arrays.equals(a.memory(DATA-32,96),b.memory(DATA-32,96)),"Original/rebuilt memory");
        if(plan.pending) pendingCases++;
        log.printf("%d\t%b\t%d\t%s%n",++cases,plan.pending,variant,plan.events);
    }
    @Override public void run() throws Exception {
        recoverArbitration=getScriptArgs().length==2 && getScriptArgs()[1].equals("svc");
        Path out=Path.of(getScriptArgs()[0]); require(!Files.exists(out.resolve("comparison.json")),"Existing output");
        byte[] mapped=new byte[0x377000];
        require(currentProgram.getMemory().getBytes(toAddr(0x100000),mapped)==mapped.length,"Map");
        require(HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(mapped)).equals(
            "834938d18d2b7c688311c46c27bed813d0d7a9f8e3cbb61da8a6a3f23d360ebd"),"Hash");
        byte[] binary=Files.readAllBytes(out.resolve("resource-signal-lock.bin")); codeSize=binary.length;
        require(codeSize>0 && codeSize<=0x1000,"Binary size");
        List<String> lines=Files.readAllLines(out.resolve("entries.txt")); require(lines.size()==3,"Entries");
        for(int i=0;i<3;i++) { rebuilt[i]=Long.parseLong(lines.get(i)); require(within(rebuilt[i],4,BUILD,BUILD+codeSize),"Entry extent"); }
        IntegratedMachine a=new IntegratedMachine(mapped,binary),b=new IntegratedMachine(mapped,binary);
        boolean[][] patterns={{false},{true,false},{true,true,false},{false,true,true,true,false}};
        long[] preserve={-1,-1,-1,-1,-1,-1,-1,-1};
        try(PrintWriter log=new PrintWriter(Files.newBufferedWriter(out.resolve("results.tsv")))) {
            log.println("case\tpending\tvariant\tevents");
            for(long first:STATES) for(long second:STATES) for(int p=0;p<4;p++)
                compare(a,b,log,first,second,new long[]{2},patterns[p],preserve,patterns[p],p,0,64,p%3,STATES[p]);
            for(long x:STATES) for(long y:STATES) for(long z:STATES) for(int p=0;p<4;p++) for(int v=0;v<3;v++)
                compare(a,b,log,0,MASK-1,new long[]{x,y,z,-1,-1},patterns[p],preserve,patterns[p],p,0,64,v,z);
            for(long x:STATES) for(int p=0;p<4;p++) for(int v=0;v<3;v++)
                compare(a,b,log,0,MASK-1,new long[]{2},patterns[p],new long[]{x,-1,-1,-1,-1},patterns[p],p,0,64,v,x);
            Random random=new Random(SIGNAL);
            for(int i=0;i<1024;i++) {
                long[] reads=new long[16];
                for(int j=0;j<reads.length;j++) reads[j]=j%3==0 ? STATES[random.nextInt(STATES.length)] : Integer.toUnsignedLong(random.nextInt());
                compare(a,b,log,i%4==0 ? MASK : Integer.toUnsignedLong(random.nextInt()),MASK-1,
                        reads,patterns[i%4],i%2==0 ? preserve : reads,patterns[(i+1)%4],i%16,0,64,i%3,Integer.toUnsignedLong(random.nextInt()));
            }
            for(int n:new int[]{1,2,7,31}) {
                long[] zeros=new long[n], positives=new long[n], negatives=new long[n];
                Arrays.fill(positives,2); Arrays.fill(negatives,MASK);
                for(long[] reads:new long[][]{zeros,positives,negatives,new long[]{0,0,2}})
                    compare(a,b,log,0,MASK-1,reads,new boolean[]{true},preserve,patterns[0],0,1,n,2,MASK);
                compare(a,b,log,0,MASK-1,negatives,patterns[0],preserve,patterns[0],0,1,n,1,MASK);
                for(long first:new long[]{0,MASK})
                    compare(a,b,log,first,MASK-1,new long[]{2},patterns[0],preserve,patterns[0],0,2,n,2,MASK);
                for(long[] reads:new long[][]{positives,negatives})
                    compare(a,b,log,0,MASK-1,new long[]{2},patterns[0],reads,new boolean[]{true},0,3,n,1,MASK);
            }
        }
        for(long[] range:new long[][]{{SIGNAL,SIGNAL_END},{ACQUIRE,ACQUIRE_END},{RELEASE,RELEASE_END}})
            for(long pc=range[0];pc<range[1];pc+=4) require(visited.contains(pc),"Unvisited instruction "+Long.toHexString(pc));
        if(recoverArbitration) for(long pc=ARBITRATE;pc<ARBITRATE+24;pc+=4)
            require(visited.contains(pc),"Unvisited arbitration instruction");
        Files.writeString(out.resolve("visited.txt"),String.join("\n",visited.stream().map(v->String.format("%08x",v)).toList())+"\n");
        Files.writeString(out.resolve("comparison.json"),String.format(Locale.ROOT,
            "{\"signal_lock_cases\":%d,\"pending_prefix_cases\":%d,\"original_instruction_addresses\":%d,\"max_steps\":%d,\"arbitration_calls_both_paths\":%d,\"exclusive_attempts_both_paths\":%d,\"clear_exclusives_both_paths\":%d,\"locks_intercepted\":false,\"arbitration_intercepted\":%b,\"svc_intercepted\":%b,\"exclusive_outcomes_scheduled\":true,\"live_verified\":false}\n",
            cases,pendingCases,visited.size(),maxSteps,boundaryCalls,attempts,clears,!recoverArbitration,recoverArbitration));
        println("SMT4_SIGNAL_LOCK_COMPARE_OK");
    }
}
