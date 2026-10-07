// Synchronous chain including signal and both locks on the same emulator/thread.
// @category SMT4
import ghidra.program.model.listing.Instruction;
import ghidra.pcode.emu.PcodeThread;
import ghidra.pcode.exec.*;
import ghidra.pcode.exec.PcodeExecutorStatePiece.Reason;
import ghidra.pcode.utils.Utils;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.pcode.PcodeOp;
import java.nio.file.*;
import java.security.MessageDigest;
import java.util.*;
import java.io.*;

public class CompareResourceChainSignal extends CompareResourceChain {
    static final long SIGNAL_WORD=0x465024, LOCK_WORD=SIGNAL_WORD+4;
    static final long ARBITRATION_HANDLE=0x471b58, ARBITRATE=0x2a88fc, MASK=0xffffffffL;
    final CompareResourceSignalLock model=new CompareResourceSignalLock();
    long signalEntry, arbitrationEntry, attempts, clears, boundaryCalls, signalCalls, wrapperReturns;
    boolean recoverArbitration;
    int signalPendingCases;
    static class PendingSignal extends RuntimeException {}
    @Override boolean originalCode(long pc) {
        return super.originalCode(pc) || within(pc,4,0x2c4298,0x2c434c) ||
            within(pc,4,0x1464f8,0x1465d4) || within(pc,4,0x138fc0,0x139010) ||
            (recoverArbitration && within(pc,4,ARBITRATE,ARBITRATE+24));
    }
    long translate(long a) {
        return a==CompareResourceSignalLock.DATA ? SIGNAL_WORD :
            a==CompareResourceSignalLock.LOCK ? LOCK_WORD : a;
    }
    CompareResourceSignalLock.Plan schedule(long first,long second,long[] reads,boolean[] failures,
            long[] release,boolean[] releaseFailures,int retries,int stop,int limit,int variant,long seed) {
        var p=model.new Plan(first,second,reads,failures,release,releaseFailures,retries,
            stop,limit,variant,(seed^0xdeadbeefL)&MASK,seed);
        for(int i=0;i<p.events.size();i++) {
            var e=p.events.get(i);
            p.events.set(i,new CompareResourceSignalLock.Event(e.kind(),translate(e.address()),e.value(),e.extra()));
        }
        return p;
    }
    CompareResourceSignalLock.Plan schedule(long seed,int round) {
        int n=(int)((seed-0x2c5e9000L)*7+round);
        long[] states=CompareResourceSignalLock.STATES;
        boolean[][] failures={{false},{true,false},{true,true,false},{false,true,true,true,false}};
        long[] reads={states[n%8],states[(n/8)%8],states[(n/64)%8],-1,-1};
        long[] release=n%2==0 ? new long[]{-1,-1,-1,-1} : new long[]{states[(n/16)%8],-1,-1,-1};
        long first=n%5==0 ? MASK : n%5==1 ? 0 : MASK-1;
        long second=n%5==1 ? states[(n/5)%6] : MASK-1;
        return schedule(first,second,reads,failures[n%4],release,failures[(n/4)%4],
            n%8,0,64,n%3,seed+round);
    }
    class SignalChainMachine extends ChainMachine {
        CompareResourceSignalLock.Plan plan, forcedPlan;
        byte[] signalBytes;
        int cursor;
        long reservationAddress, handle;
        boolean reservation, exclusiveLoad, success, storePending, inSignal;
        CompareResourceSignalLock.Event store;
        SignalChainMachine(byte[] mapped,byte[] binary) { super(mapped,binary); }
        @Override long signalEntry(boolean rebuiltPath) { return rebuiltPath ? signalEntry : SIGNAL; }
        @Override boolean executesSignal() { return true; }
        @Override void step(boolean rebuiltPath,int steps) throws Exception {
            long pc=thread.getCounter().getOffset();
            require(rebuiltPath ? within(pc,4,BUILD,BUILD+codeSize) : originalCode(pc),"Unexpected PC "+Long.toHexString(pc));
            if(!rebuiltPath) visited.add(pc);
            require(steps<=8192,"Instruction budget"); monitor.checkCancelled(); thread.stepInstruction();
        }
        CompareResourceSignalLock.Event take(String kind,long address) {
            require(cursor<plan.events.size(),"Extra event "+kind);
            CompareResourceSignalLock.Event e=plan.events.get(cursor++);
            require(e.kind().equals(kind) && e.address()==address,
                    "Expected "+e+" got "+kind+" at "+Long.toHexString(address)+" event "+cursor);
            return e;
        }
        @Override public void beforeExecuteInstruction(PcodeThread<byte[]> t,Instruction instruction,PcodeProgram program) {
            if(!inSignal) return;
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
            if(!inSignal) { super.beforeLoad(t,op,space,offset,size); return; }
            long a=Utils.bytesToLong(offset,offset.length,false);
            require(((a==SIGNAL_WORD || a==LOCK_WORD || a==ARBITRATION_HANDLE) && size==4) ||
                    within(a,size,0x100000,0x477000) || within(a,size,BUILD,BUILD+codeSize) ||
                    within(a,size,STACK-0x1000,STACK),"Unexpected read "+Long.toHexString(a));
            if(a==SIGNAL_WORD || a==LOCK_WORD) {
                require(size==4,"Signal/lock read width");
                require(!reservation,"Load before consuming reservation");
                CompareResourceSignalLock.Event e=take(exclusiveLoad ? "load" : "read",a);
                put(signalBytes,(int)(a-SIGNAL_WORD),e.value()); memory(SIGNAL_WORD,signalBytes);
                if(exclusiveLoad) { reservation=true; reservationAddress=a; }
            }
            if(a==ARBITRATION_HANDLE) require(size==4 && take("handle",a).value()==handle,"Handle reload");
        }
        @Override public boolean handleMissingUserop(PcodeThread<byte[]> t,PcodeOp op,PcodeFrame frame,
                String name,PcodeUseropLibrary<byte[]> library) {
            require(inSignal,"Exclusive outside signal");
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
            if(!inSignal) { super.beforeStore(t,op,space,offset,size,value); return; }
            long a=Utils.bytesToLong(offset,offset.length,false);
            if(within(a,size,STACK-0x1000,STACK)) return;
            require(a==reservationAddress && size==4 && success,"Unexpected nonexclusive write");
            long v=word(value,0); require(take("write",a).value()==v,"Stored value");
            put(signalBytes,(int)(a-SIGNAL_WORD),v); success=false;
        }
        @Override int signalInstructions(boolean rebuiltPath,long seed,int round,byte[] completion,int priorSteps) throws Exception {
            long DESC=descriptorAddress(), SIZE=sizeAddress(), PATH=pathAddress(), NODES=nodeAddress();
            plan=forcedPlan!=null ? forcedPlan : schedule(seed,round); cursor=0;
            reservation=exclusiveLoad=success=storePending=false;
            signalBytes=new byte[8]; put(signalBytes,0,plan.initialSignal); put(signalBytes,4,plan.initialLock);
            memory(SIGNAL_WORD,signalBytes); handle=plan.initialHandle; writeWord(ARBITRATION_HANDLE,handle);
            long returnPC=register("lr"), entrySP=register("sp");
            long[] saved=new long[8]; for(int r=4;r<=11;r++) saved[r-4]=register("r"+r);
            byte[] descriptor=memory(DESC,0x144), list=memory(NODES,nodes*0x200);
            byte[] path=memory(PATH,256), globals=memory(0x46500c,0x38);
            long oldSize=word(memory(SIZE,4),0); int oldPolls=polls, oldWrites=writes.size();
            inSignal=true; int steps=0; boolean updated=false;
            boolean inWrapper=false, sawSvc=false;
            long wrapperSP=0, wrapperLR=0;
            long[] wrapperSaved=new long[8];
            byte[] wrapperStack=null;
            while(thread.getCounter().getOffset()!=returnPC) {
                long pc=thread.getCounter().getOffset();
                if(inWrapper && pc==wrapperLR) {
                    require(sawSvc && register("r0")==plan.response,"Wrapper SVC/result");
                    require(register("sp")==wrapperSP,"Wrapper SP restoration");
                    for(int r=4;r<=11;r++) require(register("r"+r)==wrapperSaved[r-4],"Wrapper callee saved");
                    require(Arrays.equals(memory(wrapperSP,wrapperStack.length),wrapperStack),"Wrapper caller stack");
                    inWrapper=false; wrapperReturns++;
                }
                if(recoverArbitration && pc==(rebuiltPath ? arbitrationEntry : ARBITRATE)) {
                    require(!inWrapper,"Nested arbitration wrapper");
                    inWrapper=true; sawSvc=false; wrapperSP=register("sp"); wrapperLR=register("lr");
                    for(int r=4;r<=11;r++) wrapperSaved[r-4]=register("r"+r);
                    wrapperStack=memory(wrapperSP,(int)(STACK-wrapperSP));
                }
                long bits=word(memory(pc,4),0);
                boolean svc=recoverArbitration && (bits&0x0f000000L)==0x0f000000L;
                if(svc) require(inWrapper && !sawSvc && bits==0xef000022L &&
                    (rebuiltPath ? within(pc,4,arbitrationEntry,BUILD+codeSize) : pc==ARBITRATE+12),"Unexpected SVC");
                if(svc || (!recoverArbitration && pc==ARBITRATE)) {
                    var e=take("arbitrate",register("r1"));
                    require(!reservation && (register("sp")&7)==0,"Arbitration reservation/alignment");
                    require(register("r0")==handle && register("r2")==e.value() && register("r3")==e.extra(),"Arbitration arguments");
                    if(svc) require(register("r4")==0 && register("r5")==0,"SVC timeout words");
                    else require(Arrays.equals(memory(register("sp"),8),new byte[8]),"Timeout words");
                    require(Arrays.equals(memory(SIGNAL_WORD,8),signalBytes),"Arbitration signal bytes");
                    while(cursor<plan.events.size() && plan.events.get(cursor).kind().equals("effect")) {
                        var effect=plan.events.get(cursor++);
                        if(effect.address()==ARBITRATION_HANDLE) { handle=effect.value(); writeWord(ARBITRATION_HANDLE,handle); }
                        else put(signalBytes,(int)(effect.address()-SIGNAL_WORD),effect.value());
                    }
                    memory(SIGNAL_WORD,signalBytes); boundaryCalls++;
                    // Explicit worker model: completion may occur while inside acquire,
                    // signal or release arbitration. The outer wait must still sleep.
                    memory(DESC,completion); updated=true;
                    externalReturn(plan.response);
                    if(svc) {
                        sawSvc=true;
                        register("r4",0xcafebabeL); register("r5",0xfeedfaceL);
                        if(!rebuiltPath) visited.add(pc);
                        require(priorSteps+(++steps)<=8192,"Instruction budget");
                        thread.overrideCounter(toAddr(pc+4));
                    }
                    continue;
                }
                if(plan.pending && cursor==plan.events.size() && (bits&0x0ff00fffL)==0x01900f9fL) break;
                require(rebuiltPath ? within(pc,4,signalEntry,BUILD+codeSize) :
                    within(pc,4,0x2c4298,0x2c434c) || within(pc,4,0x1464f8,0x1465d4) ||
                    within(pc,4,0x138fc0,0x139010) ||
                    (recoverArbitration && within(pc,4,ARBITRATE,ARBITRATE+24)),"Unexpected signal PC "+Long.toHexString(pc));
                step(rebuiltPath,priorSteps+(++steps));
            }
            require(cursor==plan.events.size(),"Missing events: "+cursor+"/"+plan.events.size());
            require(!inWrapper,"Signal ended inside arbitration wrapper");
            require(!reservation && !storePending && !success,"Unconsumed exclusive state");
            require(word(memory(SIGNAL_WORD,4),0)==plan.signal && word(memory(LOCK_WORD,4),0)==plan.lock &&
                word(memory(ARBITRATION_HANDLE,4),0)==plan.handle,"Final signal oracle");
            require(Arrays.equals(memory(SIGNAL_WORD,8),signalBytes),"Final signal bytes");
            require(Arrays.equals(memory(DESC,0x144),updated ? completion : descriptor),"Signal descriptor effects");
            require(Arrays.equals(memory(NODES,list.length),list) && Arrays.equals(memory(PATH,256),path),"Signal list/path preservation");
            System.arraycopy(signalBytes,0,globals,(int)(SIGNAL_WORD-0x46500c),8);
            require(Arrays.equals(memory(0x46500c,globals.length),globals),"Signal global guards");
            require(word(memory(SIZE,4),0)==oldSize && polls==oldPolls && writes.size()==oldWrites,"Signal premature poll/cleanup");
            inSignal=false; signalCalls++;
            if(plan.pending) {
                require(thread.getCounter().getOffset()!=returnPC,"Pending signal returned");
                maxSteps=Math.max(maxSteps,priorSteps+steps); throw new PendingSignal();
            }
            require(register("sp")==entrySP,"Signal SP restoration");
            for(int r=4;r<=11;r++) require(register("r"+r)==saved[r-4],"Signal callee saved");
            // For a signal with no arbitration, the worker update is scheduled at return.
            if(!updated) memory(DESC,completion);
            return steps;
        }
    }
    void pendingSignals(SignalChainMachine a,SignalChainMachine b,Path out) throws Exception {
        try(PrintWriter log=new PrintWriter(Files.newBufferedWriter(out.resolve("pending-signals.tsv")))) {
            log.println("case\tlimit\tevents");
            for(int n:new int[]{1,2,7,31}) {
                long[] zeros=new long[n], positives=new long[n], negatives=new long[n];
                Arrays.fill(positives,2); Arrays.fill(negatives,MASK);
                List<CompareResourceSignalLock.Plan> plans=new ArrayList<>();
                for(long[] reads:new long[][]{zeros,positives,negatives,new long[]{0,0,2}})
                    plans.add(schedule(0,MASK-1,reads,new boolean[]{true},new long[]{-1},new boolean[]{false},0,1,n,2,MASK));
                plans.add(schedule(0,MASK-1,negatives,new boolean[]{false},new long[]{-1},new boolean[]{false},0,1,n,1,MASK));
                for(long first:new long[]{0,MASK})
                    plans.add(schedule(first,MASK-1,new long[]{2},new boolean[]{false},new long[]{-1},new boolean[]{false},0,2,n,2,MASK));
                for(long[] reads:new long[][]{positives,negatives})
                    plans.add(schedule(0,MASK-1,new long[]{2},new boolean[]{false},reads,new boolean[]{true},0,3,n,1,MASK));
                for(var p:plans) {
                    require(p.pending,"Pending fixture");
                    for(var machine:List.of(a,b)) {
                        machine.forcedPlan=p;
                        try {
                            machine.chain(machine==b,chainCases%2,"test/table.tbb",0,chainCases%3,3,true,
                                4,0x81234560L,MASK,0x80,1,0,false,0,0,0x2c5e9000L+chainCases);
                            throw new IllegalStateException("Pending chain returned");
                        } catch(PendingSignal expected) {
                            require(machine.polls==1 && word(machine.memory(SIZE,4),0)==0xa55a5aa5L &&
                                word(machine.memory(DESC+8,4),0)==0,"Pending chain cleanup");
                        } finally { machine.forcedPlan=null; }
                    }
                    require(a.writes.equals(b.writes) && a.calls.equals(b.calls) &&
                        Arrays.equals(a.memory(DESC,0x144),b.memory(DESC,0x144)) &&
                        Arrays.equals(a.memory(SIGNAL_WORD,8),b.memory(SIGNAL_WORD,8)),"Pending chain effects");
                    pendingCases++; signalPendingCases++;
                    log.printf("%d\t%d\t%s%n",++chainCases,n,p.events);
                }
            }
        }
    }
    @Override public void run() throws Exception {
        require(getScriptArgs().length==1 || (getScriptArgs().length==2 && getScriptArgs()[1].equals("svc")),"Arguments");
        recoverArbitration=getScriptArgs().length==2;
        Path out=Path.of(getScriptArgs()[0]); require(!Files.exists(out.resolve("comparison.json")),"Existing output");
        byte[] mapped=new byte[0x377000];
        require(currentProgram.getMemory().getBytes(toAddr(0x100000),mapped)==mapped.length,"Map");
        require(HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(mapped)).equals(
            "834938d18d2b7c688311c46c27bed813d0d7a9f8e3cbb61da8a6a3f23d360ebd"),"Hash");
        byte[] binary=Files.readAllBytes(out.resolve("resource-chain-signal.bin")); codeSize=binary.length;
        require(codeSize>0 && codeSize<=0x1000,"Binary extent");
        List<String> lines=Files.readAllLines(out.resolve("entries.txt")); require(lines.size()==(recoverArbitration ? 13 : 12),"Entries");
        for(String line:lines) require(within(Long.parseLong(line),4,BUILD,BUILD+codeSize),"Entry extent");
        for(int i=0;i<6;i++) entries[i]=Long.parseLong(lines.get(i));
        createEntry=Long.parseLong(lines.get(6)); waitEntry=Long.parseLong(lines.get(7));
        signalEntry=Long.parseLong(lines.get(9));
        if(recoverArbitration) arbitrationEntry=Long.parseLong(lines.get(12));
        SignalChainMachine a=new SignalChainMachine(mapped,binary),b=new SignalChainMachine(mapped,binary);
        String[] paths={"", "test/table.tbb", "rom:/test.tbb", "1234567:x", "12345678:x", "x".repeat(250)};
        long[] flags={0,1,2,3,0xfc,0x80000002L,0xffffffffL};
        long[][] results={{0,0},{1,0x7fffffffL},{0x80000000L,0},{0,0xffffffffL},{0xffffffffL,0x80000000L}};
        try(PrintWriter log=new PrintWriter(Files.newBufferedWriter(out.resolve("results.tsv")))) {
            log.println("case\tkind\tpath\tmode\tnodes\tterminal\thas_size\trounds\tvariant\tpending\tseed");
            for(int kind=0;kind<2;kind++) for(int p=0;p<paths.length;p++) for(int mode:new int[]{0,1,255})
            for(int nodes:new int[]{0,1,7}) for(long terminal:new long[]{4,5}) for(boolean size:new boolean[]{false,true})
            for(int rounds:new int[]{1,2,7}) for(int variant=0;variant<3;variant++) {
                // Include bounded nontermination without pretending to prove liveness.
                boolean pending=chainCases%17==0;
                long seed=0x2c5e9000L+chainCases, data=chainCases%2==0 ? 0 : 0x81234560L;
                long length=chainCases%3==0 ? 0 : chainCases%3==1 ? 0xffffffffL : 0x12345678L;
                long parameter=new long[]{0,4,0x80,0xffffffffL}[chainCases%4];
                long[] status=results[chainCases%results.length];
                a.chain(false,kind,paths[p],mode,nodes,flags[chainCases%flags.length],size,terminal,data,length,parameter,rounds,variant,pending,status[0],status[1],seed);
                b.chain(true,kind,paths[p],mode,nodes,flags[chainCases%flags.length],size,terminal,data,length,parameter,rounds,variant,pending,status[0],status[1],seed);
                require(a.writes.equals(b.writes) && a.calls.equals(b.calls),"Original/rebuilt effects");
                if(pending) pendingCases++;
                log.printf("%d\t%d\t%d\t%d\t%d\t%d\t%b\t%d\t%d\t%b\t%d%n",++chainCases,kind,p,mode,nodes,terminal,size,rounds,variant,pending,seed);
            }
        }
        pendingSignals(a,b,out);
        for(int i=0;i<START.length;i++) for(long pc=START[i];pc<STOP[i];pc+=4)
            require(visited.contains(pc),"Unvisited synchronous instruction "+Long.toHexString(pc));
        for(long[] range:new long[][]{{0x2b0494,0x2b0630},{0x1181b0,0x1181ec},{0x2bb4f0,0x2bb504},{0x2c4298,0x2c434c},{0x1464f8,0x1465d4},{0x138fc0,0x139010}})
            for(long pc=range[0];pc<range[1];pc+=4) require(visited.contains(pc),"Unvisited chain instruction "+Long.toHexString(pc));
        if(recoverArbitration) for(long pc=ARBITRATE;pc<ARBITRATE+24;pc+=4)
            require(visited.contains(pc),"Unvisited arbitration instruction");
        Files.writeString(out.resolve("visited.txt"),String.join("\n",visited.stream().map(v->String.format("%08x",v)).toList())+"\n");
        Files.writeString(out.resolve("comparison.json"),String.format(Locale.ROOT,
            "{\"chain_cases\":%d,\"pending_prefix_cases\":%d,\"signal_pending_prefix_cases\":%d,\"original_instruction_addresses\":%d,\"max_steps\":%d,\"outer_boundary_visits_both_paths\":%d,\"signal_calls_both_paths\":%d,\"arbitration_calls_both_paths\":%d,\"exclusive_attempts_both_paths\":%d,\"clear_exclusives_both_paths\":%d,\"wrapper_returns_both_paths\":%d,\"arbitration_intercepted\":%b,\"svc_intercepted\":%b,\"signal_locks_intercepted\":false,\"allocation_os_strings_timing_intercepted\":true,\"exclusive_outcomes_scheduled\":true,\"live_verified\":false}\n",
            chainCases,pendingCases,signalPendingCases,visited.size(),maxSteps,dependencyCalls,signalCalls,boundaryCalls,attempts,clears,wrapperReturns,!recoverArbitration,recoverArbitration));
        println("SMT4_CHAIN_SIGNAL_COMPARE_OK");
    }
}
