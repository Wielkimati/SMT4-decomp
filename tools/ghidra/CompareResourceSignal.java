// Signal orchestration: original/rebuilt instructions, scheduled exclusive outcomes.
// Lock operations and arbitration remain explicit models, not kernel emulation.
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

public class CompareResourceSignal extends CompareResourceLifecycle {
    static final long SIGNAL=0x2c4298, END_SIGNAL=0x2c434c, DATA=0x900020;
    static final long HANDLE=0x471b58, ACQUIRE=0x1464f8, RELEASE=0x138fc0, ARBITRATE=0x2a88fc;
    static final long MASK=0xffffffffL;
    static final long[] STATES={0,1,2,0x7fffffffL,0x80000000L,0xfffffffdL,0xfffffffeL,MASK};
    long entry, boundaryCalls, exclusiveAttempts;
    int cases, pendingCases;

    // Variants supply deterministic interfering writes at named boundaries.
    static long interference(int variant,int attempt) {
        return variant==1 ? (0x80000000L+attempt)&MASK : (attempt%2==0 ? MASK : 0);
    }
    class SignalMachine extends Machine {
        List<String> events=new ArrayList<>();
        byte[] expected;
        long first, second, handle, result;
        int failures, variant, mode, reads, loads, attempts, stateStores, acquires, wakes, releases;
        boolean pending, reservation, exclusiveLoad, successfulStore;
        SignalMachine(byte[] mapped,byte[] binary) { super(mapped,binary); }

        @Override public void beforeExecuteInstruction(PcodeThread<byte[]> t,Instruction instruction,PcodeProgram program) {
            exclusiveLoad=instruction.getMnemonicString().equalsIgnoreCase("ldrex");
            if(exclusiveLoad) {
                require(!reservation,"LDREX without consuming reservation");
                if(variant!=0 && loads==0) {
                    put(expected,32,interference(variant,0)); memory(DATA-32,expected);
                }
            }
        }
        @Override public void beforeLoad(PcodeThread<byte[]> t,PcodeOp op,AddressSpace space,byte[] offset,int size) {
            long a=Utils.bytesToLong(offset,offset.length,false);
            require((a==DATA && size==4) || (a==HANDLE && size==4) ||
                    within(a,size,0x100000,0x477000) || within(a,size,BUILD,BUILD+codeSize) ||
                    within(a,size,STACK-0x1000,STACK),"Unexpected read "+Long.toHexString(a));
            if(a==DATA) {
                if(exclusiveLoad) {
                    require(mode!=0 && (mode!=2 || acquires==1),"Exclusive before acquire");
                    loads++; reservation=true;
                    events.add("exclusive-load:"+word(expected,32));
                } else {
                    require(++reads<= (first==MASK ? 1 : 2),"Mode read count");
                    if(reads==2) { put(expected,32,second); memory(DATA-32,expected); }
                    events.add("read:"+word(expected,32));
                }
            }
            if(a==HANDLE) {
                require(stateStores==1,"Handle loaded before successful exchange");
                events.add("handle:"+handle);
            }
        }
        @Override public boolean handleMissingUserop(PcodeThread<byte[]> t,PcodeOp op,PcodeFrame frame,
                String name,PcodeUseropLibrary<byte[]> library) {
            require(name.equals("hasExclusiveAccess"),"Unexpected userop "+name);
            byte[] arg=t.getState().getVar(op.getInput(1),Reason.INSPECT);
            require(Utils.bytesToLong(arg,arg.length,false)==DATA && reservation,"Exclusive address/reservation");
            require(loads==attempts+1 && stateStores==0,"Exclusive attempt order");
            reservation=false;
            boolean success=!pending && attempts>=failures;
            attempts++; exclusiveAttempts++;
            events.add("exclusive-store:"+(success ? "success" : "failure"));
            if(!success && variant!=0) {
                put(expected,32,interference(variant,attempts)); memory(DATA-32,expected);
            }
            successfulStore=success;
            t.getState().setVar(op.getOutput(),machine.getArithmetic().fromConst(success ? 1 : 0,op.getOutput().getSize()));
            return true;
        }
        @Override public void beforeStore(PcodeThread<byte[]> t,PcodeOp op,AddressSpace space,
                byte[] offset,int size,byte[] value) {
            long a=Utils.bytesToLong(offset,offset.length,false);
            if(within(a,size,STACK-0x1000,STACK)) return;
            require(a==DATA && size==4 && successfulStore,"Unexpected nonexclusive store");
            require(++stateStores==1 && word(value,0)==(mode==1 ? 0 : 1),"Exchange value/count");
            successfulStore=false; put(expected,32,word(value,0)); events.add("write:"+word(value,0));
        }
        void externalReturn() {
            long lr=register("lr");
            for(String r:new String[]{"r0","r1","r2","r3","r12"}) register(r,0xdeadbeefL);
            register("r0",result); register("cpsr",0xa0000010L);
            thread.overrideContext(new RegisterValue(currentProgram.getProgramContext().getBaseContextRegister(),BigInteger.ZERO));
            thread.overrideCounter(toAddr(lr & ~1L));
        }
        void call(boolean rebuiltPath,long firstValue,long secondValue,int failCount,int changes,
                long response,boolean bounded,long seed) throws Exception {
            executing=false; events.clear();
            first=firstValue; second=secondValue; failures=failCount; variant=changes; result=response; pending=bounded;
            mode=first==MASK ? 1 : second==MASK-1 ? 2 : 0;
            reads=loads=attempts=stateStores=acquires=wakes=releases=0;
            reservation=exclusiveLoad=successfulStore=false;
            expected=new byte[96]; new Random(seed).nextBytes(expected); put(expected,32,first);
            memory(DATA-32,expected); handle=seed&MASK; writeWord(HANDLE,handle);
            byte[] stack=new byte[0x1000]; Arrays.fill(stack,(byte)0x96); memory(STACK-0x1000,stack);
            for(var r:currentProgram.getLanguage().getRegisters())
                if(r.isBaseRegister() && !r.isProcessorContext()) register(r,0);
            for(int r=0;r<=12;r++) register("r"+r,0x12340000L+r);
            register("cpsr",0x10); register("sp",STACK); register("lr",RETURN); register("r0",DATA);
            thread.overrideContext(new RegisterValue(currentProgram.getProgramContext().getBaseContextRegister(),BigInteger.ZERO));
            thread.overrideCounter(toAddr(rebuiltPath ? entry : SIGNAL)); executing=true;
            int steps=0;
            while(thread.getCounter().getOffset()!=RETURN) {
                long pc=thread.getCounter().getOffset();
                if(pc==ACQUIRE || pc==ARBITRATE || pc==RELEASE) {
                    require((register("sp")&7)==0,"Boundary stack alignment");
                    require(Arrays.equals(memory(DATA-32,expected.length),expected),"Boundary memory");
                    if(pc==ACQUIRE) {
                        require(mode==2 && ++acquires==1 && attempts==0 && wakes==0,"Acquire order");
                        require(register("r0")==DATA+4,"Acquire argument"); events.add("acquire");
                        // Independent boundary effects; handle must be reloaded after acquisition.
                        put(expected,36,0x80000001L+variant);
                        if(variant!=0) put(expected,32,0x76543210L);
                        handle^=0x1234abcdL; writeWord(HANDLE,handle);
                    } else if(pc==ARBITRATE) {
                        require(mode!=0 && ++wakes==1 && stateStores==1 && releases==0,"Arbitration order");
                        require(register("r0")==handle && register("r1")==DATA && register("r2")==0 &&
                                register("r3")== (mode==1 ? 1 : MASK),"Arbitration arguments");
                        require(word(memory(register("sp"),8),0)==0 && word(memory(register("sp"),8),4)==0,"Timeout");
                        events.add("wake:"+(mode==1 ? 1 : -1));
                        if(variant==2) put(expected,32,0x89abcdefL);
                    } else {
                        require(mode==2 && ++releases==1 && wakes==1,"Release order");
                        require(register("r0")==DATA+4,"Release argument"); events.add("release");
                        put(expected,36,0x76543210L+variant);
                    }
                    memory(DATA-32,expected); boundaryCalls++; externalReturn(); continue;
                }
                require(rebuiltPath ? within(pc,4,BUILD,BUILD+codeSize) : within(pc,4,SIGNAL,END_SIGNAL),"Unexpected PC");
                long instruction=word(memory(pc,4),0);
                boolean nextExclusive=(instruction&0x0ff00fffL)==0x01900f9fL;
                if(pending && attempts==failures && nextExclusive) break;
                if(!rebuiltPath) visited.add(pc);
                require(++steps<=2048,"Instruction budget"); monitor.checkCancelled(); thread.stepInstruction();
            }
            require(reads==(first==MASK ? 1 : 2),"Missing mode reread");
            require(loads==attempts && attempts==(mode==0 ? 0 : pending ? failures : failures+1),"Retry count");
            require(stateStores==(mode==0 || pending ? 0 : 1),"Store count");
            require(acquires==(mode==2 ? 1 : 0) && wakes==(mode==0 || pending ? 0 : 1) &&
                    releases==(mode==2 && !pending ? 1 : 0),"Final boundary counts");
            require(Arrays.equals(memory(DATA-32,expected.length),expected),"Final signal/guard memory");
            require(word(memory(HANDLE,4),0)==handle,"Handle preservation");
            require(!reservation,"Unconsumed reservation");
            if(!pending) {
                require(register("sp")==STACK,"SP restoration");
                for(int r=4;r<=11;r++) require(register("r"+r)==0x12340000L+r,"Callee saved");
            } else require(thread.getCounter().getOffset()!=RETURN,"Pending exchange returned");
            maxSteps=Math.max(maxSteps,steps);
        }
    }
    void compare(SignalMachine a,SignalMachine b,PrintWriter log,long first,long second,int failures,
            int variant,long result,boolean pending) throws Exception {
        long seed=0x2c4298L+cases*0x10001L;
        a.call(false,first,second,failures,variant,result,pending,seed);
        b.call(true,first,second,failures,variant,result,pending,seed);
        require(a.events.equals(b.events),"Original/rebuilt event trace");
        require(Arrays.equals(a.memory(DATA-32,96),b.memory(DATA-32,96)),"Original/rebuilt memory");
        if(pending) pendingCases++;
        log.printf("%d\t%x\t%x\t%d\t%d\t%x\t%b\t%s%n",++cases,first,second,failures,variant,result,pending,String.join(",",a.events));
    }
    @Override public void run() throws Exception {
        Path out=Path.of(getScriptArgs()[0]); require(!Files.exists(out.resolve("comparison.json")),"Existing output");
        byte[] mapped=new byte[0x377000];
        require(currentProgram.getMemory().getBytes(toAddr(0x100000),mapped)==mapped.length,"Map");
        require(HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(mapped)).equals(
            "834938d18d2b7c688311c46c27bed813d0d7a9f8e3cbb61da8a6a3f23d360ebd"),"Hash");
        byte[] binary=Files.readAllBytes(out.resolve("resource-signal.bin")); codeSize=binary.length;
        require(codeSize>0 && codeSize<=0x1000,"Binary size");
        List<String> lines=Files.readAllLines(out.resolve("entries.txt")); require(lines.size()==1,"Entries");
        entry=Long.parseLong(lines.get(0)); require(within(entry,4,BUILD,BUILD+codeSize),"Entry extent");
        SignalMachine a=new SignalMachine(mapped,binary),b=new SignalMachine(mapped,binary);
        try(PrintWriter log=new PrintWriter(Files.newBufferedWriter(out.resolve("results.tsv")))) {
            log.println("case\tfirst\tsecond\tfailures\tvariant\tresult\tpending\tevents");
            for(long first:STATES) for(long second:STATES) for(int failures:new int[]{0,1,2,7})
            for(int variant=0;variant<3;variant++) for(long result:new long[]{0,0x7fffffffL,0x80000000L})
                compare(a,b,log,first,second,failures,variant,result,false);
            Random random=new Random(SIGNAL);
            for(int i=0;i<1024;i++) {
                long first=i%3==0 ? MASK : Integer.toUnsignedLong(random.nextInt());
                long second=i%3==1 ? MASK-1 : Integer.toUnsignedLong(random.nextInt());
                compare(a,b,log,first,second,random.nextInt(16),i%3,Integer.toUnsignedLong(random.nextInt()),false);
            }
            for(long first:new long[]{MASK,MASK-1}) for(int failures:new int[]{1,2,7,31}) for(int variant=0;variant<3;variant++)
                compare(a,b,log,first,MASK-1,failures,variant,0,true);
        }
        for(long pc=SIGNAL;pc<END_SIGNAL;pc+=4) require(visited.contains(pc),"Unvisited instruction "+Long.toHexString(pc));
        Files.writeString(out.resolve("visited.txt"),String.join("\n",visited.stream().map(v->String.format("%08x",v)).toList())+"\n");
        Files.writeString(out.resolve("comparison.json"),String.format(Locale.ROOT,
            "{\"signal_cases\":%d,\"pending_prefix_cases\":%d,\"original_instruction_addresses\":%d,\"max_steps\":%d,\"boundary_calls_both_paths\":%d,\"exclusive_attempts_both_paths\":%d,\"lock_arbitration_intercepted\":true,\"exclusive_outcomes_scheduled\":true,\"live_verified\":false}\n",
            cases,pendingCases,visited.size(),maxSteps,boundaryCalls,exclusiveAttempts));
        println("SMT4_SIGNAL_COMPARE_OK");
    }
}
