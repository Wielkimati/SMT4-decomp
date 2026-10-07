// Wait/delay comparisons with scheduled state changes, not live scheduling.
// @category SMT4
import ghidra.program.model.lang.RegisterValue;
import ghidra.pcode.emu.PcodeThread;
import ghidra.pcode.utils.Utils;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.pcode.PcodeOp;
import java.math.BigInteger;
import java.nio.file.*;
import java.security.MessageDigest;
import java.util.*;
import java.io.*;

public class CompareResourceWait extends CompareResourceLifecycle {
    static final long DESC=0x900000, SIGNAL=0x2c4298, SLEEP=0x1382e4, SPIN=0x1382bc;
    static final long WAIT=0x1181b0, DELAY=0x2bb4f0, SIGNAL_DATA=0x465024;
    static final long[] PENDING={0,1,2,3,6,0x80000000L,0xffffffffL};
    long waitEntry, delayEntry, dependencyCalls;
    int waitCases, delayCases, pendingCases;
    class WaitMachine extends Machine {
        int polls;
        List<String> calls=new ArrayList<>();
        WaitMachine(byte[] mapped,byte[] binary) { super(mapped,binary); }
        @Override public void beforeStore(PcodeThread<byte[]> t,PcodeOp op,
                AddressSpace space,byte[] offset,int size,byte[] value) {
            long a=Utils.bytesToLong(offset,offset.length,false);
            require(within(a,size,STACK-0x1000,STACK),"Unexpected store "+Long.toHexString(a));
        }
        @Override public void beforeLoad(PcodeThread<byte[]> t,PcodeOp op,
                AddressSpace space,byte[] offset,int size) {
            long a=Utils.bytesToLong(offset,offset.length,false);
            require((a==DESC && size==4) || within(a,size,0x100000,0x477000) ||
                    within(a,size,BUILD,BUILD+codeSize) || within(a,size,STACK-0x1000,STACK),
                    "Unexpected read "+Long.toHexString(a));
            if(a==DESC) polls++;
        }
        void setup(long entry,long low,long high,byte[] descriptor) {
            executing=false; polls=0; calls.clear();
            memory(DESC,descriptor);
            byte[] stack=new byte[0x1000]; Arrays.fill(stack,(byte)0x96); memory(STACK-0x1000,stack);
            for(var r:currentProgram.getLanguage().getRegisters())
                if(r.isBaseRegister() && !r.isProcessorContext()) register(r,0);
            for(int r=0;r<=12;r++) register("r"+r,0x12340000L+r);
            register("cpsr",0x10); register("sp",STACK); register("lr",RETURN);
            register("r0",low); register("r1",high);
            thread.overrideContext(new RegisterValue(currentProgram.getProgramContext().getBaseContextRegister(),BigInteger.ZERO));
            thread.overrideCounter(toAddr(entry)); executing=true;
        }
        void externalReturn() {
            long lr=register("lr");
            for(String r:new String[]{"r0","r1","r2","r3","r12"}) register(r,0xdeadbeefL);
            register("cpsr",0xa0000010L);
            thread.overrideContext(new RegisterValue(currentProgram.getProgramContext().getBaseContextRegister(),BigInteger.ZERO));
            thread.overrideCounter(toAddr(lr & ~1L));
        }
        void abi() {
            require(register("sp")==STACK,"SP restoration");
            for(int r=4;r<=11;r++) require(register("r"+r)==0x12340000L+r,"Callee-saved register");
        }
        void step(boolean rebuiltPath,boolean includeWait,int steps) throws Exception {
            long pc=thread.getCounter().getOffset();
            require(rebuiltPath ? within(pc,4,BUILD,BUILD+codeSize) :
                    within(pc,4,DELAY,0x2bb518) || (includeWait && within(pc,4,WAIT,0x1181ec)),
                    "Unexpected PC "+Long.toHexString(pc));
            if(!rebuiltPath) visited.add(pc);
            require(steps<=4096,"Instruction budget"); monitor.checkCancelled(); thread.stepInstruction();
        }
        void waitCall(boolean rebuiltPath,long initial,int rounds,long terminal,int variant,boolean pending,long seed) throws Exception {
            byte[] expected=new byte[0x144]; new Random(seed).nextBytes(expected); put(expected,0,initial);
            setup(rebuiltPath ? waitEntry : WAIT,DESC,0,expected);
            int signals=0,sleeps=0,steps=0;
            while(thread.getCounter().getOffset()!=RETURN) {
                long pc=thread.getCounter().getOffset();
                if(pc==SIGNAL || pc==SLEEP) {
                    require((register("sp")&7)==0,"Dependency stack alignment");
                    require(Arrays.equals(memory(DESC,expected.length),expected),"Descriptor before dependency");
                    if(pc==SIGNAL) {
                        require(signals==sleeps && polls==signals+1,"Signal/poll order");
                        require(register("r0")==SIGNAL_DATA,"Signal argument");
                        if(pending && signals==rounds) break; // bounded nontermination observation
                        require(signals<rounds,"Unexpected extra iteration");
                        signals++;
                        // Completion at signal does not bypass the subsequent delay.
                        long state=variant==2 ? (signals%2==0 ? 4 : 5) :
                            variant==0 && signals==rounds ? terminal : PENDING[signals%PENDING.length];
                        put(expected,0,state); calls.add("signal");
                    } else {
                        require(signals==sleeps+1 && polls==signals,"Delay/poll order");
                        require(register("r0")==3000000 && register("r1")==0,"Delay duration");
                        sleeps++;
                        long state=!pending && sleeps==rounds ? terminal : PENDING[(sleeps+2)%PENDING.length];
                        put(expected,0,state); calls.add("sleep:3000000");
                    }
                    memory(DESC,expected); dependencyCalls++; externalReturn(); continue;
                }
                step(rebuiltPath,true,++steps);
            }
            require(signals==rounds && sleeps==rounds,"Dependency count");
            require(polls==rounds+1,"One state read per poll");
            require(Arrays.equals(memory(DESC,expected.length),expected),"Final descriptor");
            if(!pending) abi();
            else require(thread.getCounter().getOffset()!=RETURN,"Pending state returned");
            maxSteps=Math.max(maxSteps,steps);
        }
        void delayCall(boolean rebuiltPath,long duration) throws Exception {
            byte[] descriptor=new byte[0x144]; Arrays.fill(descriptor,(byte)0xa5);
            setup(rebuiltPath ? delayEntry : DELAY,duration&0xffffffffL,duration>>>32,descriptor);
            boolean sleep=duration>=0x3477;
            long scaled=BigInteger.valueOf(duration).multiply(new BigInteger("44a2fa85",16))
                .shiftRight(32).and(new BigInteger("ffffffff",16)).longValue();
            int steps=0,count=0;
            while(thread.getCounter().getOffset()!=RETURN) {
                long pc=thread.getCounter().getOffset();
                if(pc==SLEEP || pc==SPIN) {
                    require(++count==1 && pc==(sleep ? SLEEP : SPIN),"Delay branch");
                    require((register("sp")&7)==0,"Delay stack alignment");
                    require(register("r0")== (sleep ? duration&0xffffffffL : scaled),"Delay low/scaled argument");
                    if(sleep) require(register("r1")==duration>>>32,"Delay high argument");
                    calls.add(sleep ? "sleep:"+duration : "spin:"+scaled);
                    dependencyCalls++; externalReturn(); continue;
                }
                step(rebuiltPath,false,++steps);
            }
            require(count==1 && polls==0,"Direct delay dependencies");
            require(Arrays.equals(memory(DESC,descriptor.length),descriptor),"Direct delay descriptor preservation");
            abi(); maxSteps=Math.max(maxSteps,steps);
        }
    }
    @Override public void run() throws Exception {
        Path out=Path.of(getScriptArgs()[0]); require(!Files.exists(out.resolve("comparison.json")),"Existing output");
        byte[] mapped=new byte[0x377000];
        require(currentProgram.getMemory().getBytes(toAddr(0x100000),mapped)==mapped.length,"Map");
        require(HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(mapped)).equals(
            "834938d18d2b7c688311c46c27bed813d0d7a9f8e3cbb61da8a6a3f23d360ebd"),"Hash");
        byte[] binary=Files.readAllBytes(out.resolve("resource-wait.bin")); codeSize=binary.length;
        require(codeSize>0 && codeSize<=0x1000,"Binary size");
        List<String> lines=Files.readAllLines(out.resolve("entries.txt")); require(lines.size()==2,"Entries");
        waitEntry=Long.parseLong(lines.get(0)); delayEntry=Long.parseLong(lines.get(1));
        require(within(waitEntry,4,BUILD,BUILD+codeSize) && within(delayEntry,4,BUILD,BUILD+codeSize),"Entries extent");
        WaitMachine a=new WaitMachine(mapped,binary),b=new WaitMachine(mapped,binary);
        try(PrintWriter log=new PrintWriter(Files.newBufferedWriter(out.resolve("results.tsv")))) {
            log.println("kind\tcase\tinput\trounds\tterminal\tvariant\tpending");
            for(long state:new long[]{4,5}) compareWait(a,b,log,state,0,state,0,false);
            for(long state:PENDING) for(int rounds:new int[]{1,2,7,31})
            for(long terminal:new long[]{4,5}) for(int variant=0;variant<3;variant++)
                compareWait(a,b,log,state,rounds,terminal,variant,false);
            for(long state:PENDING) for(int variant=0;variant<3;variant++)
                compareWait(a,b,log,state,8,4,variant,true);
            List<Long> durations=new ArrayList<>();
            for(long d:new long[]{Long.MIN_VALUE,Long.MIN_VALUE+1,-0x100000001L,-0x100000000L,
                -0xffffffffL,-13432,-13431,-2,-1,0,1,2,3,4,13429,13430,13431,13432,
                3000000,0x7fffffffL,0x80000000L,0xffffffffL,0x100000000L,Long.MAX_VALUE}) durations.add(d);
            Random rng=new Random(0x2bb4f0);
            for(int i=0;i<1024;i++) durations.add(rng.nextLong());
            // Exhaust the short nonnegative branch, including multiply/rounding boundaries.
            for(long d=0;d<13431;d++) durations.add(d);
            for(long d:durations) {
                a.delayCall(false,d); b.delayCall(true,d);
                require(a.calls.equals(b.calls),"Original/rebuilt delay calls");
                log.printf("delay\t%d\t%d\t0\t0\t0\tfalse%n",++delayCases,d);
            }
        }
        for(long pc=WAIT;pc<0x1181ec;pc+=4) require(visited.contains(pc),"Unvisited wait instruction");
        for(long pc=DELAY;pc<0x2bb518;pc+=4) require(visited.contains(pc),"Unvisited delay instruction");
        Files.writeString(out.resolve("visited.txt"),String.join("\n",visited.stream().map(v->String.format("%08x",v)).toList())+"\n");
        Files.writeString(out.resolve("comparison.json"),String.format(Locale.ROOT,
            "{\"wait_cases\":%d,\"pending_prefix_cases\":%d,\"delay_cases\":%d,\"original_instruction_addresses\":%d,\"max_steps\":%d,\"dependency_calls_both_paths\":%d,\"signal_sleep_spin_intercepted\":true,\"live_verified\":false}\n",
            waitCases,pendingCases,delayCases,visited.size(),maxSteps,dependencyCalls));
        println("SMT4_WAIT_COMPARE_OK");
    }
    void compareWait(WaitMachine a,WaitMachine b,PrintWriter log,long state,int rounds,long terminal,int variant,boolean pending) throws Exception {
        long seed=0x1181b0L+waitCases;
        a.waitCall(false,state,rounds,terminal,variant,pending,seed);
        b.waitCall(true,state,rounds,terminal,variant,pending,seed);
        require(a.calls.equals(b.calls),"Original/rebuilt wait calls");
        if(pending) pendingCases++;
        log.printf("wait\t%d\t%d\t%d\t%d\t%d\t%b%n",++waitCases,state,rounds,terminal,variant,pending);
    }
}
