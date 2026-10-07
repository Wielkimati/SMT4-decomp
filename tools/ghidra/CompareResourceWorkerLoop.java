// Outer worker entry with an explicit node-region boundary and scheduled lower calls.
// @category SMT4
import ghidra.pcode.emu.PcodeThread;
import ghidra.pcode.utils.Utils;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.pcode.PcodeOp;
import java.nio.file.*;
import java.security.MessageDigest;
import java.util.*;
import java.io.*;

public class CompareResourceWorkerLoop extends CompareResourceSync {
    static final long GLOBAL=0x465000, WAIT=0x2c367c, RESET=0x138f5c, DELAY=0x2bb4f0;
    static final long ACQUIRE=0x2c4350, UNLOCK=0x2c54a4, CHECK=0x2c54bc, NODE=0x710000;
    static final long MASK=0xffffffffL;
    static final long[][] RANGES={{0x113d58,0x113de8},{0x1142d4,0x1142e8},{0x114340,0x114370}};
    int cases;
    long nodeCalls, lowerCalls;
    @Override boolean originalCode(long pc) {
        for(long[] range:RANGES) if(within(pc,4,range[0],range[1])) return true;
        return false;
    }
    class Scenario {
        String stopAt;
        int nodes, rounds, errors, stopValue, mutation;
        Scenario(String s,int n,int r,int e,int v,int m) {
            stopAt=s; nodes=n; rounds=r; errors=e; stopValue=v; mutation=m;
        }
        long node(int index) { return index>=nodes ? 0 : DESC+((mutation&1)!=0 ? 0x1000 : 0)+index*0x200; }
        long result(boolean acquire) {
            return (errors & (acquire ? 1 : 2))!=0 ? (acquire ? 0x80000042L : MASK) : 0x7fffffffL;
        }
        boolean stopped(String event,int round,boolean prior) {
            if(event.equals("wait") && stopAt.equals("clear-initial") && round==1) prior=false;
            if(event.equals("wait") && round>rounds) return true;
            return prior || (round==rounds && event.equals(stopAt));
        }
        // Independent orchestration oracle: scheduled effects only determine stop;
        // expected node arguments come from the fixture, never executed registers.
        List<String> oracle() {
            List<String> events=new ArrayList<>();
            boolean stop=stopAt.equals("initial") || stopAt.equals("clear-initial");
            for(int round=1;round<=rounds+1;round++) {
                events.add("wait"); stop=stopped("wait",round,stop);
                if(stop) break;
                for(String event:new String[]{"acquire","check-acquire","unlock","check-unlock"}) {
                    if(event.equals("check-acquire") && (errors&1)==0) continue;
                    if(event.equals("check-unlock") && (errors&2)==0) continue;
                    events.add(event); stop=stopped(event,round,stop);
                }
                if(stop) break;
                for(int n=0;n<nodes;n++) {
                    String event="node-"+n;
                    events.add(event);
                    stop=stopped(event,round,stop);
                    if(stop) break;
                }
                if(stop) break;
                events.add("reset"); stop=stopped("reset",round,stop);
                events.add("delay"); stop=stopped("delay",round,stop);
            }
            return events;
        }
        public String toString() { return stopAt+"/"+nodes+"/"+rounds+"/"+errors+"/"+stopValue+"/"+mutation; }
    }
    class LoopMachine extends SyncMachine {
        List<String> trace=new ArrayList<>(), events=new ArrayList<>();
        int round, nodeIndex;
        Scenario scenario;
        String lastLock;
        LoopMachine(byte[] mapped,byte[] binary) { super(mapped,binary); }
        long get(long address) { return word(memory(address,4),0); }
        @Override public void beforeStore(PcodeThread<byte[]> t,PcodeOp op,AddressSpace space,
                byte[] offset,int size,byte[] value) {
            long address=Utils.bytesToLong(offset,offset.length,false);
            require(within(address,size,STACK-0x1000,STACK),"Unexpected outer-loop store "+Long.toHexString(address));
        }
        @Override public void beforeLoad(PcodeThread<byte[]> t,PcodeOp op,AddressSpace space,
                byte[] offset,int size) {
            long address=Utils.bytesToLong(offset,offset.length,false);
            require((address==GLOBAL && size==1) ||
                    ((address==GLOBAL+12 || address==GLOBAL+16) && size==4) ||
                    within(address,size,0x113d58,0x114374) ||
                    within(address,size,BUILD,BUILD+codeSize) || within(address,size,STACK-0x1000,STACK),
                    "Unexpected outer-loop read "+Long.toHexString(address));
        }
        void event(String name) {
            events.add(name);
            trace.add(name+":"+HexFormat.of().formatHex(memory(GLOBAL,0x40)));
            require(events.size()<=64,"Dependency budget");
            boolean prior=memory(GLOBAL,1)[0]!=0;
            memory(GLOBAL,new byte[]{(byte)(scenario.stopped(name,round,prior) ? scenario.stopValue : 0)});
            // Every boundary can replace the global handle; acquire's stack copy
            // and unlock's reload must still match the original timing.
            writeWord(GLOBAL+16,(get(GLOBAL+16)+0x10203)&MASK);
        }
        void call(boolean rebuiltPath,Scenario s) throws Exception {
            scenario=s; trace.clear(); events.clear(); round=0; nodeIndex=0; lastLock="";
            initialize(rebuiltPath,0,new byte[0x144]);
            byte[] globals=new byte[0x40]; Arrays.fill(globals,(byte)0xa5);
            put(globals,12,(s.mutation&1)!=0 ? 0x909000 : s.node(0)); put(globals,16,0xffff0010L);
            globals[0]=(byte)((s.stopAt.equals("initial") || s.stopAt.equals("clear-initial")) ? s.stopValue : 0);
            memory(GLOBAL,globals);
            thread.overrideCounter(toAddr(rebuiltPath ? entries[0] : 0x113d58)); executing=true;
            int steps=0;
            while(thread.getCounter().getOffset()!=RETURN) {
                long pc=thread.getCounter().getOffset(), result=0;
                boolean external=true;
                if(pc==WAIT) {
                    require(register("r0")==GLOBAL+0x24,"Wait event address");
                    round++; nodeIndex=0; event("wait");
                } else if(pc==ACQUIRE) {
                    require(register("r2")==1 && register("r3")==0,"Acquire count/wait-all");
                    require(within(register("r1"),4,register("sp"),STACK-16),"Handle pointer");
                    require(get(register("r1"))==get(GLOBAL+16),"Acquire handle snapshot");
                    require(get(register("sp"))==MASK && get(register("sp")+4)==MASK,"Infinite timeout");
                    require(within(register("r0"),4,register("sp"),STACK-16),"Acquire output pointer");
                    writeWord(register("r0"),7); event("acquire");
                    writeWord(GLOBAL+12,s.node(0)); lastLock="acquire"; result=s.result(true);
                } else if(pc==UNLOCK) {
                    require(register("r1")==get(GLOBAL+16) && register("r2")==1,"Unlock handle/count");
                    require(within(register("r0"),4,register("sp"),STACK-16),"Unlock output pointer");
                    writeWord(register("r0"),9); event("unlock");
                    if((s.mutation&2)!=0) writeWord(GLOBAL+12,0x909000);
                    lastLock="unlock"; result=s.result(false);
                } else if(pc==CHECK) {
                    boolean acquiring=lastLock.equals("acquire");
                    require((s.result(acquiring)&0x80000000L)!=0 && register("r0")==s.result(acquiring) && register("r1")==1,"Checker arguments/sign");
                    event("check-"+lastLock); result=0xdeadbeefL;
                } else if(pc==(rebuiltPath ? NODE : 0x113de8)) {
                    require((register("sp")&7)==0,"Node stack alignment");
                    require(nodeIndex<s.nodes,"Excess node visit");
                    require(register(rebuiltPath ? "r0" : "r7")==s.node(nodeIndex),"Node order/head snapshot");
                    event("node-"+nodeIndex); result=s.node(++nodeIndex); nodeCalls++;
                    if(rebuiltPath) externalReturn(result);
                    else {
                        // Adapted region returns r7 at the original loop boundary.
                        for(String reg:new String[]{"r0","r1","r2","r3","r12"}) register(reg,0xdeadbeefL);
                        register("r7",result); register("cpsr",0xa0000010L);
                        thread.overrideCounter(toAddr(0x113dd4));
                    }
                    continue;
                } else if(pc==RESET) {
                    require(register("r0")==GLOBAL+0x24,"Reset event address"); event("reset");
                } else if(pc==DELAY) {
                    require(register("r0")==3000000 && register("r1")==0,"Delay 64-bit duration"); event("delay");
                } else external=false;
                if(external) {
                    require((register("sp")&7)==0,"Call stack alignment");
                    lowerCalls++; externalReturn(result); continue;
                }
                require(rebuiltPath ? within(pc,4,BUILD,BUILD+codeSize) : originalCode(pc),"Instruction escape "+Long.toHexString(pc));
                if(!rebuiltPath) visited.add(pc);
                require(++steps<2000,"Instruction budget"); monitor.checkCancelled(); thread.stepInstruction();
            }
            require(events.equals(s.oracle()),"Oracle dependency sequence: "+events+" expected "+s.oracle());
            finish(steps);
            for(byte value:memory(STACK-0x1000,0x800)) require(value==(byte)0x96,"Stack lower guard");
        }
    }
    @Override public void run() throws Exception {
        Path out=Path.of(getScriptArgs()[0]);
        require(!Files.exists(out.resolve("comparison.json")),"Existing output");
        byte[] mapped=new byte[0x377000];
        require(currentProgram.getMemory().getBytes(toAddr(0x100000),mapped)==mapped.length,"Map");
        require(HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(mapped)).equals(
            "834938d18d2b7c688311c46c27bed813d0d7a9f8e3cbb61da8a6a3f23d360ebd"),"Hash");
        byte[] binary=Files.readAllBytes(out.resolve("worker-loop.bin")); codeSize=binary.length;
        require(codeSize>0 && codeSize<=0x1000,"Binary extent");
        entries[0]=Long.parseLong(Files.readString(out.resolve("entries.txt")).trim());
        require(within(entries[0],4,BUILD,BUILD+codeSize),"Entry extent");
        LoopMachine a=new LoopMachine(mapped,binary),b=new LoopMachine(mapped,binary);
        try(PrintWriter log=new PrintWriter(Files.newBufferedWriter(out.resolve("results.tsv")))) {
            log.println("case\tscenario\tevents");
            for(String stop:new String[]{"initial","wait","acquire","check-acquire","unlock","check-unlock","node-0","node-2","reset","delay","none","clear-initial"})
            for(int nodes:new int[]{0,1,3}) for(int rounds:new int[]{1,3}) for(int errors=0;errors<4;errors++)
            for(int value:new int[]{1,128,255}) for(int mutation=0;mutation<4;mutation++) {
                Scenario s=new Scenario(stop,nodes,rounds,errors,value,mutation);
                try {
                    a.call(false,s); b.call(true,s);
                    require(a.trace.equals(b.trace),"Dependency snapshots differ");
                    require(Arrays.equals(a.memory(GLOBAL,0x40),b.memory(GLOBAL,0x40)),"Global state differs");
                    log.printf("%d\t%s\t%s%n",++cases,s,a.events);
                } catch(Exception e) { println("Worker loop case "+cases+" "+s); throw e; }
            }
        }
        StringBuilder listing=new StringBuilder();
        for(long[] range:RANGES) for(long pc=range[0];pc<range[1];pc+=4) {
            require(visited.contains(pc),"Unvisited outer-loop instruction "+Long.toHexString(pc));
            var instruction=currentProgram.getListing().getInstructionAt(toAddr(pc));
            require(instruction!=null,"Missing Ghidra instruction");
            listing.append(String.format("%08x %s%n",pc,instruction));
        }
        Files.writeString(out.resolve("original-loop-ghidra.txt"),listing);
        Files.writeString(out.resolve("comparison.json"),String.format(Locale.ROOT,
            "{\"cases\":%d,\"original_instruction_addresses\":%d,\"binary_bytes\":%d,\"max_steps\":%d,\"paired_node_calls\":%d,\"paired_lower_calls\":%d,\"node_region_modeled\":true,\"live_verified\":false}\n",
            cases,visited.size(),codeSize,maxSteps,nodeCalls,lowerCalls));
        println("SMT4_WORKER_LOOP_OK");
    }
}
