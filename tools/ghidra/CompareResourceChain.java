// Integrated synchronous loader: constructor and wait/delay execute instructions.
// @category SMT4
import ghidra.pcode.emu.PcodeThread;
import ghidra.pcode.utils.Utils;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.pcode.PcodeOp;
import java.nio.file.*;
import java.security.MessageDigest;
import java.nio.charset.StandardCharsets;
import java.util.*;
import java.io.*;

public class CompareResourceChain extends CompareResourceSync {
    static final long NODES=0x903000, HEAD=0x46500c, HANDLE=0x465010;
    static final long ACQUIRE=0x2c4350, RELEASE=0x2c54a4, CHECK=0x2c54bc;
    static final long ALLOCATE=0x2c4bd8, CLEAR=0x2c4b84, LENGTH=0x2c32e4;
    static final long COPY=0x2bf8c0, FORMAT=0x2be850, SIGNAL=0x2c4298, SLEEP=0x1382e4;
    static final long[] PENDING={0,1,2,3,6,0x80000000L,0xffffffffL};
    long createEntry, waitEntry;
    int chainCases, pendingCases;
    @Override boolean originalCode(long pc) {
        return super.originalCode(pc) || within(pc,4,0x2b0494,0x2b0630) ||
            within(pc,4,0x1181b0,0x1181ec) || within(pc,4,0x2bb4f0,0x2bb518);
    }
    static boolean prefix(String s) { return s.substring(0,Math.min(8,s.length())).contains(":"); }
    static byte[] z(String s) { return (s+"\0").getBytes(StandardCharsets.US_ASCII); }
    class ChainMachine extends SyncMachine {
        int nodes, polls;
        boolean waiting;
        List<Long> calls=new ArrayList<>();
        ChainMachine(byte[] mapped,byte[] binary) { super(mapped,binary); }
        long nodeAddress() { return NODES; }
        long chainReturn() { return RETURN; }
        long initialChainSize() { return 0xa55a5aa5L; }
        byte[] chainList(Random rng,int count) {
            byte[] list=new byte[count*0x200]; rng.nextBytes(list); return list;
        }
        void chainArguments(boolean hasSize,long flags,long parameter) {
            register("r0",pathAddress()); register("r1",hasSize ? sizeAddress() : 0);
            register("r2",flags); register("r3",parameter);
        }
        // Extension points for the signal/lock integration; the baseline still
        // returns from the modeled signal boundary without executing its code.
        long signalEntry(boolean rebuiltPath) { return SIGNAL; }
        boolean executesSignal() { return false; }
        int signalInstructions(boolean rebuiltPath,long seed,int round,byte[] completion,int priorSteps) throws Exception { return 0; }
        @Override public void beforeStore(PcodeThread<byte[]> t,PcodeOp op,
                AddressSpace space,byte[] offset,int size,byte[] value) {
            long DESC=descriptorAddress(), SIZE=sizeAddress(), NODES=nodeAddress();
            long a=Utils.bytesToLong(offset,offset.length,false);
            if(within(a,size,STACK-0x1000,STACK)) return;
            require(within(a,size,DESC,DESC+0x144) || within(a,size,SIZE,SIZE+4) ||
                within(a,size,HEAD,HEAD+4) || (nodes>0 && within(a,size,
                NODES+(nodes-1)*0x200+0x13c,NODES+(nodes-1)*0x200+0x140)),"Unexpected store "+Long.toHexString(a));
            require(size<=8,"Store width");
            CompareResourceCreate.record(writes,a,size,Utils.bytesToLong(value,size,false));
        }
        @Override public void beforeLoad(PcodeThread<byte[]> t,PcodeOp op,
                AddressSpace space,byte[] offset,int size) {
            long DESC=descriptorAddress(), NODES=nodeAddress();
            long a=Utils.bytesToLong(offset,offset.length,false);
            if(waiting && a==DESC && size==4) polls++;
            if(within(a,size,NODES,NODES+nodes*0x200)) return;
            super.beforeLoad(t,op,space,offset,size);
        }
        void snapshot(byte[] expected,byte[] list,long size,String stage) {
            long DESC=descriptorAddress(), SIZE=sizeAddress(), NODES=nodeAddress();
            require(Arrays.equals(memory(DESC,expected.length),expected),stage+" descriptor");
            require(Arrays.equals(memory(NODES,list.length),list),stage+" list");
            require(word(memory(HEAD,4),0)==(nodes==0 ? DESC : NODES),stage+" head");
            require(word(memory(SIZE,4),0)==size,stage+" size");
        }
        void chain(boolean rebuiltPath,int kind,String path,int mode,int count,long flags,
                boolean hasSize,long terminal,long data,long length,long parameter,int rounds,
                int variant,boolean pending,long acquireResult,long releaseResult,long seed) throws Exception {
            long DESC=descriptorAddress(), SIZE=sizeAddress(), PATH=pathAddress(), NODES=nodeAddress();
            long RETURN=chainReturn(), initialSize=initialChainSize();
            Random rng=new Random(seed); byte[] dirty=new byte[0x144]; rng.nextBytes(dirty);
            initialize(rebuiltPath,kind,dirty); nodes=count; calls.clear(); polls=0; waiting=false;
            byte[] list=chainList(rng,nodes);
            for(int i=0;i<nodes;i++) {
                put(list,i*0x200+0x13c,i+1<nodes ? NODES+(i+1)*0x200 : 0);
                put(list,i*0x200+0x140,i==0 ? 0 : NODES+(i-1)*0x200);
            }
            memory(NODES,list); writeWord(HEAD,nodes==0 ? 0 : NODES);
            long handle=Integer.toUnsignedLong(rng.nextInt()),laterHandle=handle^0x87654321L;
            writeWord(HANDLE,handle); memory(MODE,new byte[]{(byte)mode});
            byte[] input=new byte[256]; Arrays.fill(input,(byte)0xd7);
            System.arraycopy(z(path),0,input,0,path.length()+1); memory(PATH,input);
            chainArguments(hasSize,flags,parameter);
            String formatted=mode!=0 || prefix(path) ? path : "rom:/"+path;
            String stored=prefix(formatted) ? formatted : "rom:/"+formatted;
            require(stored.length()<256,"Fixture path bound");
            byte[] linked=new byte[0x144],expectedList=list.clone();
            if(nodes>0) {
                put(linked,0x140,NODES+(nodes-1)*0x200);
                put(expectedList,(nodes-1)*0x200+0x13c,DESC);
            }
            byte[] created=linked.clone();
            System.arraycopy(z(stored),0,created,0x2c,stored.length()+1);
            put(created,4,1); put(created,40,0x80);
            byte[] configured=created.clone();
            put(configured,36,(flags&1)|((flags&2)<<3)); put(configured,40,kind==1 ? 4 : parameter);
            byte[] expected=configured.clone();
            List<Long> expectedCalls=new ArrayList<>(List.of(0x2c3b98L));
            if(mode==0) expectedCalls.add(0x2b0674L);
            expectedCalls.addAll(List.of(FORMAT,ACQUIRE));
            if((acquireResult>>>31)!=0) expectedCalls.add(CHECK);
            expectedCalls.addAll(List.of(ALLOCATE,CLEAR,LENGTH,prefix(formatted) ? COPY : FORMAT,RELEASE));
            if((releaseResult>>>31)!=0) expectedCalls.add(CHECK);
            for(int i=0;i<rounds;i++) expectedCalls.addAll(List.of(SIGNAL,SLEEP));
            List<String> expectedWrites=new ArrayList<>();
            if(nodes==0) CompareResourceCreate.record(expectedWrites,HEAD,4,DESC);
            else {
                CompareResourceCreate.record(expectedWrites,NODES+(nodes-1)*0x200+0x13c,4,DESC);
                CompareResourceCreate.record(expectedWrites,DESC+0x140,4,NODES+(nodes-1)*0x200);
            }
            for(int offset:new int[]{0,12,16,20,24,0x12c,8}) CompareResourceCreate.record(expectedWrites,DESC+offset,4,0);
            CompareResourceCreate.record(expectedWrites,DESC+0x20,1,0);
            CompareResourceCreate.record(expectedWrites,DESC+40,4,0x80);
            CompareResourceCreate.record(expectedWrites,DESC+4,4,1);
            CompareResourceCreate.record(expectedWrites,DESC+36,4,(flags&1)|((flags&2)<<3));
            CompareResourceCreate.record(expectedWrites,DESC+40,4,kind==1 ? 4 : parameter);
            int steps=0,signals=0,sleeps=0,creates=0,waits=0,cleanups=0;
            long buffer=0,lastResult=0; boolean firstFormat=true;
            executing=true;
            while(thread.getCounter().getOffset()!=RETURN) {
                long pc=thread.getCounter().getOffset();
                if(pc==signalEntry(rebuiltPath)) pc=SIGNAL;
                if(pc==(rebuiltPath ? createEntry : 0x2b0494)) {
                    creates++; require(register("r0")==buffer && register("r1")==0,"Create arguments");
                    require(Arrays.equals(memory(buffer,formatted.length()+1),z(formatted)),"Constructor input");
                }
                if(pc==(rebuiltPath ? waitEntry : 0x1181b0)) {
                    waits++; waiting=true; require(register("r0")==DESC,"Wait argument");
                    snapshot(configured,expectedList,initialSize,"Before wait");
                }
                if(pc==(rebuiltPath ? entries[5] : START[5])) waiting=false;
                if(pc==(rebuiltPath ? entries[2] : START[2])) {
                    cleanups++; require(!pending,"Pending cleanup");
                    byte[] detached=expected.clone(); if(terminal==4) put(detached,12,0);
                    snapshot(detached,expectedList,hasSize ? terminal==5 ? 0 : length : initialSize,"Before cleanup");
                }
                if(List.of(0x2c3b98L,0x2b0674L,FORMAT,ACQUIRE,CHECK,ALLOCATE,CLEAR,LENGTH,COPY,RELEASE,SIGNAL,SLEEP).contains(pc)) {
                    if(pending && pc==SIGNAL && signals==rounds) break;
                    require(calls.size()<expectedCalls.size() && pc==expectedCalls.get(calls.size()),"Dependency order "+Long.toHexString(pc));
                    calls.add(pc); dependencyCalls++;
                    require((register("sp")&7)==0,"Dependency stack alignment"); long result=0;
                    if(pc==0x2c3b98) {
                        buffer=register("r0"); require(register("r1")==256 && within(buffer,256,register("sp"),STACK-16),"Scratch extent");
                        memory(buffer,new byte[256]);
                    } else if(pc==0x2b0674) {
                        require(register("r0")==PATH,"Prefix input"); result=prefix(path) ? 1 : 0;
                    } else if(pc==FORMAT && firstFormat) {
                        firstFormat=false; boolean direct=mode!=0 || prefix(path);
                        require(register("r0")==buffer && register("r1")== (direct ? PATH : 0x409740),"Outer format");
                        if(!direct) require(register("r2")==PATH,"Outer format input");
                        require(Arrays.equals(memory(buffer,256),new byte[256]),"Scratch clearing");
                        memory(buffer,z(formatted)); result=formatted.length();
                    } else if(pc==ACQUIRE) {
                        require(within(register("r0"),4,register("sp"),STACK-16) && within(register("r1"),4,register("sp"),STACK-16),"Acquire pointers");
                        require(word(memory(register("r1"),4),0)==handle && register("r2")==1 && register("r3")==0,"Acquire arguments");
                        require(word(memory(register("sp"),8),0)==0xffffffffL && word(memory(register("sp"),8),4)==0xffffffffL,"Timeout");
                        require(writes.isEmpty() && Arrays.equals(memory(DESC,0x144),dirty),"Early mutation");
                        writeWord(register("r0"),0x13579bdf); writeWord(HANDLE,laterHandle); result=acquireResult; lastResult=result;
                    } else if(pc==CHECK) {
                        require(register("r0")==lastResult && register("r1")==1,"Result handling");
                    } else if(pc==ALLOCATE) {
                        require(register("r0")==0x100 && register("r1")==0x100 && register("r2")==0 && register("r3")==0x144 && word(memory(register("sp"),4),0)==1,"Allocation arguments");
                        require(writes.isEmpty(),"Write before allocation"); result=DESC;
                    } else if(pc==CLEAR) {
                        require(register("r0")==DESC && register("r1")==0x144,"Descriptor clear");
                        require(writes.isEmpty() && Arrays.equals(memory(DESC,0x144),dirty),"Write before clear"); memory(DESC,new byte[0x144]);
                    } else if(pc==LENGTH || pc==COPY || pc==FORMAT) {
                        snapshot(linked,expectedList,initialSize,"Before constructor strings");
                        require(Arrays.equals(memory(buffer,formatted.length()+1),z(formatted)),"Preserve formatted input");
                        if(pc==LENGTH) { require(register("r0")==buffer,"Length argument"); result=formatted.length(); }
                        else {
                            require(register("r0")==DESC+0x2c && register("r1")== (pc==COPY ? buffer : 0x2b066c),"Constructor string arguments");
                            if(pc==FORMAT) require(register("r2")==buffer,"Constructor format input");
                            memory(DESC+0x2c,z(stored)); result=pc==COPY ? DESC+0x2c : stored.length();
                        }
                    } else if(pc==RELEASE) {
                        snapshot(created,expectedList,initialSize,"Before release");
                        require(within(register("r0"),4,register("sp"),STACK-16) && register("r1")==laterHandle,"Release reread");
                        writeWord(register("r0"),0x2468ace0); result=releaseResult; lastResult=result;
                    } else {
                        snapshot(expected,expectedList,initialSize,"Before timing boundary");
                        if(pc==SIGNAL) {
                            require(signals==sleeps && polls==signals+1 && register("r0")==0x465024,"Signal arguments/order"); signals++;
                            put(expected,0,variant==2 ? 5 : variant==0 && signals==rounds && !pending ? terminal : PENDING[signals%7]);
                        } else {
                            require(signals==sleeps+1 && polls==signals && register("r0")==3000000 && register("r1")==0,"Sleep arguments/order"); sleeps++;
                            put(expected,0,sleeps==rounds && !pending ? terminal : PENDING[(sleeps+2)%7]);
                        }
                        if(word(expected,0)==4 || word(expected,0)==5) { put(expected,12,data); put(expected,24,length); }
                        if(pc!=SIGNAL || !executesSignal()) memory(DESC,expected);
                    }
                    if(pc==SIGNAL && executesSignal())
                        steps+=signalInstructions(rebuiltPath,seed,signals,expected,steps);
                    else externalReturn(result);
                    continue;
                }
                step(rebuiltPath,++steps);
            }
            require(calls.equals(expectedCalls) && creates==1 && waits==1 && signals==rounds && sleeps==rounds,"Call counts");
            require(polls==rounds+1,"Wait poll count");
            if(pending) require(cleanups==0 && thread.getCounter().getOffset()!=RETURN,"Pending prefix returned");
            else {
                require(cleanups==1 && register("r0")== (terminal==5 ? 0 : data),"Result/cleanup");
                if(hasSize) CompareResourceCreate.record(expectedWrites,SIZE,4,terminal==5 ? 0 : length);
                if(terminal==4) { put(expected,12,0); CompareResourceCreate.record(expectedWrites,DESC+12,4,0); }
                put(expected,8,1); CompareResourceCreate.record(expectedWrites,DESC+8,4,1); finish(steps);
            }
            snapshot(expected,expectedList,hasSize && !pending ? terminal==5 ? 0 : length : initialSize,"Final");
            require(Arrays.equals(memory(PATH,256),input) && word(memory(HANDLE,4),0)==laterHandle && memory(MODE,1)[0]==(byte)mode,"Input/global preservation");
            Collections.sort(writes); Collections.sort(expectedWrites);
            require(writes.equals(expectedWrites),"External store multiset"); maxSteps=Math.max(maxSteps,steps);
        }
    }
    @Override public void run() throws Exception {
        Path out=Path.of(getScriptArgs()[0]); require(!Files.exists(out.resolve("comparison.json")),"Existing output");
        byte[] mapped=new byte[0x377000];
        require(currentProgram.getMemory().getBytes(toAddr(0x100000),mapped)==mapped.length,"Map");
        require(HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(mapped)).equals(
            "834938d18d2b7c688311c46c27bed813d0d7a9f8e3cbb61da8a6a3f23d360ebd"),"Hash");
        byte[] binary=Files.readAllBytes(out.resolve("resource-chain.bin")); codeSize=binary.length;
        require(codeSize>0 && codeSize<=0x1000,"Binary extent");
        List<String> lines=Files.readAllLines(out.resolve("entries.txt")); require(lines.size()==9,"Entries");
        for(int i=0;i<9;i++) require(within(Long.parseLong(lines.get(i)),4,BUILD,BUILD+codeSize),"Entry extent");
        for(int i=0;i<6;i++) entries[i]=Long.parseLong(lines.get(i));
        createEntry=Long.parseLong(lines.get(6)); waitEntry=Long.parseLong(lines.get(7));
        ChainMachine a=new ChainMachine(mapped,binary),b=new ChainMachine(mapped,binary);
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
        for(int i=0;i<START.length;i++) for(long pc=START[i];pc<STOP[i];pc+=4)
            require(visited.contains(pc),"Unvisited synchronous instruction "+Long.toHexString(pc));
        for(long[] range:new long[][]{{0x2b0494,0x2b0630},{0x1181b0,0x1181ec},{0x2bb4f0,0x2bb504}})
            for(long pc=range[0];pc<range[1];pc+=4) require(visited.contains(pc),"Unvisited chain instruction "+Long.toHexString(pc));
        Files.writeString(out.resolve("visited.txt"),String.join("\n",visited.stream().map(v->String.format("%08x",v)).toList())+"\n");
        Files.writeString(out.resolve("comparison.json"),String.format(Locale.ROOT,
            "{\"chain_cases\":%d,\"pending_prefix_cases\":%d,\"original_instruction_addresses\":%d,\"max_steps\":%d,\"dependency_calls_both_paths\":%d,\"create_wait_delay_intercepted\":false,\"allocation_sync_strings_timing_intercepted\":true,\"live_verified\":false}\n",
            chainCases,pendingCases,visited.size(),maxSteps,dependencyCalls));
        println("SMT4_CHAIN_COMPARE_OK");
    }
}
