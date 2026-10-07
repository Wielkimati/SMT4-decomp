// Registry callers execute the synchronous chain on the same thread and memory.
// Allocation, worker completion, strings, OS calls and SVC remain explicit models.
// @category SMT4
import ghidra.pcode.emu.PcodeThread;
import ghidra.pcode.utils.Utils;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.pcode.PcodeOp;
import java.nio.file.*;
import java.security.MessageDigest;
import java.util.*;
import java.io.*;

public class CompareResourceRegistryChain extends CompareResourceChainSignal {
    static final long BULK=0x33c8a0, INDEX=0x29706c, STATE=0x4651c0;
    static final long POOL=0x910000, PATHS=0x920000;
    long bulkEntry, dynamicEntry, indexEntry, remainderEntry, nestedLoads;
    int individualCases, bulkCases, registryPendingCases, indexCalls;
    @Override boolean originalCode(long pc) {
        return super.originalCode(pc) || within(pc,4,ORIGINAL[0],END[0]) ||
            within(pc,4,BULK,0x33c958) || within(pc,4,INDEX,0x2970bc) ||
            within(pc,4,0x2c61b0,0x2c62f0);
    }
    static long advance(long state) { return (state*0x41c64e6dL+0x3039)&MASK; }
    static String path(int id) {
        return switch(id%6) {
            case 0 -> "";
            case 1 -> "rom:/table/"+id+".tbb";
            case 2 -> "1234567:x";
            case 3 -> "12345678:x";
            case 4 -> "x".repeat(250);
            default -> "table/"+id+".tbb";
        };
    }
    int[] order(byte[] initial,boolean bulk,long id,long seed) {
        if(!bulk) return id<67 && word(initial,(int)id*16+4)==0 && initial[(int)id*16+12]==0 ? new int[]{(int)id} : new int[0];
        List<Integer> permutation=new ArrayList<>();
        for(int i=0;i<67;i++) permutation.add(i);
        for(int i=0;i<33;i++) { seed=advance(seed); Collections.swap(permutation,i,i+1+(int)((seed>>>16)%(66-i))); }
        return permutation.stream().filter(i->word(initial,i*16+4)==0 && initial[i*16+12]!=0).mapToInt(i->i).toArray();
    }
    class RegistryMachine extends SignalChainMachine {
        boolean nested;
        int ordinal, selected, stateStores;
        long returnPC, entrySP, staleSize;
        long[] saved=new long[8];
        byte[] callerStack;
        List<String> registryWrites=new ArrayList<>(), effects=new ArrayList<>();
        RegistryMachine(byte[] mapped,byte[] binary) { super(mapped,binary); }
        @Override long descriptorAddress() { return POOL+ordinal*0x200L; }
        @Override long nodeAddress() { return POOL; }
        @Override long sizeAddress() { return REG+selected*16L+8; }
        @Override long pathAddress() { return PATHS+selected*256L; }
        @Override long chainReturn() { return returnPC; }
        @Override long initialChainSize() { return staleSize; }
        @Override byte[] chainList(Random rng,int count) {
            byte[] list=memory(POOL,count*0x200);
            if(count>0) require(word(memory(HEAD,4),0)==POOL,"Retained list head");
            for(int i=0;i<count;i++) {
                require(word(list,i*0x200+0x13c)==(i+1<count ? POOL+(i+1)*0x200L : 0),"Retained next link");
                require(word(list,i*0x200+0x140)==(i==0 ? 0 : POOL+(i-1)*0x200L),"Retained backlink");
            }
            return list;
        }
        @Override void initialize(boolean rebuiltPath,int kind,byte[] initial) {
            if(!nested) { super.initialize(rebuiltPath,kind,initial); return; }
            // Supply fresh allocation bytes; preserve the caller's CPU, stack,
            // registry and all descriptors retained from previous loads.
            writes.clear(); memory(descriptorAddress(),initial);
        }
        @Override void chainArguments(boolean hasSize,long flags,long parameter) {
            require(hasSize && register("r0")==pathAddress() && register("r1")==sizeAddress() &&
                register("r2")==flags && flags==0,"Nested load arguments");
            // r3 is unspecified at the three-argument wrapper entry. Its own
            // instruction must supply parameter 4 to the synchronous routine.
        }
        @Override void finish(int steps) {
            if(!nested) { super.finish(steps); return; }
            require(register("sp")==entrySP,"Nested SP restoration");
            for(int r=4;r<=11;r++) require(register("r"+r)==saved[r-4],"Nested callee-saved register");
            require(Arrays.equals(memory(entrySP,callerStack.length),callerStack),"Nested caller stack preservation");
            maxSteps=Math.max(maxSteps,steps);
        }
        @Override public void beforeLoad(PcodeThread<byte[]> t,PcodeOp op,AddressSpace space,byte[] offset,int size) {
            long a=Utils.bytesToLong(offset,offset.length,false);
            if(!inSignal && within(a,size,REG,REG+67*16)) return;
            if(!nested) {
                require(within(a,size,0x100000,0x477000) || within(a,size,BUILD,BUILD+codeSize) ||
                    within(a,size,STACK-0x1000,STACK),"Unexpected registry read "+Long.toHexString(a));
                return;
            }
            super.beforeLoad(t,op,space,offset,size);
        }
        @Override public void beforeStore(PcodeThread<byte[]> t,PcodeOp op,AddressSpace space,
                byte[] offset,int size,byte[] value) {
            long a=Utils.bytesToLong(offset,offset.length,false);
            if(within(a,size,REG,REG+67*16)) {
                require(within(a,size,REG+selected*16L+(nested ? 8 : 4),REG+selected*16L+(nested ? 12 : 8)),
                    "Registry store field/order");
                CompareResourceCreate.record(registryWrites,a,size,Utils.bytesToLong(value,size,false));
                if(!nested) return;
            }
            if(!nested) {
                if(a==STATE && size==4) { stateStores++; return; }
                require(within(a,size,STACK-0x1000,STACK),"Unexpected outer store"); return;
            }
            super.beforeStore(t,op,space,offset,size,value);
        }
        void compare(boolean rebuiltPath,boolean bulk,long id,byte[] initial,long seed,int outcome,int pendingAt,int pendingKind) throws Exception {
            nested=false; ordinal=0; selected=0; stateStores=0;
            initialize(rebuiltPath,0,new byte[0x144]);
            byte[] guards=new byte[67*16+32]; Arrays.fill(guards,(byte)0xc9);
            System.arraycopy(initial,0,guards,16,initial.length); memory(REG-16,guards);
            memory(POOL,new byte[68*0x200]);
            for(int i=0;i<67;i++) {
                byte[] input=new byte[256]; Arrays.fill(input,(byte)0xd7);
                System.arraycopy(z(path(i)),0,input,0,path(i).length()+1); memory(PATHS+i*256L,input);
            }
            byte[] allPaths=memory(PATHS,67*256);
            writeWord(STATE,seed); register("r0",id);
            thread.overrideCounter(toAddr(rebuiltPath ? bulk ? bulkEntry : dynamicEntry : bulk ? BULK : ORIGINAL[0]));
            byte[] expected=initial.clone(); int[] loads=order(initial,bulk,id,seed);
            List<String> expectedRegistryWrites=new ArrayList<>(); registryWrites.clear(); effects.clear();
            int steps=0,indices=0,remainders=0; long state=seed;
            executing=true;
            while(thread.getCounter().getOffset()!=RETURN) {
                long pc=thread.getCounter().getOffset();
                if(pc==(rebuiltPath ? indexEntry : INDEX)) {
                    require(bulk && ordinal==0 && indices<33 && register("r0")==indices+1 && register("r1")==66,"Index arguments/order");
                    require(stateStores==indices && word(memory(STATE,4),0)==state,"Index state before call");
                    state=advance(state); indices++; indexCalls++;
                }
                if(pc==(rebuiltPath ? remainderEntry : 0x2c61b0)) {
                    require(bulk && ++remainders==indices && register("r0")==state>>>16 && register("r1")==67-indices,"Remainder arguments");
                    require(stateStores==indices && word(memory(STATE,4),0)==state,"Remainder state");
                }
                if(pc==(rebuiltPath ? entries[1] : START[1])) {
                    require(ordinal<loads.length,"Extra nested load"); selected=loads[ordinal];
                    require(Arrays.equals(memory(REG,initial.length),expected),"Registry before nested load");
                    require(indices==(bulk ? 33 : 0) && remainders==indices,"Permutation before loads");
                    entrySP=register("sp"); returnPC=register("lr");
                    require((entrySP&7)==0,"Nested stack alignment");
                    for(int r=4;r<=11;r++) saved[r-4]=register("r"+r);
                    callerStack=memory(entrySP,(int)(STACK-entrySP)); staleSize=word(expected,selected*16+8);
                    long terminal=outcome==1 ? 5 : 4;
                    long data=outcome==2 ? 0 : 0x81230000L+selected*0x100L;
                    long length=new long[]{0,MASK,0x80000000L,0x12345678L}[selected%4];
                    nested=true;
                    boolean pending=ordinal==pendingAt;
                    if(pending && pendingKind==1)
                        forcedPlan=schedule(0,MASK-1,new long[]{0},new boolean[]{true},new long[]{-1},new boolean[]{false},0,1,3,2,MASK);
                    try {
                        chain(rebuiltPath,1,path(selected),new int[]{0,1,255}[selected%3],ordinal,0,true,
                            terminal,data,length,4,1+selected%3,selected%3,pending && pendingKind==0,
                            selected%2==0 ? MASK : 0,selected%3==0 ? 0x80000000L : 0,
                            0x2c5e9000L+selected+ordinal*67L);
                        require(pendingKind!=1 || !pending,"Expected pending signal");
                    } catch(PendingSignal stop) { require(pending && pendingKind==1,"Unexpected pending signal"); }
                    finally { forcedPlan=null; }
                    effects.addAll(writes); effects.add(calls.toString()); nestedLoads++;
                    nested=false;
                    if(pending) {
                        require(thread.getCounter().getOffset()!=returnPC && thread.getCounter().getOffset()!=RETURN,"Pending registry returned");
                        require(Arrays.equals(memory(REG,initial.length),expected),"Pending registry publication");
                        break;
                    }
                    require(thread.getCounter().getOffset()==returnPC,"Nested return target");
                    put(expected,selected*16+8,terminal==5 ? 0 : length);
                    CompareResourceCreate.record(expectedRegistryWrites,REG+selected*16L+8,4,terminal==5 ? 0 : length);
                    require(Arrays.equals(memory(REG,initial.length),expected),"Size before registry publication");
                    require(register("r0")== (terminal==5 ? 0 : data),"Nested result");
                    put(expected,selected*16+4,terminal==5 ? 0 : data);
                    CompareResourceCreate.record(expectedRegistryWrites,REG+selected*16L+4,4,terminal==5 ? 0 : data);
                    ordinal++; continue;
                }
                require(rebuiltPath ? within(pc,4,BUILD,BUILD+codeSize) :
                    within(pc,4,ORIGINAL[0],END[0]) || within(pc,4,BULK,0x33c958) ||
                    within(pc,4,INDEX,0x2970bc) || within(pc,4,0x2c61b0,0x2c62f0),"Unexpected outer PC");
                if(!rebuiltPath) visited.add(pc);
                require(++steps<=20000,"Registry instruction budget"); monitor.checkCancelled(); thread.stepInstruction();
            }
            require(indices==(bulk ? 33 : 0) && remainders==indices && stateStores==indices,"Index counts");
            require(word(memory(STATE,4),0)==state,"Final PRNG state");
            if(pendingAt<0) {
                require(ordinal==loads.length,"Missing loads");
                long result=bulk ? 1 : id>=67 ? 0 : word(initial,(int)id*16+4)!=0 || initial[(int)id*16+12]==0 ? 1 : 0;
                require(register("r0")==result,"Registry result"); super.finish(steps);
            } else require(ordinal==pendingAt,"Pending load position");
            require(registryWrites.equals(expectedRegistryWrites),"Registry store sequence");
            System.arraycopy(expected,0,guards,16,expected.length);
            require(Arrays.equals(memory(REG-16,guards.length),guards),"Registry/guard preservation");
            require(Arrays.equals(memory(PATHS,allPaths.length),allPaths),"All input paths preserved");
            maxSteps=Math.max(maxSteps,steps);
        }
    }
    byte[] fixture(Random rng,int profile) {
        byte[] b=new byte[67*16]; rng.nextBytes(b);
        for(int i=0;i<67;i++) {
            put(b,i*16,PATHS+i*256L);
            put(b,i*16+4,profile==1 || (profile==5 && i%3==0) ? 0x89000000L+i*16 : 0);
            b[i*16+12]=(byte)(profile==2 ? 0 : profile==3 ? 128 : profile==4 ? 255 : profile==5 && i%2==0 ? 0 : 1);
        }
        return b;
    }
    void pair(RegistryMachine a,RegistryMachine b,boolean bulk,long id,byte[] initial,long seed,int outcome,int pendingAt,int pendingKind) throws Exception {
        a.compare(false,bulk,id,initial,seed,outcome,pendingAt,pendingKind);
        b.compare(true,bulk,id,initial,seed,outcome,pendingAt,pendingKind);
        require(a.registryWrites.equals(b.registryWrites) && a.effects.equals(b.effects),"Original/rebuilt trace");
        require(Arrays.equals(a.memory(POOL,68*0x200),b.memory(POOL,68*0x200)),"Original/rebuilt descriptor pool");
        if(bulk) bulkCases++; else individualCases++;
        if(pendingAt>=0) registryPendingCases++;
    }
    @Override public void run() throws Exception {
        Path out=Path.of(getScriptArgs()[0]); require(!Files.exists(out.resolve("comparison.json")),"Existing output");
        recoverArbitration=true;
        byte[] mapped=new byte[0x377000];
        require(currentProgram.getMemory().getBytes(toAddr(0x100000),mapped)==mapped.length,"Map");
        require(HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(mapped)).equals(
            "834938d18d2b7c688311c46c27bed813d0d7a9f8e3cbb61da8a6a3f23d360ebd"),"Hash");
        byte[] binary=Files.readAllBytes(out.resolve("resource-registry-chain.bin")); codeSize=binary.length;
        require(codeSize>0 && codeSize<=0x2000,"Binary extent");
        List<String> lines=Files.readAllLines(out.resolve("entries.txt")); require(lines.size()==17,"Entries");
        for(String line:lines) require(within(Long.parseLong(line),4,BUILD,BUILD+codeSize),"Entry extent");
        for(int i=0;i<6;i++) entries[i]=Long.parseLong(lines.get(i));
        createEntry=Long.parseLong(lines.get(6)); waitEntry=Long.parseLong(lines.get(7));
        signalEntry=Long.parseLong(lines.get(9)); arbitrationEntry=Long.parseLong(lines.get(12));
        dynamicEntry=Long.parseLong(lines.get(13)); bulkEntry=Long.parseLong(lines.get(14));
        indexEntry=Long.parseLong(lines.get(15)); remainderEntry=Long.parseLong(lines.get(16));
        RegistryMachine a=new RegistryMachine(mapped,binary),b=new RegistryMachine(mapped,binary);
        Random rng=new Random(0x49382c); List<Long> ids=new ArrayList<>();
        for(long i=0;i<67;i++) ids.add(i);
        ids.addAll(List.of(67L,68L,0x7fffffffL,0x80000000L,MASK));
        try(PrintWriter log=new PrintWriter(Files.newBufferedWriter(out.resolve("results.tsv")))) {
            log.println("kind\tid_or_seed\tprofile\toutcome\tpending_at\tpending_kind");
            for(long id:ids) for(int loaded=0;loaded<2;loaded++) for(int policy:new int[]{0,1,128,255}) for(int outcome=0;outcome<3;outcome++) {
                byte[] initial=fixture(rng,5);
                if(id<67) { put(initial,(int)id*16+4,loaded==0 ? 0 : 0x81234560L); initial[(int)id*16+12]=(byte)policy; }
                pair(a,b,false,id,initial,MASK,outcome,-1,0);
                log.printf("individual\t%d\t%d:%d\t%d\t-1\t0%n",id,loaded,policy,outcome);
            }
            println("Individual registry cases passed: "+individualCases);
            for(long seed:new long[]{0,1,0x7fffffffL,0x80000000L,MASK-1,MASK,0x12345678L,0xdeadbeefL})
            for(int profile=0;profile<6;profile++) for(int outcome=0;outcome<3;outcome++) {
                pair(a,b,true,0,fixture(rng,profile),seed,outcome,-1,0);
                log.printf("bulk\t%d\t%d\t%d\t-1\t0%n",seed,profile,outcome);
            }
            for(int kind=0;kind<2;kind++) for(int pendingKind=0;pendingKind<2;pendingKind++)
            for(int position:kind==0 ? new int[]{0} : new int[]{0,1,33,66}) for(int outcome=0;outcome<3;outcome++) {
                byte[] initial=fixture(rng,kind==0 ? 2 : 0);
                pair(a,b,kind==1,1,initial,0xdeadbeefL,outcome,position,pendingKind);
                log.printf("pending-%d\t1\t0\t%d\t%d\t%d%n",kind,outcome,position,pendingKind);
            }
        }
        for(long[] range:new long[][]{{ORIGINAL[0],END[0]},{BULK,0x33c958},{ARBITRATE,ARBITRATE+24}})
            for(long pc=range[0];pc<range[1];pc+=4) require(visited.contains(pc),"Unvisited registry/wrapper instruction "+Long.toHexString(pc));
        Files.writeString(out.resolve("visited.txt"),String.join("\n",visited.stream().map(v->String.format("%08x",v)).toList())+"\n");
        Files.writeString(out.resolve("comparison.json"),String.format(Locale.ROOT,
            "{\"individual_cases\":%d,\"bulk_cases\":%d,\"pending_prefix_cases\":%d,\"nested_loads_both_paths\":%d,\"original_instruction_addresses\":%d,\"max_segment_steps\":%d,\"index_calls_both_paths\":%d,\"signal_calls_both_paths\":%d,\"svc_calls_both_paths\":%d,\"wrapper_returns_both_paths\":%d,\"registry_load_intercepted\":false,\"index_intercepted\":false,\"svc_intercepted\":true,\"allocation_worker_os_strings_timing_modeled\":true,\"live_verified\":false}\n",
            individualCases,bulkCases,registryPendingCases,nestedLoads,visited.size(),maxSteps,indexCalls,signalCalls,boundaryCalls,wrapperReturns));
        println("SMT4_REGISTRY_CHAIN_COMPARE_OK");
    }
}
