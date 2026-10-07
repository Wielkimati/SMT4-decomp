// Release wrapper only; recursive synchronization, metadata cleanup and free modeled.
// @category SMT4
import ghidra.pcode.emu.PcodeThread;
import ghidra.pcode.utils.Utils;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.pcode.PcodeOp;
import java.nio.file.*;
import java.security.MessageDigest;
import java.util.*;
import java.io.*;

public class CompareResourceRelease extends CompareResourceSync {
    static final long ENTRY=0x2c43b4, END=0x2c4424, STATE=0x465120, MASK=0xffffffffL;
    static final long ACQUIRE=0x2c3afc, RELEASE=0x2c3a78, CONVERT=0x1245f0, FREE=0x1244e8;
    int cases, directCases, convertedCases;
    @Override boolean originalCode(long pc) { return within(pc,4,ENTRY,END); }
    static boolean direct(long address,long[] ranges) {
        // Test mathematical non-wrapping intervals. A wrapped endpoint lies below
        // its base and the original conjunction then accepts no addresses.
        for(int i=0;i<4;i+=2) {
            long end=ranges[i]+ranges[i+1];
            if(end<=MASK && ranges[i]<=address && address<=end) return true;
        }
        return false;
    }
    class ReleaseMachine extends SyncMachine {
        List<String> trace=new ArrayList<>();
        ReleaseMachine(byte[] mapped,byte[] binary) { super(mapped,binary); }
        @Override public void beforeStore(PcodeThread<byte[]> t,PcodeOp op,AddressSpace space,
                byte[] offset,int size,byte[] value) {
            long a=Utils.bytesToLong(offset,offset.length,false);
            require(within(a,size,STACK-64,STACK),"Unexpected release store "+Long.toHexString(a));
        }
        void call(boolean rebuiltPath,long address,long[] ranges,long converted,int effect,long seed) throws Exception {
            byte[] initial=new byte[0x144]; initialize(rebuiltPath,0,initial);
            Random rng=new Random(seed); byte[] state=new byte[0x60]; rng.nextBytes(state);
            long lockBefore=word(state,20), lockAfter=(lockBefore^0x88888888L)&MASK;
            long[] before=ranges.clone();
            if(effect==1) { before[0]=address; before[1]=0; before[2]=address; before[3]=0; }
            if(effect==2) { before[0]=(address+1)&MASK; before[1]=0; before[2]=(address+1)&MASK; before[3]=0; }
            int[] offsets={0x24,0x34,0x28,0x38};
            for(int i=0;i<4;i++) put(state,16+offsets[i],before[i]);
            memory(STATE-16,state); byte[] stack=memory(STACK-0x1000,0x1000);
            register("r0",address); register("s16",0x81234567L); register("s17",0xfedcba98L);
            thread.overrideCounter(toAddr(rebuiltPath ? entries[0] : ENTRY));
            boolean isDirect=direct(address,ranges);
            List<Long> expected=new ArrayList<>(List.of(ACQUIRE));
            if(!isDirect) expected.add(CONVERT);
            expected.add(FREE); expected.add(RELEASE);
            int calls=0,steps=0; trace.clear(); executing=true;
            while(thread.getCounter().getOffset()!=RETURN) {
                long pc=thread.getCounter().getOffset();
                if(pc==ACQUIRE || pc==CONVERT || pc==FREE || pc==RELEASE) {
                    require(calls<expected.size() && expected.get(calls++)==pc,"Release dependency order");
                    require((register("sp")&7)==0,"Dependency stack alignment");
                    long arg=pc==ACQUIRE ? lockBefore : pc==RELEASE ? lockAfter :
                        pc==CONVERT || isDirect ? address : converted;
                    require(register("r0")==arg,"Release dependency argument at "+Long.toHexString(pc));
                    require(Arrays.equals(state,memory(STATE-16,state.length)),"State before dependency");
                    trace.add(Long.toHexString(pc)+":"+Long.toHexString(arg)); dependencyCalls++;
                    if(pc==ACQUIRE) {
                        for(int i=0;i<4;i++) put(state,16+offsets[i],ranges[i]);
                        memory(STATE-16,state);
                    }
                    if(pc==FREE) { put(state,20,lockAfter); memory(STATE-16,state); }
                    externalReturn(pc==CONVERT ? converted : Integer.toUnsignedLong(rng.nextInt()));
                    continue;
                }
                step(rebuiltPath,++steps);
            }
            require(calls==expected.size(),"Missing release dependency");
            require(Arrays.equals(state,memory(STATE-16,state.length)),"Final state/guards");
            byte[] actual=memory(STACK-0x1000,0x1000);
            for(int i=0;i<stack.length-64;i++) require(stack[i]==actual[i],"Stack guard");
            require(register("s16")==0x81234567L && register("s17")==0xfedcba98L,"d8 preservation");
            finish(steps);
        }
    }
    void compare(ReleaseMachine a,ReleaseMachine b,PrintWriter log,long address,long[] ranges,long converted,int effect) throws Exception {
        try {
            a.call(false,address,ranges,converted,effect,ENTRY+cases);
            b.call(true,address,ranges,converted,effect,ENTRY+cases);
            require(a.trace.equals(b.trace),"Call trace difference");
        } catch(Exception ex) {
            throw new IllegalStateException("Case "+cases+" address="+address+" ranges="+Arrays.toString(ranges)+" effect="+effect,ex);
        }
        if(direct(address,ranges)) directCases++; else convertedCases++;
        log.printf("%d\t%d\t%s\t%d\t%d%n",++cases,address,Arrays.toString(ranges),converted,effect);
    }
    @Override public void run() throws Exception {
        Path out=Path.of(getScriptArgs()[0]); require(!Files.exists(out.resolve("comparison.json")),"Existing output");
        byte[] mapped=new byte[0x377000];
        require(currentProgram.getMemory().getBytes(toAddr(0x100000),mapped)==mapped.length,"Map");
        require(HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(mapped)).equals(
            "834938d18d2b7c688311c46c27bed813d0d7a9f8e3cbb61da8a6a3f23d360ebd"),"Hash");
        byte[] binary=Files.readAllBytes(out.resolve("resource-release.bin")); codeSize=binary.length;
        require(codeSize>0 && codeSize<=0x1000,"Binary size");
        List<String> lines=Files.readAllLines(out.resolve("entries.txt")); require(lines.size()==1,"Entries");
        entries[0]=Long.parseLong(lines.get(0)); require(within(entries[0],4,BUILD,BUILD+codeSize),"Entry extent");
        ReleaseMachine a=new ReleaseMachine(mapped,binary),b=new ReleaseMachine(mapped,binary);
        long[][] profiles={{0,0},{0,MASK},{1,0},{1,MASK},{0x1000,0x100},{0x1080,0x100},
            {0x80000000L,0x7fffffffL},{0x80000000L,0x80000000L},{MASK,0},{MASK,1}};
        long[] results={0,1,0x80000000L,MASK};
        try(PrintWriter log=new PrintWriter(Files.newBufferedWriter(out.resolve("results.tsv")))) {
            log.println("case\taddress\tranges\tconverted\tacquire_effect");
            for(long[] first:profiles) for(long[] second:profiles) {
                long[] ranges={first[0],first[1],second[0],second[1]};
                Set<Long> addresses=new TreeSet<>(List.of(0L,1L,0x7fffffffL,0x80000000L,MASK));
                for(long[] range:new long[][]{first,second}) for(long bound:new long[]{range[0],(range[0]+range[1])&MASK})
                    for(int delta=-1;delta<=1;delta++) addresses.add((bound+delta)&MASK);
                for(long address:addresses) for(int effect=0;effect<3;effect++)
                    compare(a,b,log,address,ranges,results[cases%results.length],effect);
            }
            Random rng=new Random(ENTRY);
            for(int i=0;i<1024;i++) {
                long[] ranges=new long[4]; for(int j=0;j<4;j++) ranges[j]=Integer.toUnsignedLong(rng.nextInt());
                compare(a,b,log,Integer.toUnsignedLong(rng.nextInt()),ranges,Integer.toUnsignedLong(rng.nextInt()),i%3);
            }
        }
        StringBuilder listing=new StringBuilder();
        for(long pc=ENTRY;pc<END;pc+=4) {
            require(visited.contains(pc),"Unvisited original instruction "+Long.toHexString(pc));
            var instruction=currentProgram.getListing().getInstructionAt(toAddr(pc));
            require(instruction!=null,"Missing Ghidra disassembly");
            listing.append(String.format("%08x %s%n",pc,instruction));
        }
        Files.writeString(out.resolve("original-ghidra.txt"),listing);
        Files.writeString(out.resolve("comparison.json"),String.format(Locale.ROOT,
            "{\"release_cases\":%d,\"direct_cases\":%d,\"converted_cases\":%d,\"original_instruction_addresses\":%d,\"max_steps\":%d,\"dependency_calls_both_paths\":%d,\"lower_dependencies_modeled\":true,\"live_verified\":false}\n",
            cases,directCases,convertedCases,visited.size(),maxSteps,dependencyCalls));
        println("SMT4_RELEASE_COMPARE_OK");
    }
}
