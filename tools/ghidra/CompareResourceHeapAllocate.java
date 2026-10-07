// Six-word wrapper only; all four subobject dependencies are modeled.
// @category SMT4
import ghidra.pcode.emu.PcodeThread;
import ghidra.pcode.utils.Utils;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.pcode.PcodeOp;
import java.nio.file.*;
import java.security.MessageDigest;
import java.util.*;
import java.io.*;

public class CompareResourceHeapAllocate extends CompareResourceSync {
    static final long ENTRY=0x2c3a98, END=0x2c3afc, MASK=0xffffffffL;
    static final long[] CALLS={0x146ce0,0x146cf0,0x146d10,0x146ad8};
    int cases, nullCases, overflowCases, effectCases, zeroSizeCases, wrapAddressCases, textSize;
    @Override boolean originalCode(long pc) { return within(pc,4,ENTRY,END); }
    class HeapMachine extends SyncMachine {
        final List<String> trace=new ArrayList<>();
        long counter;
        int calls, reads, stores;
        HeapMachine(byte[] mapped,byte[] binary) { super(mapped,binary); }
        @Override void step(boolean rebuiltPath,int steps) throws Exception {
            if(rebuiltPath) require(within(thread.getCounter().getOffset(),4,BUILD,BUILD+textSize),"PC outside rebuilt text");
            super.step(rebuiltPath,steps);
        }
        @Override public void beforeStore(PcodeThread<byte[]> t,PcodeOp op,AddressSpace space,
                byte[] offset,int n,byte[] value) {
            long a=Utils.bytesToLong(offset,offset.length,false);
            if(within(a,n,STACK-64,STACK)) return;
            require(a==counter && n==4 && calls==4,"Unexpected heap store "+Long.toHexString(a));
            stores++;
            trace.add("store:"+Long.toHexString(Utils.bytesToLong(value,n,false)));
        }
        @Override public void beforeLoad(PcodeThread<byte[]> t,PcodeOp op,AddressSpace space,byte[] offset,int n) {
            long a=Utils.bytesToLong(offset,offset.length,false);
            if(a==counter && n==4) {
                require(calls==4,"Counter read before allocation returned"); reads++; return;
            }
            require(within(a,n,STACK-64,STACK+8) || within(a,n,BUILD,BUILD+codeSize),
                "Unexpected heap read "+Long.toHexString(a));
        }
        byte[] call(boolean rebuiltPath,long heap,long size,long alignment,long fourth,long fifth,long sixth,
                    long initialCount,long result,int effect) throws Exception {
            initialize(rebuiltPath,0,new byte[0x144]);
            trace.clear(); calls=0; reads=0; stores=0; counter=(heap+84)&MASK;
            Random rng=new Random(ENTRY+cases);
            byte[] region=new byte[36]; rng.nextBytes(region); put(region,16,initialCount);
            memory(counter-16,region);
            byte[] caller=new byte[32]; rng.nextBytes(caller); put(caller,0,fifth); put(caller,4,sixth); memory(STACK,caller);
            register("r0",heap); register("r1",size); register("r2",alignment); register("r3",fourth);
            for(int r=16;r<32;r++) register("s"+r,0x81234000L+r);
            thread.overrideCounter(toAddr(rebuiltPath ? entries[0] : ENTRY)); executing=true;
            long[] values={fourth,fifth,sixth,size};
            int steps=0;
            while(thread.getCounter().getOffset()!=RETURN) {
                long pc=thread.getCounter().getOffset();
                boolean dependency=false; for(long address:CALLS) if(pc==address) dependency=true;
                if(dependency) {
                    require(calls<4 && pc==CALLS[calls],"Heap dependency order");
                    require((register("sp")&7)==0,"Dependency stack alignment");
                    require(register("r0")==((heap+24)&MASK) && register("r1")==values[calls],"Heap dependency arguments");
                    if(calls==3) require(register("r2")==alignment,"Allocation alignment");
                    require(Arrays.equals(region,memory(counter-16,region.length)),"Heap counter/guards before dependency");
                    require(reads==0 && stores==0,"Premature counter access");
                    trace.add(Long.toHexString(pc)+":"+Long.toHexString(register("r0"))+":"+
                        Long.toHexString(register("r1"))+(calls==3 ? ":"+Long.toHexString(register("r2")) : ""));
                    // Deliberate effects test post-call loads, not the actual lower algorithm.
                    if(effect!=0) {
                        long count=calls==3 ? (effect==2 ? MASK : (initialCount^0xa5a55a5aL)) :
                            (initialCount+0x1234567L*(calls+1))&MASK;
                        put(region,16,count); memory(counter-16,region);
                    }
                    for(int r=0;r<16;r++) register("s"+r,0xdead0000L+r);
                    externalReturn(calls==3 ? result : Integer.toUnsignedLong(rng.nextInt()));
                    calls++; dependencyCalls++; continue;
                }
                step(rebuiltPath,++steps);
            }
            require(calls==4,"Missing heap dependency");
            require(register("r0")==result,"Allocation return preservation");
            require(reads==(result==0 ? 0 : 1) && stores==(result==0 ? 0 : 1),"Conditional counter accesses");
            if(result!=0) put(region,16,(word(region,16)+1)&MASK);
            require(Arrays.equals(region,memory(counter-16,region.length)),"Final counter/guards");
            require(Arrays.equals(caller,memory(STACK,caller.length)),"Caller stack");
            byte[] stack=memory(STACK-0x1000,0x1000);
            for(int i=0;i<stack.length-64;i++) require(stack[i]==(byte)0x96,"Stack guard");
            for(int r=16;r<32;r++) require(register("s"+r)==0x81234000L+r,"Callee-saved VFP register");
            finish(steps); return region;
        }
    }
    void compare(HeapMachine a,HeapMachine b,PrintWriter log,long heap,long size,long alignment,
                 long fourth,long fifth,long sixth,long count,long result,int effect) throws Exception {
        try {
            byte[] x=a.call(false,heap,size,alignment,fourth,fifth,sixth,count,result,effect);
            byte[] y=b.call(true,heap,size,alignment,fourth,fifth,sixth,count,result,effect);
            require(Arrays.equals(x,y) && a.trace.equals(b.trace),"Heap original/rebuilt state/trace");
        } catch(Exception ex) { throw new IllegalStateException("Heap wrapper case "+cases+" args="+
            Arrays.toString(new long[]{heap,size,alignment,fourth,fifth,sixth,count,result,effect}),ex); }
        if(result==0) nullCases++;
        if(result!=0 && (effect==2 || (effect==0 && count==MASK) || (effect==1 && (count^0xa5a55a5aL)==MASK))) overflowCases++;
        if(effect!=0) effectCases++;
        if(size==0) zeroSizeCases++;
        if(heap+84>MASK) wrapAddressCases++;
        log.printf("%d\t%x\t%x\t%x\t%x\t%x\t%x\t%x\t%x\t%d%n",++cases,heap,size,alignment,fourth,fifth,sixth,count,result,effect);
    }
    @Override public void run() throws Exception {
        Path out=Path.of(getScriptArgs()[0]); require(!Files.exists(out.resolve("comparison.json")),"Existing output");
        byte[] mapped=new byte[0x377000]; require(currentProgram.getMemory().getBytes(toAddr(0x100000),mapped)==mapped.length,"Map");
        require(HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(mapped)).equals(
            "834938d18d2b7c688311c46c27bed813d0d7a9f8e3cbb61da8a6a3f23d360ebd"),"Hash");
        byte[] binary=Files.readAllBytes(out.resolve("resource-heap-allocate.bin")); codeSize=binary.length;
        require(codeSize>0 && codeSize<=0x1000,"Binary size");
        textSize=Integer.parseInt(Files.readString(out.resolve("text-size.txt")).trim());
        require(textSize>0 && textSize<=codeSize,"Text extent");
        List<String> lines=Files.readAllLines(out.resolve("entries.txt")); require(lines.size()==1,"Entries");
        entries[0]=Long.parseLong(lines.get(0)); require(within(entries[0],4,BUILD,BUILD+codeSize),"Entry");
        HeapMachine a=new HeapMachine(mapped,binary),b=new HeapMachine(mapped,binary);
        long[] heaps={0x910000,0x89100000L,0xfffffff0L};
        long[] sizes={0,1,4,0x80000000L,MASK};
        long[] alignments={0,1,4,8,16,64,128,0xfffffffcL,0xfffffff8L,0xfffffff0L,0xffffffc0L,0xffffff80L,0x80000000L,MASK};
        long[] counts={0,1,0x7fffffffL,0x80000000L,0xfffffffeL,MASK};
        long[] results={0,1,0x87654320L,MASK};
        long[][] options={{0,0,0},{1,0x80000000L,MASK},{0x12345678,0x89abcdefL,0x76543210}};
        try(PrintWriter log=new PrintWriter(Files.newBufferedWriter(out.resolve("results.tsv")))) {
            log.println("case\theap\tsize\talignment\tfourth\tfifth\tsixth\tcount\tresult\teffect");
            for(long heap:heaps) for(long size:sizes) for(long alignment:alignments) for(long count:counts)
            for(long result:results) for(int effect=0;effect<3;effect++) {
                long[] opt=options[cases%options.length];
                compare(a,b,log,heap,size,alignment,opt[0],opt[1],opt[2],count,result,effect);
            }
            Random rng=new Random(ENTRY);
            for(int i=0;i<1024;i++) compare(a,b,log,heaps[i%3],Integer.toUnsignedLong(rng.nextInt()),
                Integer.toUnsignedLong(rng.nextInt()),Integer.toUnsignedLong(rng.nextInt()),Integer.toUnsignedLong(rng.nextInt()),
                Integer.toUnsignedLong(rng.nextInt()),Integer.toUnsignedLong(rng.nextInt()),
                i%4==0 ? 0 : Integer.toUnsignedLong(rng.nextInt()),i%3);
        }
        StringBuilder listing=new StringBuilder();
        for(long pc=ENTRY;pc<END;pc+=4) {
            require(visited.contains(pc),"Unvisited original "+Long.toHexString(pc));
            var ins=currentProgram.getListing().getInstructionAt(toAddr(pc)); require(ins!=null,"Missing listing");
            listing.append(String.format("%08x %s %s%n",pc,HexFormat.of().formatHex(ins.getBytes()),ins));
        }
        Files.writeString(out.resolve("original-ghidra.txt"),listing);
        // Export bounded caller windows from the saved program, without changing analysis.
        StringBuilder callers=new StringBuilder();
        int callerCount=0;
        for(var ref:getReferencesTo(toAddr(ENTRY))) {
            if(!ref.getReferenceType().isCall()) continue;
            callerCount++; long at=ref.getFromAddress().getOffset();
            callers.append(String.format("CALL %08x%n",at));
            for(long pc=at-48;pc<=at+20;pc+=4) {
                var ins=currentProgram.getListing().getInstructionAt(toAddr(pc));
                if(ins!=null) callers.append(String.format("%08x %s %s%n",pc,HexFormat.of().formatHex(ins.getBytes()),ins));
            }
        }
        Files.writeString(out.resolve("caller-ghidra.txt"),callers);
        Files.writeString(out.resolve("comparison.json"),String.format(Locale.ROOT,
            "{\"wrapper_cases\":%d,\"null_results\":%d,\"overflow_cases\":%d,\"dependency_effect_cases\":%d,\"zero_size_cases\":%d,\"wrapping_heap_addresses\":%d,\"caller_sites\":%d,\"original_instruction_addresses\":%d,\"max_steps\":%d,\"dependency_calls_both_paths\":%d,\"lower_dependencies_modeled\":true,\"live_verified\":false}\n",
            cases,nullCases,overflowCases,effectCases,zeroSizeCases,wrapAddressCases,callerCount,visited.size(),maxSteps,dependencyCalls));
        println("SMT4_HEAP_ALLOCATE_COMPARE_OK");
    }
}
