// Aligned allocator: explicit raw allocation, accounting, zero and lock models.
// @category SMT4
import ghidra.pcode.emu.PcodeThread;
import ghidra.pcode.utils.Utils;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.pcode.PcodeOp;
import java.nio.file.*;
import java.security.MessageDigest;
import java.util.*;
import java.io.*;

public class CompareResourceAllocateLower extends CompareResourceSync {
    static final long ENTRY=0x2c5544, END=0x2c5634, STATE=0x465120, MASK=0xffffffffL;
    static final long ACQUIRE=0x2c3afc, RELEASE=0x2c3a78, RAW=0x2b26f0, ZERO=0x2c3b9c, ACCOUNT=0x2b260c;
    int cases, specialCases, nullCases, wrapCases, materializedZeroCases;
    @Override boolean originalCode(long pc) { return within(pc,4,ENTRY,END); }
    class LowerMachine extends SyncMachine {
        List<String> trace=new ArrayList<>();
        long raw, user, base;
        boolean special, allocated;
        LowerMachine(byte[] mapped,byte[] binary) { super(mapped,binary); }
        @Override public void beforeStore(PcodeThread<byte[]> t,PcodeOp op,AddressSpace space,
                byte[] offset,int size,byte[] value) {
            long a=Utils.bytesToLong(offset,offset.length,false);
            if(within(a,size,STACK-64,STACK)) return;
            require(!special && allocated && (within(a,size,raw,raw+8) || within(a,size,user-4,user)),
                "Unexpected metadata store "+Long.toHexString(a));
        }
        @Override public void beforeLoad(PcodeThread<byte[]> t,PcodeOp op,AddressSpace space,
                byte[] offset,int size) {
            long a=Utils.bytesToLong(offset,offset.length,false);
            require(within(a,size,STACK-64,STACK+4) || within(a,size,STATE+4,STATE+8) ||
                within(a,size,ENTRY,END+4) || within(a,size,BUILD,BUILD+codeSize),
                "Unexpected allocator read "+Long.toHexString(a));
        }
        void call(boolean rebuiltPath,long[] args,long rawResult,int effect,long seed) throws Exception {
            initialize(rebuiltPath,0,new byte[0x144]);
            raw=rawResult; special=args[0]==0x20000 || args[0]==0x30000; allocated=false;
            // Independent arithmetic oracle: ceiling to the next 128-byte boundary.
            user=special ? raw : ((raw+60+127)/128)*128;
            long rounded=((args[3]+315)&MASK)/128*128;
            base=special ? 0x900000 : raw&~0xfffL;
            Random rng=new Random(seed);
            byte[] heap=new byte[4096]; rng.nextBytes(heap); memory(base,heap);
            byte[] metadata=heap.clone();
            if(!special) {
                put(metadata,(int)(raw-base),rounded);
                put(metadata,(int)(raw-base+4),128);
                put(metadata,(int)(user-base-4),raw);
            }
            byte[] expected=heap;
            byte[] state=new byte[0x60]; rng.nextBytes(state);
            long lock=word(state,20); memory(STATE-16,state);
            byte[] upper=new byte[64]; rng.nextBytes(upper); put(upper,0,args[4]); memory(STACK,upper);
            byte[] stack=memory(STACK-0x1000,0x1000);
            for(int i=0;i<4;i++) register("r"+i,args[i]);
            register("s16",0x81234567L); register("s17",0xfedcba98L);
            thread.overrideCounter(toAddr(rebuiltPath ? entries[0] : ENTRY));
            List<Long> expectedCalls=new ArrayList<>(List.of(ACQUIRE,RAW));
            if(!special) expectedCalls.addAll(List.of(ACCOUNT,ZERO));
            expectedCalls.add(RELEASE);
            int calls=0,steps=0; trace.clear(); executing=true;
            while(thread.getCounter().getOffset()!=RETURN) {
                long pc=thread.getCounter().getOffset();
                if(pc==ACQUIRE || pc==RAW || pc==ACCOUNT || pc==ZERO || pc==RELEASE) {
                    require(calls<expectedCalls.size() && expectedCalls.get(calls++)==pc,"Allocator dependency order");
                    require((register("sp")&7)==0,"Dependency stack alignment");
                    require(Arrays.equals(state,memory(STATE-16,state.length)),"State before dependency");
                    if(pc==ACCOUNT) expected=metadata;
                    require(Arrays.equals(expected,memory(base,heap.length)),"Heap metadata/order/guards");
                    if(pc==ACQUIRE || pc==RELEASE) {
                        require(register("r0")==lock,"Allocator lock argument");
                        trace.add(Long.toHexString(pc)+":"+lock);
                    } else if(pc==RAW) {
                        for(int i=0;i<4;i++) require(register("r"+i)==(i==3 && !special ? rounded : args[i]),
                            "Raw allocation argument "+i);
                        require(word(memory(register("sp"),4),0)==args[4],"Raw fifth argument");
                        trace.add("raw:"+Arrays.toString(args)+":"+(special ? args[3] : rounded));
                        allocated=true;
                    } else if(pc==ACCOUNT) {
                        require(register("r0")==raw,"Accounting raw pointer");
                        trace.add("account:"+raw);
                        // Accounting owns other header fields. Preserve its modeled effects.
                        byte[] change=new byte[24]; rng.nextBytes(change);
                        expected=expected.clone(); System.arraycopy(change,0,expected,(int)(raw-base+8),change.length);
                        memory(base,expected);
                    } else {
                        require(register("r0")==user && register("r1")==args[3],"Allocator zero arguments");
                        trace.add("zero:"+user+":"+args[3]);
                        // Large/wrapping sizes test marshalling only, never fictitious huge buffers.
                        if(args[3]<=1024) {
                            expected=expected.clone();
                            Arrays.fill(expected,(int)(user-base),(int)(user-base+args[3]),(byte)0);
                            memory(base,expected);
                        }
                    }
                    dependencyCalls++;
                    if((effect==1 && pc==ACQUIRE) || (effect==2 && pc==RAW) ||
                       (effect==3 && pc==ACCOUNT) || (effect==4 && pc==ZERO) || (effect==5 && pc!=RELEASE)) {
                        lock=(lock^pc^0x87654321L)&MASK;
                        put(state,20,lock); memory(STATE-16,state);
                    }
                    for(int i=0;i<16;i++) register("s"+i,Integer.toUnsignedLong(rng.nextInt()));
                    externalReturn(pc==RAW ? raw : (user^0xface9876L)&MASK);
                    continue;
                }
                step(rebuiltPath,++steps);
            }
            require(calls==expectedCalls.size(),"Missing allocator dependency");
            require(register("r0")==user,"Aligned allocation result");
            require(Arrays.equals(expected,memory(base,heap.length)),"Final heap/guards");
            require(Arrays.equals(state,memory(STATE-16,state.length)),"Final state/guards");
            require(Arrays.equals(upper,memory(STACK,upper.length)),"Caller stack/fifth argument changed");
            byte[] actual=memory(STACK-0x1000,0x1000);
            for(int i=0;i<stack.length-64;i++) require(stack[i]==actual[i],"Stack guard");
            require(register("s16")==0x81234567L && register("s17")==0xfedcba98L,"d8 preservation");
            finish(steps);
        }
    }
    void compare(LowerMachine a,LowerMachine b,PrintWriter log,long[] args,long raw,int effect) throws Exception {
        try {
            a.call(false,args,raw,effect,ENTRY+cases);
            b.call(true,args,raw,effect,ENTRY+cases);
            require(a.trace.equals(b.trace),"Call trace difference");
        } catch(Exception ex) {
            throw new IllegalStateException("Case "+cases+" args="+Arrays.toString(args)+" raw="+raw+" effect="+effect,ex);
        }
        boolean special=args[0]==0x20000 || args[0]==0x30000;
        if(special) specialCases++;
        if(raw==0) nullCases++;
        if(!special && args[3]+315>MASK) wrapCases++;
        if(!special && args[3]<=1024) materializedZeroCases++;
        log.printf("%d\t%s\t%d\t%d%n",++cases,Arrays.toString(args),raw,effect);
    }
    @Override public void run() throws Exception {
        Path out=Path.of(getScriptArgs()[0]); require(!Files.exists(out.resolve("comparison.json")),"Existing output");
        byte[] mapped=new byte[0x377000];
        require(currentProgram.getMemory().getBytes(toAddr(0x100000),mapped)==mapped.length,"Map");
        require(HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(mapped)).equals(
            "834938d18d2b7c688311c46c27bed813d0d7a9f8e3cbb61da8a6a3f23d360ebd"),"Hash");
        byte[] binary=Files.readAllBytes(out.resolve("resource-allocate-lower.bin")); codeSize=binary.length;
        require(codeSize>0 && codeSize<=0x1000,"Binary size");
        List<String> lines=Files.readAllLines(out.resolve("entries.txt")); require(lines.size()==1,"Entries");
        entries[0]=Long.parseLong(lines.get(0)); require(within(entries[0],4,BUILD,BUILD+codeSize),"Entry extent");
        LowerMachine a=new LowerMachine(mapped,binary),b=new LowerMachine(mapped,binary);
        long[] sizes={0,1,4,24,68,69,70,127,128,196,197,198,324,1024,0x7fffffffL,0x80000000L,
            0xfffffec4L,0xfffffec5L,0xfffffec6L,0xfffffffeL,MASK};
        try(PrintWriter log=new PrintWriter(Files.newBufferedWriter(out.resolve("results.tsv")))) {
            log.println("case\targuments\traw_result\tlock_effect");
            // Every word-aligned residue modulo 128, low/high-bit storage, all lock effects.
            for(long base:new long[]{0x900100,0x89000100L}) for(int residue=0;residue<128;residue+=4)
                for(long size:sizes) for(int effect=0;effect<6;effect++)
                    compare(a,b,log,new long[]{256,256,0,size,effect%2},base+residue,effect);
            // Both exact bypass selectors, untouched result words (including null), full-width arguments.
            for(long first:new long[]{0x20000,0x30000}) for(long size:sizes)
                for(long result:new long[]{0,1,0x900100,0x80000000L,MASK}) for(int effect=0;effect<6;effect++)
                    compare(a,b,log,new long[]{first,0xfedcba98L,0x89abcdefL,size,0x87654321L},result,effect);
            long[] values={0,1,255,256,0x10000,0x1ffff,0x20000,0x20001,0x2ffff,0x30000,0x30001,
                0x80020000L,0x80030000L,0x7fffffffL,0x80000000L,MASK};
            for(int slot=0;slot<5;slot++) for(long value:values) for(int effect=0;effect<6;effect++) {
                long[] args={0x10000,0x50607080,0x90a0b0c0L,24,0xfedcba98L};
                args[slot]=value; compare(a,b,log,args,0x90013c,effect);
            }
            Random rng=new Random(ENTRY);
            for(int i=0;i<1024;i++) {
                long[] args=new long[5]; for(int j=0;j<5;j++) args[j]=Integer.toUnsignedLong(rng.nextInt());
                compare(a,b,log,args,0x900100+(rng.nextInt(32)*4),i%6);
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
            "{\"allocate_lower_cases\":%d,\"special_cases\":%d,\"null_special_cases\":%d,\"wrapping_size_cases\":%d,\"materialized_zero_cases\":%d,\"original_instruction_addresses\":%d,\"max_steps\":%d,\"dependency_calls_both_paths\":%d,\"lower_dependencies_modeled\":true,\"live_verified\":false}\n",
            cases,specialCases,nullCases,wrapCases,materializedZeroCases,visited.size(),maxSteps,dependencyCalls));
        println("SMT4_ALLOCATE_LOWER_COMPARE_OK");
    }
}
