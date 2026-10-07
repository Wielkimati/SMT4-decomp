// Raw router only: heap algorithms and recursive synchronization are modeled.
// @category SMT4
import ghidra.pcode.emu.PcodeThread;
import ghidra.pcode.utils.Utils;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.pcode.PcodeOp;
import java.nio.file.*;
import java.security.MessageDigest;
import java.util.*;
import java.io.*;

public class CompareResourceAllocateRaw extends CompareResourceSync {
    static final long ENTRY=0x2b26f0, END=0x2b285c, STATE=0x465170, MASK=0xffffffffL;
    static final long ACQUIRE=0x2c3afc, RELEASE=0x2c3a78, HEAP=0x2c3a98, FIXED=0x144978;
    int cases, zeroCases, lockedCases, fixedCases, unknownCases, nullCases, textSize;
    final Set<Long> alignments=new TreeSet<>();
    @Override boolean originalCode(long pc) {
        return within(pc,4,ENTRY,END) && !within(pc,4,0x2b2724,0x2b273c);
    }
    static long alignment(long second,long fifth) {
        // Table oracle indexed by exact selector, independent of source switch.
        Map<Long,Long> table=Map.of(256L,4L,257L,128L,258L,8L,259L,64L,260L,16L,261L,16L);
        long magnitude=table.getOrDefault(second,8L);
        return fifth==0 ? 0x100000000L-magnitude : magnitude;
    }
    class RawMachine extends SyncMachine {
        final List<String> trace=new ArrayList<>();
        int stateReads;
        RawMachine(byte[] mapped,byte[] binary) { super(mapped,binary); }
        @Override void step(boolean rebuiltPath,int steps) throws Exception {
            if(rebuiltPath) require(within(thread.getCounter().getOffset(),4,BUILD,BUILD+textSize),"PC outside rebuilt text");
            super.step(rebuiltPath,steps);
        }
        @Override public void beforeStore(PcodeThread<byte[]> t,PcodeOp op,AddressSpace space,
                byte[] offset,int n,byte[] value) {
            long a=Utils.bytesToLong(offset,offset.length,false);
            require(within(a,n,STACK-64,STACK),"Unexpected router store "+Long.toHexString(a));
        }
        @Override public void beforeLoad(PcodeThread<byte[]> t,PcodeOp op,AddressSpace space,byte[] offset,int n) {
            long a=Utils.bytesToLong(offset,offset.length,false);
            if(a==STATE+4 && n==4) stateReads++;
            require(within(a,n,STACK-64,STACK+4) || within(a,n,ENTRY,END+12) ||
                within(a,n,BUILD,BUILD+codeSize) || (a==STATE+4 && n==4),
                "Unexpected router read "+Long.toHexString(a));
        }
        void call(boolean rebuiltPath,long first,long second,long third,long size,long fifth,
                  long base,long result,int effect) throws Exception {
            initialize(rebuiltPath,0,new byte[0x144]); trace.clear(); stateReads=0;
            Random rng=new Random(ENTRY+cases);
            byte[] state=new byte[0x40]; rng.nextBytes(state); put(state,20,base); memory(STATE-16,state);
            byte[] caller=new byte[32]; rng.nextBytes(caller); put(caller,0,fifth); memory(STACK,caller);
            register("r0",first); register("r1",second); register("r2",third); register("r3",size);
            register("s16",0x81234567L); register("s17",0xfedcba98L);
            thread.overrideCounter(toAddr(rebuiltPath ? entries[0] : ENTRY)); executing=true;
            boolean locked=size!=0 && (first==256 || first==65536);
            boolean fixed=size!=0 && (first==131072 || first==196608);
            List<Long> expected=locked ? List.of(ACQUIRE,HEAP,RELEASE) : fixed ? List.of(FIXED) : List.of();
            long heap=(base+(first==256 ? 28 : 136))&MASK;
            long lock=(heap+88)&MASK;
            int calls=0,steps=0;
            while(thread.getCounter().getOffset()!=RETURN) {
                long pc=thread.getCounter().getOffset();
                if(pc==ACQUIRE || pc==RELEASE || pc==HEAP || pc==FIXED) {
                    require(calls<expected.size() && expected.get(calls)==pc,"Router dependency order");
                    require((register("sp")&7)==0,"Dependency stack alignment");
                    require(Arrays.equals(state,memory(STATE-16,state.length)),"State/guards before dependency");
                    long[] args=pc==HEAP ? new long[]{heap,size,alignment(second,fifth),0,0,0} :
                        pc==FIXED ? new long[]{first==131072 ? 0x4e4100 : 0x4e411c,size,first,STATE} : new long[]{lock};
                    for(int i=0;i<args.length;i++) {
                        long actual=i<4 ? register("r"+i) : word(memory(register("sp")+4*(i-4),4),0);
                        require(actual==args[i],"Router argument "+i+" at "+Long.toHexString(pc)+" expected="+args[i]+" actual="+actual);
                    }
                    trace.add(Long.toHexString(pc)+":"+Arrays.toString(args));
                    // Changes after acquire/allocation must not retarget this call's saved objects.
                    if(effect!=0) { put(state,20,(base+0x12345678L*(calls+1))&MASK); memory(STATE-16,state); }
                    for(int r=0;r<16;r++) register("s"+r,0xdead0000L+r);
                    externalReturn(pc==HEAP || pc==FIXED ? result : Integer.toUnsignedLong(rng.nextInt()));
                    calls++; dependencyCalls++; continue;
                }
                step(rebuiltPath,++steps);
            }
            require(calls==expected.size(),"Missing router dependency");
            require(register("r0")== (locked || fixed ? result : 0),"Router return");
            require(stateReads==(size==0 ? 0 : 1),"Router global read count");
            require(Arrays.equals(state,memory(STATE-16,state.length)),"Final state/guards");
            require(Arrays.equals(caller,memory(STACK,caller.length)),"Caller stack");
            byte[] stack=memory(STACK-0x1000,0x1000);
            for(int i=0;i<stack.length-64;i++) require(stack[i]==(byte)0x96,"Stack guard");
            require(register("s16")==0x81234567L && register("s17")==0xfedcba98L,"d8 preservation");
            finish(steps);
        }
    }
    void compare(RawMachine a,RawMachine b,PrintWriter log,long first,long second,long third,long size,
                 long fifth,long base,long result,int effect) throws Exception {
        try {
            a.call(false,first,second,third,size,fifth,base,result,effect);
            b.call(true,first,second,third,size,fifth,base,result,effect);
            require(a.trace.equals(b.trace),"Router call trace");
        } catch(Exception ex) { throw new IllegalStateException("Raw router case "+cases+" args="+
            Arrays.toString(new long[]{first,second,third,size,fifth,base,result,effect}),ex); }
        if(size==0) zeroCases++;
        else if(first==256 || first==65536) { lockedCases++; alignments.add(alignment(second,fifth)); }
        else if(first==131072 || first==196608) fixedCases++;
        else unknownCases++;
        if(size!=0 && (first==256 || first==65536 || first==131072 || first==196608) && result==0) nullCases++;
        log.printf("%d\t%x\t%x\t%x\t%x\t%x\t%x\t%x\t%d%n",++cases,first,second,third,size,fifth,base,result,effect);
    }
    @Override public void run() throws Exception {
        Path out=Path.of(getScriptArgs()[0]); require(!Files.exists(out.resolve("comparison.json")),"Existing output");
        byte[] mapped=new byte[0x377000]; require(currentProgram.getMemory().getBytes(toAddr(0x100000),mapped)==mapped.length,"Map");
        require(HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(mapped)).equals(
            "834938d18d2b7c688311c46c27bed813d0d7a9f8e3cbb61da8a6a3f23d360ebd"),"Hash");
        long[] words={0x2b273c,0x2b2744,0x2b2758,0x2b274c,0x2b2754,0x2b2754,STATE,0x4e4100,0x4e411c};
        StringBuilder literals=new StringBuilder();
        for(int i=0;i<words.length;i++) {
            long address=i<6 ? 0x2b2724+i*4 : END+(i-6)*4;
            require(word(mapped,(int)(address-0x100000))==words[i],"Table/literal word");
            literals.append(String.format("%08x %08x%n",address,words[i]));
        }
        Files.writeString(out.resolve("original-words.txt"),literals);
        byte[] binary=Files.readAllBytes(out.resolve("resource-allocate-raw.bin")); codeSize=binary.length;
        require(codeSize>0 && codeSize<=0x1000,"Binary size");
        textSize=Integer.parseInt(Files.readString(out.resolve("text-size.txt")).trim());
        require(textSize>0 && textSize<=codeSize,"Text extent");
        List<String> lines=Files.readAllLines(out.resolve("entries.txt")); require(lines.size()==1,"Entries");
        entries[0]=Long.parseLong(lines.get(0)); require(within(entries[0],4,BUILD,BUILD+codeSize),"Entry");
        RawMachine a=new RawMachine(mapped,binary),b=new RawMachine(mapped,binary);
        long[] selectors={0,255,256,257,65535,65536,65537,131071,131072,131073,196607,196608,196609,0x80000100L,MASK};
        long[] seconds={0,1,255,256,257,258,259,260,261,262,0x80000100L,0xffffff00L,MASK};
        long[] fifths={0,1,256,0x80000000L,MASK};
        long[] bases={0,1,0x900000,0x89000000L,0xffffff80L};
        long[] results={0,1,0x87654320L,MASK};
        try(PrintWriter log=new PrintWriter(Files.newBufferedWriter(out.resolve("results.tsv")))) {
            log.println("case\tfirst\tsecond\tthird\tsize\tfifth\tbase\tresult\teffect");
            for(long first:selectors) for(long second:seconds) for(long fifth:fifths)
            for(long size:new long[]{0,1,0x80000000L,MASK}) for(int effect=0;effect<2;effect++)
                compare(a,b,log,first,second,(0x87654321L*cases)&MASK,size,fifth,bases[cases%bases.length],results[(cases/8)%4],effect);
            Random rng=new Random(ENTRY);
            for(int i=0;i<1024;i++) compare(a,b,log,i%5==0 ? Integer.toUnsignedLong(rng.nextInt()) : new long[]{256,65536,131072,196608}[i%4],
                Integer.toUnsignedLong(rng.nextInt()),Integer.toUnsignedLong(rng.nextInt()),Integer.toUnsignedLong(rng.nextInt()),
                i%2==0 ? 0 : Integer.toUnsignedLong(rng.nextInt()),Integer.toUnsignedLong(rng.nextInt()),
                Integer.toUnsignedLong(rng.nextInt()),i%2);
        }
        require(alignments.size()==10,"Signed alignment coverage");
        StringBuilder listing=new StringBuilder();
        for(long pc=ENTRY;pc<END;pc+=4) if(originalCode(pc)) {
            require(visited.contains(pc),"Unvisited original "+Long.toHexString(pc));
            var ins=currentProgram.getListing().getInstructionAt(toAddr(pc)); require(ins!=null,"Missing listing");
            listing.append(String.format("%08x %s%n",pc,ins));
        }
        Files.writeString(out.resolve("original-ghidra.txt"),listing);
        Files.writeString(out.resolve("comparison.json"),String.format(Locale.ROOT,
            "{\"router_cases\":%d,\"zero_size_cases\":%d,\"locked_cases\":%d,\"fixed_cases\":%d,\"unknown_cases\":%d,\"null_results\":%d,\"signed_alignments\":%d,\"original_instruction_addresses\":%d,\"max_steps\":%d,\"dependency_calls_both_paths\":%d,\"lower_dependencies_modeled\":true,\"live_verified\":false}\n",
            cases,zeroCases,lockedCases,fixedCases,unknownCases,nullCases,alignments.size(),visited.size(),maxSteps,dependencyCalls));
        println("SMT4_ALLOCATE_RAW_COMPARE_OK");
    }
}
