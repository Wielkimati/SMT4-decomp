// Four inclusive unsigned ranges; no intercepted calls and no raw-pointer dereference.
// @category SMT4
import ghidra.pcode.emu.PcodeThread;
import ghidra.pcode.utils.Utils;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.pcode.PcodeOp;
import java.nio.file.*;
import java.security.MessageDigest;
import java.util.*;
import java.io.*;

public class CompareResourceHeapIndex extends CompareResourceSync {
    static final long ENTRY=0x2b3340, END=0x2b33cc, STATE=0x465120, MASK=0xffffffffL;
    int cases, unmatched, overlapping;
    final int[] results=new int[4];
    @Override boolean originalCode(long pc) { return within(pc,4,ENTRY,END); }
    class IndexMachine extends SyncMachine {
        IndexMachine(byte[] mapped,byte[] binary) { super(mapped,binary); }
        @Override public void beforeStore(PcodeThread<byte[]> t,PcodeOp op,AddressSpace space,byte[] offset,int n,byte[] value) {
            long a=Utils.bytesToLong(offset,offset.length,false);
            require(within(a,n,STACK-64,STACK),"Unexpected selector store "+Long.toHexString(a));
        }
        @Override public void beforeLoad(PcodeThread<byte[]> t,PcodeOp op,AddressSpace space,byte[] offset,int n) {
            long a=Utils.bytesToLong(offset,offset.length,false);
            require(within(a,n,STACK-64,STACK) || within(a,n,STATE+28,STATE+60) ||
                within(a,n,ENTRY,END+4) || within(a,n,BUILD,BUILD+codeSize),
                "Unexpected selector read "+Long.toHexString(a));
        }
        void call(boolean rebuiltPath,long raw,byte[] state,int want) throws Exception {
            initialize(rebuiltPath,0,new byte[0x144]); memory(STATE-16,state);
            register("r0",raw); register("s16",0x81234567L); register("s17",0xfedcba98L);
            thread.overrideCounter(toAddr(rebuiltPath ? entries[0] : ENTRY)); executing=true;
            int steps=0;
            while(thread.getCounter().getOffset()!=RETURN) step(rebuiltPath,++steps);
            require(register("r0")==want,"Selector result expected="+want+" actual="+register("r0"));
            require(Arrays.equals(state,memory(STATE-16,state.length)),"Selector state/guards changed");
            for(byte b:memory(STACK-0x1000,0xfc0)) require(b==(byte)0x96,"Stack guard");
            require(register("s16")==0x81234567L && register("s17")==0xfedcba98L,"VFP preserved");
            finish(steps);
        }
    }
    void compare(IndexMachine a,IndexMachine b,PrintWriter log,long[] starts,long[] lengths,long raw) throws Exception {
        // Build an abstract membership bitset, then choose its lowest member.
        int members=0;
        for(int i=0;i<4;i++) {
            long end=(starts[i]+lengths[i])&MASK;
            if(starts[i]<=raw && raw<=end) members|=1<<i;
        }
        int want=members==0 ? 0 : Integer.numberOfTrailingZeros(members);
        byte[] state=new byte[96]; new Random(ENTRY+cases).nextBytes(state);
        for(int i=0;i<4;i++) { put(state,16+28+4*i,starts[i]); put(state,16+44+4*i,lengths[i]); }
        try { a.call(false,raw,state,want); b.call(true,raw,state,want); }
        catch(Exception ex) { throw new IllegalStateException("Heap index case "+cases+" raw="+Long.toHexString(raw)+
            " starts="+Arrays.toString(starts)+" lengths="+Arrays.toString(lengths),ex); }
        results[want]++; if(members==0) unmatched++; if(Integer.bitCount(members)>1) overlapping++;
        log.printf("%d\t%08x\t%s\t%s\t%d\t%d%n",++cases,raw,Arrays.toString(starts),Arrays.toString(lengths),members,want);
    }
    void probes(IndexMachine a,IndexMachine b,PrintWriter log,long[] starts,long[] lengths,int slot,long extra) throws Exception {
        long start=starts[slot], end=(start+lengths[slot])&MASK;
        for(long raw:new long[]{start-1,start,start+1,end-1,end,end+1,extra})
            compare(a,b,log,starts,lengths,raw&MASK);
    }
    @Override public void run() throws Exception {
        Path out=Path.of(getScriptArgs()[0]); require(!Files.exists(out.resolve("comparison.json")),"Output exists");
        byte[] mapped=new byte[0x377000]; require(currentProgram.getMemory().getBytes(toAddr(0x100000),mapped)==mapped.length,"Map");
        require(HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(mapped)).equals(
            "834938d18d2b7c688311c46c27bed813d0d7a9f8e3cbb61da8a6a3f23d360ebd"),"Hash");
        byte[] binary=Files.readAllBytes(out.resolve("resource-heap-index.bin")); codeSize=binary.length;
        require(codeSize>0 && codeSize<=0x1000,"Binary extent");
        List<String> lines=Files.readAllLines(out.resolve("entries.txt")); require(lines.size()==1,"Entries");
        entries[0]=Long.parseLong(lines.get(0)); require(within(entries[0],4,BUILD,BUILD+codeSize),"Entry extent");
        IndexMachine a=new IndexMachine(mapped,binary), b=new IndexMachine(mapped,binary);
        long[] values={0,1,3,127,128,0x7fffffffL,0x80000000L,0x80000001L,0xffffff00L,0xfffffffeL,MASK};
        Random rng=new Random(ENTRY);
        try(PrintWriter log=new PrintWriter(Files.newBufferedWriter(out.resolve("results.tsv")))) {
            log.println("case\traw\tstarts\tlengths\tmembership\tresult");
            for(int slot=0;slot<4;slot++) for(long start:values) for(long length:values) {
                // Other ranges wrap to empty, isolating each index (including zero).
                long[] starts={MASK,MASK,MASK,MASK}, lengths={1,1,1,1};
                starts[slot]=start; lengths[slot]=length;
                probes(a,b,log,starts,lengths,slot,Integer.toUnsignedLong(rng.nextInt()));
            }
            for(int n=0;n<2048;n++) {
                long[] starts=new long[4], lengths=new long[4];
                for(int i=0;i<4;i++) { starts[i]=Integer.toUnsignedLong(rng.nextInt()); lengths[i]=Integer.toUnsignedLong(rng.nextInt()); }
                probes(a,b,log,starts,lengths,n%4,Integer.toUnsignedLong(rng.nextInt()));
            }
            for(int membership=0;membership<16;membership++) {
                long[] starts=new long[4], lengths=new long[4];
                for(int i=0;i<4;i++) starts[i]=0x80000000L+((membership&(1<<i))==0 ? 1 : 0);
                compare(a,b,log,starts,lengths,0x80000000L);
            }
        }
        require(cases==17740 && unmatched>0 && overlapping>0,"Corpus counts");
        for(int result:results) require(result>0,"Every selector result");
        StringBuilder listing=new StringBuilder();
        for(long pc=ENTRY;pc<END;pc+=4) {
            require(visited.contains(pc),"Unvisited selector instruction "+Long.toHexString(pc));
            var ins=currentProgram.getListing().getInstructionAt(toAddr(pc)); require(ins!=null,"Missing instruction");
            listing.append(String.format("%08x %s%n",pc,ins));
        }
        Files.writeString(out.resolve("original-ghidra.txt"),listing);
        Files.writeString(out.resolve("comparison.json"),String.format(Locale.ROOT,
            "{\"selector_cases\":%d,\"original_instruction_addresses\":%d,\"max_steps\":%d,\"unmatched_cases\":%d,\"overlapping_cases\":%d,\"result_counts\":%s,\"modeled_calls\":0,\"live_verified\":false}\n",
            cases,visited.size(),maxSteps,unmatched,overlapping,Arrays.toString(results)));
        println("SMT4_HEAP_INDEX_COMPARE_OK");
    }
}
