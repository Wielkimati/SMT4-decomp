// Direct leaf setters: no intercepted calls or allocator execution.
// @category SMT4
import ghidra.pcode.emu.PcodeThread;
import ghidra.pcode.utils.Utils;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.pcode.PcodeOp;
import java.nio.file.*;
import java.security.MessageDigest;
import java.util.*;
import java.io.*;

public class CompareResourceHeapConfigure extends CompareResourceSync {
    static final long[] STARTS={0x146ce0,0x146cf0,0x146d10}, ENDS={0x146cf0,0x146d10,0x146d20};
    static final long MASK=0xffffffffL;
    final int[] counts=new int[3];
    int cases, negativeBytes, wrapped, unchanged;
    @Override boolean originalCode(long pc) {
        for(int k=0;k<3;k++) if(within(pc,4,STARTS[k],ENDS[k])) return true;
        return false;
    }
    class ConfigureMachine extends SyncMachine {
        long field;
        int width, reads, stores, kind;
        final List<String> trace=new ArrayList<>();
        ConfigureMachine(byte[] mapped,byte[] binary) { super(mapped,binary); }
        @Override public void beforeStore(PcodeThread<byte[]> t,PcodeOp op,AddressSpace space,
                byte[] offset,int n,byte[] value) {
            long a=Utils.bytesToLong(offset,offset.length,false);
            require(a==field && n==width && reads==1 && stores==0,"Exact field store after read");
            stores++;
            trace.add("W:"+a+":"+n+":"+Utils.bytesToLong(value,n,false));
        }
        @Override public void beforeLoad(PcodeThread<byte[]> t,PcodeOp op,AddressSpace space,byte[] offset,int n) {
            long a=Utils.bytesToLong(offset,offset.length,false);
            require(a==field && n==width && reads==0 && stores==0,"Exact field read before store");
            reads++; trace.add("R:"+a+":"+n);
        }
        @Override void step(boolean rebuiltPath,int steps) throws Exception {
            if(!rebuiltPath) require(within(thread.getCounter().getOffset(),4,STARTS[kind],ENDS[kind]),"Wrong original entry range");
            super.step(rebuiltPath,steps);
        }
        byte[] call(boolean rebuiltPath,int k,long object,long value,byte[] initial,byte[] expected,long result) throws Exception {
            initialize(rebuiltPath,k,new byte[0x144]);
            kind=k; width=k==2 ? 1 : 2; field=(object+0x34+2*k)&MASK;
            long backing=(object+0x24)&MASK;
            memory(backing,initial); reads=0; stores=0; trace.clear();
            register("r0",object); register("r1",value);
            // Poison incidental inputs; the consumed contract is r0/r1 only.
            register("r2",(value^0xa55a1234L)&MASK); register("r3",(object^0x5aa54321L)&MASK);
            for(int r=16;r<32;r++) register("s"+r,0x81234000L+r);
            byte[] caller=new byte[32]; Arrays.fill(caller,(byte)0x69); memory(STACK,caller);
            thread.overrideCounter(toAddr(rebuiltPath ? entries[k] : STARTS[k])); executing=true;
            int steps=0;
            while(thread.getCounter().getOffset()!=RETURN) step(rebuiltPath,++steps);
            require(register("r0")==result,"Previous-value return");
            require(reads==1 && stores==1,"Exactly one read and one store");
            byte[] actual=memory(backing,initial.length);
            require(Arrays.equals(actual,expected),"Field contents/unrelated bytes/guards");
            for(byte b:memory(STACK-0x1000,0x1000)) require(b==(byte)0x96,"Stack unchanged");
            require(Arrays.equals(caller,memory(STACK,caller.length)),"Caller stack unchanged");
            for(int r=16;r<32;r++) require(register("s"+r)==0x81234000L+r,"Callee-saved VFP");
            finish(steps); return actual;
        }
    }
    void compare(ConfigureMachine a,ConfigureMachine b,PrintWriter log,int k,long object,int old,long value) throws Exception {
        byte[] initial=new byte[40]; new Random(0x146ce0+cases).nextBytes(initial);
        int at=16+2*k; initial[at]=(byte)old;
        if(k!=2) initial[at+1]=(byte)(old>>>8);
        byte[] expected=initial.clone();
        // Byte-oriented oracle independently preserves every unrelated bit/byte.
        long result;
        if(k==0) {
            result=old; expected[at]=(byte)value; expected[at+1]=(byte)(value>>>8);
        } else if(k==1) {
            result=old%2;
            expected[at]=(byte)((old/2*2)+(value%2));
        } else {
            result=old<128 ? old : (0x100000000L+old-256);
            expected[at]=(byte)value;
        }
        try {
            byte[] x=a.call(false,k,object,value,initial,expected,result);
            byte[] y=b.call(true,k,object,value,initial,expected,result);
            require(Arrays.equals(x,y) && a.trace.equals(b.trace),"Original/rebuilt memory/access trace");
        } catch(Exception ex) { throw new IllegalStateException("Heap configuration case "+cases+" kind="+k+
            " object="+Long.toHexString(object)+" old="+old+" value="+Long.toHexString(value),ex); }
        if(k==2 && old>=128) negativeBytes++;
        if(object+0x38>MASK) wrapped++;
        if(Arrays.equals(initial,expected)) unchanged++;
        counts[k]++; log.printf("%d\t%d\t%x\t%x\t%x\t%x%n",++cases,k,object,old,value,result);
    }
    @Override public void run() throws Exception {
        Path out=Path.of(getScriptArgs()[0]); require(!Files.exists(out.resolve("comparison.json")),"Output exists");
        byte[] mapped=new byte[0x377000]; require(currentProgram.getMemory().getBytes(toAddr(0x100000),mapped)==mapped.length,"Map");
        require(HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(mapped)).equals(
            "834938d18d2b7c688311c46c27bed813d0d7a9f8e3cbb61da8a6a3f23d360ebd"),"Hash");
        byte[] binary=Files.readAllBytes(out.resolve("resource-heap-configure.bin")); codeSize=binary.length;
        require(codeSize>0 && codeSize<=0x1000,"Binary extent");
        List<String> lines=Files.readAllLines(out.resolve("entries.txt")); require(lines.size()==3,"Entries");
        for(int k=0;k<3;k++) { entries[k]=Long.parseLong(lines.get(k)); require(within(entries[k],4,BUILD,BUILD+codeSize),"Entry extent"); }
        ConfigureMachine a=new ConfigureMachine(mapped,binary),b=new ConfigureMachine(mapped,binary);
        long[] objects={0x910000,0x89100000L,0xfffffff0L};
        long[] values={0,1,2,0x7f,0x80,0xff,0x100,0x7fff,0x8000,0xffff,0x80000000L,MASK};
        Random rng=new Random(0x146ce0);
        try(PrintWriter log=new PrintWriter(Files.newBufferedWriter(out.resolve("results.tsv")))) {
            log.println("case\tkind\tsubobject\told\tvalue\treturn");
            for(int k=0;k<3;k++) for(long object:objects) for(long old:values) for(long value:values)
                compare(a,b,log,k,object,(int)(old & (k==2 ? 255 : 65535)),value);
            // Exhaust every old halfword, with full-width deterministic option words.
            for(int k=0;k<2;k++) for(int old=0;old<65536;old++)
                compare(a,b,log,k,objects[old%3],old,Integer.toUnsignedLong(rng.nextInt()));
            // Exhaust all old/new byte pairs, with nonzero and varying upper option bits.
            for(int old=0;old<256;old++) for(int value=0;value<256;value++)
                compare(a,b,log,2,objects[(old+value)%3],old,(Integer.toUnsignedLong(rng.nextInt())&0xffffff00L)|value);
            for(int k=0;k<3;k++) for(int n=0;n<1024;n++)
                compare(a,b,log,k,objects[n%3],rng.nextInt(k==2 ? 256 : 65536),Integer.toUnsignedLong(rng.nextInt()));
        }
        require(cases==200976 && negativeBytes>0 && wrapped>0 && unchanged>0,"Corpus");
        StringBuilder listing=new StringBuilder();
        for(int k=0;k<3;k++) for(long pc=STARTS[k];pc<ENDS[k];pc+=4) {
            require(visited.contains(pc),"Unvisited original instruction");
            var ins=currentProgram.getListing().getInstructionAt(toAddr(pc)); require(ins!=null,"Instruction");
            listing.append(String.format("%08x %s %s%n",pc,HexFormat.of().formatHex(ins.getBytes()),ins));
        }
        Files.writeString(out.resolve("original-ghidra.txt"),listing);
        Files.writeString(out.resolve("comparison.json"),String.format(Locale.ROOT,
            "{\"configuration_cases\":%d,\"cases_per_entry\":%s,\"negative_byte_returns\":%d,\"wrapping_addresses\":%d,\"unchanged_field_stores\":%d,\"original_instruction_addresses\":%d,\"max_steps\":%d,\"modeled_calls\":0,\"live_verified\":false}\n",
            cases,Arrays.toString(counts),negativeBytes,wrapped,unchanged,visited.size(),maxSteps));
        println("SMT4_HEAP_CONFIGURE_COMPARE_OK");
    }
}
