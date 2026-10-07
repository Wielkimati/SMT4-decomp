// Consumed-domain index/remainder execution, plus bulk loading with real index code.
// Only the file backend is intercepted in integrated comparisons.
// @category SMT4
import ghidra.pcode.emu.PcodeThread;
import ghidra.pcode.utils.Utils;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.lang.RegisterValue;
import ghidra.program.model.pcode.PcodeOp;
import java.math.BigInteger;
import java.nio.file.*;
import java.security.MessageDigest;
import java.util.*;
import java.io.*;

public class CompareResourceOrder extends CompareResourceBulk {
    class OrderMachine extends Machine {
        boolean index;
        int stateStores;
        OrderMachine(byte[] mapped, byte[] binary) { super(mapped,binary); }
        @Override public void beforeStore(PcodeThread<byte[]> t, PcodeOp op,
                AddressSpace space, byte[] offset, int size, byte[] value) {
            long a=Utils.bytesToLong(offset,offset.length,false);
            require(within(a,size,STACK-0x1000,STACK) || (index && a==STATE && size==4),
                "Unexpected order write "+Long.toHexString(a));
            if (a==STATE) stateStores++;
        }
        void compare(boolean isRebuilt, boolean isIndex, long[] row) throws Exception {
            executing=false; index=isIndex; stateStores=0;
            long initial=isIndex ? row[0] : 0xdeadbeefL;
            writeWord(STATE,initial);
            for (var r:currentProgram.getLanguage().getRegisters())
                if (r.isBaseRegister() && !r.isProcessorContext()) register(r,0);
            for (int r=0;r<=12;++r) register("r"+r,0x12340000L+r);
            register("cpsr",0x10); register("sp",STACK); register("lr",RETURN);
            register("r0",row[isIndex ? 1 : 0]); register("r1",row[isIndex ? 2 : 1]);
            thread.overrideContext(new RegisterValue(currentProgram.getProgramContext().getBaseContextRegister(),BigInteger.ZERO));
            thread.overrideCounter(toAddr(isRebuilt ? rebuilt[isIndex ? 1 : 2] : isIndex ? INDEX : 0x2c61b0));
            executing=true;
            int steps=0, calls=0;
            while (thread.getCounter().getOffset()!=RETURN) {
                long pc=thread.getCounter().getOffset();
                if (isIndex && pc==(isRebuilt ? rebuilt[2] : 0x2c61b0)) {
                    require(++calls==1,"Remainder call count");
                    require(register("r0")==row[3]>>>16 && register("r1")==row[2]-row[1]+1,"Remainder input");
                    require(stateStores==1 && word(memory(STATE,4),0)==row[3],"State before remainder");
                    require((register("sp") & 7)==0,"Remainder stack alignment");
                }
                require(isRebuilt ? within(pc,4,BUILD,BUILD+codeSize) :
                    within(pc,4,0x2c61b0,0x2c62f0) || (isIndex && within(pc,4,INDEX,0x2970bc)),
                    "Unexpected order instruction "+Long.toHexString(pc));
                if (!isRebuilt) visited.add(pc);
                require(++steps<=512,"Order instruction budget");
                monitor.checkCancelled(); thread.stepInstruction();
            }
            require(register(isRebuilt || isIndex ? "r0" : "r1")==row[isIndex ? 4 : 2],
                "Order result mismatch rebuilt="+isRebuilt+" index="+isIndex+" row="+Arrays.toString(row));
            require(calls==(isIndex ? 1 : 0),"Missing remainder call");
            require(stateStores==(isIndex ? 1 : 0),"State write count");
            require(word(memory(STATE,4),0)==(isIndex ? row[3] : initial),"State mismatch");
            require(register("sp")==STACK,"SP not restored");
            for (int r=4;r<=11;++r) require(register("r"+r)==0x12340000L+r,"Saved register");
            maxSteps=Math.max(maxSteps,steps);
        }
    }

    int direct(Path out, String name, boolean index, OrderMachine original, OrderMachine recovered) throws Exception {
        List<String> lines=Files.readAllLines(out.resolve(name+".tsv"));
        int count=0;
        for (String line:lines.subList(1,lines.size())) {
            long[] row=Arrays.stream(line.split("\t")).mapToLong(Long::parseLong).toArray();
            if (index) {
                require(row.length==5 && row[0]>=0 && row[0]<=0xffffffffL && row[1]>=1 && row[1]<=33 && row[2]==66,"Index domain");
                require(row[3]==advance(row[0]) && row[4]==row[1]+(row[3]>>>16)%(67-row[1]),"Index oracle");
            } else {
                require(row.length==3 && row[0]>=0 && row[0]<=65535 && row[1]>=34 && row[1]<=66,"Remainder domain");
                require(row[2]==row[0]%row[1],"Remainder oracle");
            }
            original.compare(false,index,row); recovered.compare(true,index,row); count++;
        }
        return count;
    }

    @Override public void run() throws Exception {
        Path out=Path.of(getScriptArgs()[0]);
        require(!Files.exists(out.resolve("comparison.json")),"Output exists");
        byte[] mapped=new byte[0x377000];
        require(currentProgram.getMemory().getBytes(toAddr(0x100000),mapped)==mapped.length,"Map");
        require(HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(mapped))
            .equals("834938d18d2b7c688311c46c27bed813d0d7a9f8e3cbb61da8a6a3f23d360ebd"),"Hash");
        byte[] binary=Files.readAllBytes(out.resolve("resource-order.bin")); codeSize=binary.length;
        require(codeSize>0 && codeSize<=0x1000,"Binary size");
        List<String> entries=Files.readAllLines(out.resolve("entries.txt"));
        require(entries.size()==3,"Entry count");
        for (int i=0;i<3;++i) {
            rebuilt[i]=Long.parseLong(entries.get(i));
            require(within(rebuilt[i],4,BUILD,BUILD+codeSize),"Entry extent");
        }
        OrderMachine original=new OrderMachine(mapped,binary), recovered=new OrderMachine(mapped,binary);
        int remainderCount=direct(out,"remainders",false,original,recovered);
        println("Remainder cases passed: "+remainderCount);
        int indexCount=direct(out,"indices",true,original,recovered);
        println("Index cases passed: "+indexCount);
        int directMax=maxSteps; maxSteps=0;
        recoverIndex=true;
        BulkMachine bulkOriginal=new BulkMachine(mapped,binary), bulkRecovered=new BulkMachine(mapped,binary);
        Random rng=new Random(0x4651c0);
        List<Long> seeds=new ArrayList<>(List.of(0L,1L,0x7fffffffL,0x80000000L,0xfffffffeL,0xffffffffL));
        for (int i=0;i<64;++i) seeds.add(Integer.toUnsignedLong(rng.nextInt()));
        int count=0;
        try (PrintWriter log=new PrintWriter(Files.newBufferedWriter(out.resolve("bulk-results.tsv")))) {
            log.println("seed\tprofile\tsize_write\tresult_mode\tloads");
            for (long s:seeds) for (int profile=0;profile<6;++profile) {
                seed=s;
                int[] choices=new int[33]; long state=s;
                for (int i=0;i<33;++i) { state=advance(state); choices[i]=i+1+(int)((state>>>16)%(66-i)); }
                byte[] initial=new byte[67*16]; rng.nextBytes(initial);
                for (int id=0;id<67;++id) {
                    int off=id*16; put(initial,off,0x85000000L+id*0x100L);
                    boolean loaded=profile==1 || (profile==5 && rng.nextBoolean());
                    put(initial,off+4,loaded ? 0x89000000L+id*16 : 0);
                    initial[off+12]=(byte)(profile==2 ? 0 : profile==3 ? 128 : profile==4 ? 255 :
                        profile==5 ? new int[]{0,1,128,255}[rng.nextInt(4)] : 1);
                }
                // Vary each backend model independently of the registry profile.
                for (int mode=0;mode<2;++mode) for (int resultMode=0;resultMode<3;++resultMode) {
                    bulkOriginal.compare(false,initial,choices,mode,resultMode);
                    bulkRecovered.compare(true,initial,choices,mode,resultMode);
                    log.printf("%d\t%d\t%d\t%d\t%d%n",s,profile,mode,resultMode,loadOrder(initial,choices).length);
                    count++;
                }
            }
        }
        for (long pc=ENTRY;pc<LIMIT;pc+=4) require(visited.contains(pc),"Unvisited bulk instruction");
        // The signed-endpoint swap and full-width division normalization are
        // outside this positive consumed domain. Export exact coverage, not 100%.
        Files.writeString(out.resolve("coverage.txt"),String.join("\n",visited.stream().map(v->String.format("%08x",v)).toList())+"\n");
        try (PrintWriter listing=new PrintWriter(Files.newBufferedWriter(out.resolve("original-listing.txt")))) {
            for (long[] range:new long[][]{{INDEX,0x2970c4},{0x2c61b0,0x2c62f0}})
                for (long pc=range[0];pc<range[1];pc+=4)
                    listing.printf("%08x %08x %s%n",pc,getInt(toAddr(pc)),getInstructionAt(toAddr(pc)));
        }
        Files.writeString(out.resolve("comparison.json"),String.format(Locale.ROOT,
            "{\"remainder_cases\":%d,\"index_cases\":%d,\"bulk_cases\":%d,\"load_calls\":%d,\"original_instruction_addresses\":%d,\"direct_max_steps\":%d,\"bulk_max_steps\":%d,\"index_intercepted\":false,\"backend_intercepted\":true,\"live_verified\":false}\n",
            remainderCount,indexCount,count,totalLoads,visited.size(),directMax,maxSteps));
        println("SMT4_ORDER_COMPARE_OK");
    }
}
