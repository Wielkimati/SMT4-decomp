// ARM bulk-loader comparison. Index and file dependencies are explicitly modeled.
// Reuses the lifecycle harness's memory guards and register helpers.
// @category SMT4
import ghidra.program.model.lang.RegisterValue;
import ghidra.pcode.emu.PcodeThread;
import ghidra.pcode.utils.Utils;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.pcode.PcodeOp;
import java.math.BigInteger;
import java.nio.file.*;
import java.security.MessageDigest;
import java.util.*;
import java.io.*;

public class CompareResourceBulk extends CompareResourceLifecycle {
    static final long ENTRY = 0x33c8a0, LIMIT = 0x33c958, INDEX = 0x29706c, LOAD = 0x2c3344;
    int totalLoads;
    static final long STATE = 0x4651c0;
    boolean recoverIndex;
    long seed;
    static long advance(long state) { return (state * 0x41c64e6dL + 0x3039) & 0xffffffffL; }
    boolean indexCode(long pc) {
        return within(pc,4,INDEX,0x2970bc) || within(pc,4,0x2c61b0,0x2c62f0);
    }

    // Independent permutation oracle: swap by copying, then filter the final sequence.
    int[] loadOrder(byte[] initial, int[] choices) {
        List<Integer> order = new ArrayList<>();
        for (int i=0;i<67;++i) order.add(i);
        for (int i=0;i<33;++i) Collections.swap(order,i,choices[i]);
        return order.stream().filter(i -> word(initial,i*16+4)==0 && initial[i*16+12]!=0)
                    .mapToInt(Integer::intValue).toArray();
    }

    class BulkMachine extends Machine {
        int stateStores;
        BulkMachine(byte[] mapped, byte[] binary) { super(mapped,binary); }
        @Override public void beforeStore(PcodeThread<byte[]> t, PcodeOp op,
                AddressSpace space, byte[] offset, int size, byte[] value) {
            long a=Utils.bytesToLong(offset,offset.length,false);
            if (recoverIndex && a==STATE && size==4) { stateStores++; return; }
            super.beforeStore(t,op,space,offset,size,value);
        }
        void compare(boolean isRebuilt, byte[] initial, int[] choices, int mode, int resultMode) throws Exception {
            executing=false; stores=0; writableEntry=0x900000;
            stateStores=0;
            if (recoverIndex) writeWord(STATE,seed);
            memory(REG,initial);
            for (var r:currentProgram.getLanguage().getRegisters())
                if (r.isBaseRegister() && !r.isProcessorContext()) register(r,0);
            for (int r=0;r<=12;++r) register("r"+r,0x12340000L+r);
            register("cpsr",0x10); register("sp",STACK); register("lr",RETURN);
            thread.overrideContext(new RegisterValue(currentProgram.getProgramContext().getBaseContextRegister(),BigInteger.ZERO));
            thread.overrideCounter(toAddr(isRebuilt ? rebuilt[0] : ENTRY));
            byte[] expected=initial.clone();
            int[] order=loadOrder(initial,choices);
            int indices=0,loads=0,steps=0;
            long expectedState=seed;
            if (recoverIndex) for (int i=0;i<33;++i) expectedState=advance(expectedState);
            long callState=seed;
            int remainders=0;
            executing=true;
            while (thread.getCounter().getOffset()!=RETURN) {
                long pc=thread.getCounter().getOffset();
                if (recoverIndex && pc==(isRebuilt ? rebuilt[1] : INDEX)) {
                    require(loads==0 && indices<33,"Executed index phase/count");
                    require(register("r0")==indices+1 && register("r1")==66,"Executed index arguments");
                    require(word(memory(STATE,4),0)==callState && stateStores==indices,"State before index");
                    callState=advance(callState);
                    indices++;
                }
                if (recoverIndex && pc==(isRebuilt ? rebuilt[2] : 0x2c61b0)) {
                    require(++remainders==indices,"Remainder count");
                    require(register("r0")==callState>>>16 && register("r1")==67-indices,"Remainder arguments");
                    require(word(memory(STATE,4),0)==callState && stateStores==indices,"State before remainder");
                }
                if ((!recoverIndex && pc==INDEX) || pc==LOAD) {
                    require(Arrays.equals(memory(REG,initial.length),expected),"Registry at dependency entry");
                    require((register("sp") & 7)==0,"Dependency stack alignment");
                    long result;
                    if (pc==INDEX) {
                        require(loads==0 && indices<33,"Index call phase/count");
                        require(register("r0")==indices+1 && register("r1")==66,"Index arguments");
                        result=choices[indices++];
                    } else {
                        if (recoverIndex) {
                            require(stateStores==33 && word(memory(STATE,4),0)==expectedState,"State at load");
                        }
                        require(indices==33 && loads<order.length,"Load call phase/count");
                        int id=order[loads++], off=id*16;
                        writableEntry=REG+off;
                        require(register("r0")==word(expected,off),"Path/order mismatch");
                        require(register("r1")==writableEntry+8 && register("r2")==0,"Load arguments/order");
                        long size=(0xdead0000L+id*0x10203L)&0xffffffffL;
                        result=resultMode==0 || (resultMode==2 && (id&1)==0) ? 0 : 0x81230000L+id*0x100L;
                        if (mode!=0) { writeWord(writableEntry+8,size); put(expected,off+8,size); }
                        put(expected,off+4,result);
                    }
                    long lr=register("lr");
                    for (String r:new String[]{"r0","r1","r2","r3","r12"}) register(r,0xdeadbeefL);
                    register("r0",result);
                    thread.overrideCounter(toAddr(lr));
                    continue;
                }
                require(isRebuilt ? within(pc,4,BUILD,BUILD+codeSize) :
                        within(pc,4,ENTRY,LIMIT) || (recoverIndex && indexCode(pc)),
                        "Unexpected instruction "+Long.toHexString(pc));
                if (!isRebuilt) visited.add(pc);
                require(++steps<=20000,"Instruction budget");
                monitor.checkCancelled(); thread.stepInstruction();
            }
            if (recoverIndex) {
                require(remainders==33,"Missing remainder calls");
                require(stateStores==33 && word(memory(STATE,4),0)==expectedState,"Final state");
            }
            require(indices==33 && loads==order.length,"Missing dependency calls");
            require(register("r0")==1,"Return mismatch");
            require(Arrays.equals(memory(REG,initial.length),expected),"Final registry mismatch");
            require(register("sp")==STACK,"SP not restored");
            for (int r=4;r<=11;++r) require(register("r"+r)==0x12340000L+r,"Saved register");
            maxSteps=Math.max(maxSteps,steps);
            if (!isRebuilt) totalLoads+=loads;
        }
    }

    @Override public void run() throws Exception {
        Path out=Path.of(getScriptArgs()[0]);
        require(!Files.exists(out.resolve("comparison.json")),"Output exists");
        byte[] mapped=new byte[0x377000];
        require(currentProgram.getMemory().getBytes(toAddr(0x100000),mapped)==mapped.length,"Map");
        require(HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(mapped))
            .equals("834938d18d2b7c688311c46c27bed813d0d7a9f8e3cbb61da8a6a3f23d360ebd"),"Hash");
        byte[] binary=Files.readAllBytes(out.resolve("resource-bulk.bin"));
        codeSize=binary.length;
        require(codeSize>0 && codeSize<=0x1000,"Binary size");
        List<String> entries=Files.readAllLines(out.resolve("entries.txt"));
        require(entries.size()==1,"Entry count");
        rebuilt[0]=Long.parseLong(entries.get(0));
        require(within(rebuilt[0],4,BUILD,BUILD+codeSize),"Entry extent");
        BulkMachine original=new BulkMachine(mapped,binary), recovered=new BulkMachine(mapped,binary);
        Random rng=new Random(0x33c8a0);
        List<int[]> schedules=new ArrayList<>();
        int[] low=new int[33], high=new int[33];
        for (int i=0;i<33;++i) { low[i]=i+1; high[i]=66; }
        schedules.add(low); schedules.add(high);
        // Cover every permitted return at every one of the 33 call positions.
        for (int at=0;at<33;++at) for (int v=at+1;v<=66;++v) {
            int[] s=low.clone(); s[at]=v; schedules.add(s);
        }
        for (int n=0;n<64;++n) {
            int[] s=new int[33];
            for (int i=0;i<33;++i) s[i]=i+1+rng.nextInt(66-i);
            schedules.add(s);
        }
        int count=0;
        try (PrintWriter log=new PrintWriter(Files.newBufferedWriter(out.resolve("results.tsv")))) {
            log.println("case\tprofile\tsize_write\tresult_mode\tloads");
            // Six full profiles at the two endpoints; mixed profiles across all choices.
            for (int schedule=0;schedule<schedules.size();++schedule) {
                int profiles=schedule<2 ? 6 : 1;
                for (int p=0;p<profiles;++p) {
                    int profile=schedule<2 ? p : 5;
                    byte[] initial=new byte[67*16]; rng.nextBytes(initial);
                    for (int id=0;id<67;++id) {
                        int off=id*16;
                        put(initial,off,0x85000000L+id*0x100L); // unique path per entry
                        boolean loaded=profile==1 || (profile==5 && rng.nextBoolean());
                        put(initial,off+4,loaded ? 0x89000000L+id*16 : 0);
                        initial[off+12]=(byte)(profile==2 ? 0 : profile==3 ? 128 : profile==4 ? 255 :
                            profile==5 ? new int[]{0,1,128,255}[rng.nextInt(4)] : 1);
                    }
                    int mode=count%2, resultMode=count%3;
                    int[] s=schedules.get(schedule);
                    original.compare(false,initial,s,mode,resultMode);
                    recovered.compare(true,initial,s,mode,resultMode);
                    log.printf("%d\t%d\t%d\t%d\t%d%n",count,profile,mode,resultMode,loadOrder(initial,s).length);
                    count++;
                }
            }
        }
        for (long pc=ENTRY;pc<LIMIT;pc+=4)
            require(visited.contains(pc),"Unvisited original instruction "+Long.toHexString(pc));
        Files.writeString(out.resolve("comparison.json"),String.format(Locale.ROOT,
            "{\"bulk_cases\":%d,\"load_calls\":%d,\"original_instruction_addresses\":%d,\"max_steps\":%d,\"index_intercepted\":true,\"backend_intercepted\":true,\"live_verified\":false}\n",
            count,totalLoads,visited.size(),maxSteps));
        println("SMT4_BULK_COMPARE_OK");
    }
}
