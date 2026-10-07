// Allocation wrapper: lower allocation, zeroing and recursive locks modeled.
// @category SMT4
import ghidra.pcode.emu.PcodeThread;
import ghidra.pcode.utils.Utils;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.pcode.PcodeOp;
import java.nio.file.*;
import java.security.MessageDigest;
import java.util.*;
import java.io.*;

public class CompareResourceAllocate extends CompareResourceSync {
    static final long ENTRY=0x2c4bd8, END=0x2c4c40, STATE=0x465120, MASK=0xffffffffL;
    static final long ACQUIRE=0x2c3afc, RELEASE=0x2c3a78, LOWER=0x2c5544, ZERO=0x2c3b9c;
    int cases, nullCases, zeroSizeCases;
    @Override boolean originalCode(long pc) { return within(pc,4,ENTRY,END); }
    class AllocateMachine extends SyncMachine {
        List<String> trace=new ArrayList<>();
        AllocateMachine(byte[] mapped,byte[] binary) { super(mapped,binary); }
        @Override public void beforeStore(PcodeThread<byte[]> t,PcodeOp op,AddressSpace space,
                byte[] offset,int size,byte[] value) {
            long a=Utils.bytesToLong(offset,offset.length,false);
            require(within(a,size,STACK-64,STACK),"Unexpected allocation store "+Long.toHexString(a));
        }
        @Override public void beforeLoad(PcodeThread<byte[]> t,PcodeOp op,AddressSpace space,
                byte[] offset,int size) {
            long a=Utils.bytesToLong(offset,offset.length,false);
            require(within(a,size,STACK-64,STACK+4) || within(a,size,STATE,STATE+0x3c) ||
                within(a,size,ENTRY,END+4) || within(a,size,BUILD,BUILD+codeSize),
                "Unexpected allocation read "+Long.toHexString(a));
        }
        void call(boolean rebuiltPath,long[] args,long result,int effect,long seed) throws Exception {
            initialize(rebuiltPath,0,new byte[0x144]);
            Random rng=new Random(seed); byte[] state=new byte[0x60]; rng.nextBytes(state);
            long lock=word(state,20);
            memory(STATE-16,state);
            byte[] upper=new byte[64]; rng.nextBytes(upper); put(upper,0,args[4]); memory(STACK,upper);
            byte[] stack=memory(STACK-0x1000,0x1000);
            for(int i=0;i<4;i++) register("r"+i,args[i]);
            register("s16",0x81234567L); register("s17",0xfedcba98L);
            thread.overrideCounter(toAddr(rebuiltPath ? entries[0] : ENTRY));
            List<Long> expected=new ArrayList<>(List.of(ACQUIRE,LOWER));
            if(result!=0) expected.add(ZERO);
            expected.add(RELEASE);
            int calls=0,steps=0; trace.clear(); executing=true;
            while(thread.getCounter().getOffset()!=RETURN) {
                long pc=thread.getCounter().getOffset();
                if(pc==ACQUIRE || pc==LOWER || pc==ZERO || pc==RELEASE) {
                    require(calls<expected.size() && expected.get(calls++)==pc,"Allocation dependency order");
                    require((register("sp")&7)==0,"Dependency stack alignment");
                    require(Arrays.equals(state,memory(STATE-16,state.length)),"State before dependency");
                    if(pc==ACQUIRE || pc==RELEASE) {
                        require(register("r0")==lock,"Allocation lock argument");
                        trace.add(Long.toHexString(pc)+":"+lock);
                    } else if(pc==LOWER) {
                        for(int i=0;i<4;i++) require(register("r"+i)==args[i],"Forwarded allocation argument "+i);
                        require(word(memory(register("sp"),4),0)==args[4],"Forwarded fifth allocation argument");
                        trace.add("lower:"+Arrays.toString(args));
                    } else {
                        require(register("r0")==result && register("r1")==args[3],"Allocation zero arguments");
                        trace.add("zero:"+result+":"+args[3]);
                    }
                    dependencyCalls++;
                    // Independently vary which lower call changes the lock handle.
                    if((effect==1 && pc==ACQUIRE) || (effect==2 && pc==LOWER) ||
                       (effect==3 && pc==ZERO) || (effect==4 && pc!=RELEASE)) {
                        lock=(lock^pc^0x87654321L)&MASK;
                        put(state,20,lock); memory(STATE-16,state);
                    }
                    // Clobber volatile VFP registers too: original saves fifth in s16.
                    for(int i=0;i<16;i++) register("s"+i,Integer.toUnsignedLong(rng.nextInt()));
                    externalReturn(pc==LOWER ? result : (result^0xface9876L)&MASK);
                    continue;
                }
                step(rebuiltPath,++steps);
            }
            require(calls==expected.size(),"Missing allocation dependency");
            require(register("r0")==result,"Allocation result preservation");
            require(Arrays.equals(state,memory(STATE-16,state.length)),"Final state/guards");
            require(Arrays.equals(upper,memory(STACK,upper.length)),"Caller stack/fifth argument changed");
            byte[] actual=memory(STACK-0x1000,0x1000);
            for(int i=0;i<stack.length-64;i++) require(stack[i]==actual[i],"Stack guard");
            require(register("s16")==0x81234567L && register("s17")==0xfedcba98L,"d8 preservation");
            finish(steps);
        }
    }
    void compare(AllocateMachine a,AllocateMachine b,PrintWriter log,long[] args,long result,int effect) throws Exception {
        try {
            a.call(false,args,result,effect,ENTRY+cases);
            b.call(true,args,result,effect,ENTRY+cases);
            require(a.trace.equals(b.trace),"Call trace difference");
        } catch(Exception ex) {
            throw new IllegalStateException("Case "+cases+" args="+Arrays.toString(args)+" result="+result+" effect="+effect,ex);
        }
        if(result==0) nullCases++;
        if(args[3]==0) zeroSizeCases++;
        log.printf("%d\t%s\t%d\t%d%n",++cases,Arrays.toString(args),result,effect);
    }
    @Override public void run() throws Exception {
        Path out=Path.of(getScriptArgs()[0]); require(!Files.exists(out.resolve("comparison.json")),"Existing output");
        byte[] mapped=new byte[0x377000];
        require(currentProgram.getMemory().getBytes(toAddr(0x100000),mapped)==mapped.length,"Map");
        require(HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(mapped)).equals(
            "834938d18d2b7c688311c46c27bed813d0d7a9f8e3cbb61da8a6a3f23d360ebd"),"Hash");
        byte[] binary=Files.readAllBytes(out.resolve("resource-allocate.bin")); codeSize=binary.length;
        require(codeSize>0 && codeSize<=0x1000,"Binary size");
        List<String> lines=Files.readAllLines(out.resolve("entries.txt")); require(lines.size()==1,"Entries");
        entries[0]=Long.parseLong(lines.get(0)); require(within(entries[0],4,BUILD,BUILD+codeSize),"Entry extent");
        AllocateMachine a=new AllocateMachine(mapped,binary),b=new AllocateMachine(mapped,binary);
        long[] values={0,1,3,4,24,127,128,256,324,0x20000,0x30000,0x7fffffffL,0x80000000L,MASK};
        long[] results={0,1,0x900003,0x80000000L,MASK};
        try(PrintWriter log=new PrintWriter(Files.newBufferedWriter(out.resolve("results.tsv")))) {
            log.println("case\targuments\tresult\tlock_effect");
            // One argument at a time, with distinct full-width sentinels in the others.
            for(int slot=0;slot<5;slot++) for(long value:values) for(long result:results) for(int effect=0;effect<5;effect++) {
                long[] args={0x10203040,0x50607080,0x90a0b0c0L,0xd0e0f000L,0xfedcba98L};
                args[slot]=value; compare(a,b,log,args,result,effect);
            }
            // Actual descriptor and callback request shapes, including simulated failure.
            for(long[] args:new long[][]{{256,256,0,324,1},{256,256,0,24,0}})
                for(long result:results) for(int effect=0;effect<5;effect++) compare(a,b,log,args,result,effect);
            Random rng=new Random(ENTRY);
            for(int i=0;i<1024;i++) {
                long[] args=new long[5]; for(int j=0;j<5;j++) args[j]=Integer.toUnsignedLong(rng.nextInt());
                compare(a,b,log,args,i%4==0 ? 0 : Integer.toUnsignedLong(rng.nextInt()),i%5);
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
            "{\"allocate_cases\":%d,\"null_cases\":%d,\"zero_size_cases\":%d,\"original_instruction_addresses\":%d,\"max_steps\":%d,\"dependency_calls_both_paths\":%d,\"lower_dependencies_modeled\":true,\"live_verified\":false}\n",
            cases,nullCases,zeroSizeCases,visited.size(),maxSteps,dependencyCalls));
        println("SMT4_ALLOCATE_COMPARE_OK");
    }
}
