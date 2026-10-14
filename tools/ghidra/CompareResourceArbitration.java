// Compare argument marshalling around an explicit, returning SVC boundary.
// No kernel execution, pointer validity, scheduling or timeout semantics claimed.
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

public class CompareResourceArbitration extends CompareResourceLifecycle {
    static final long ENTRY=0x2a88fc, END=0x2a8914, MASK=0xffffffffL;
    static final long[] WORDS={0,1,0x12345678L,0x7fffffffL,0x80000000L,0x89abcdefL,0xfffffffeL,MASK};
    int cases;
    class ArbitrationMachine extends Machine {
        long entrySp;
        ArbitrationMachine(byte[] mapped,byte[] binary) { super(mapped,binary); }
        @Override public void beforeLoad(PcodeThread<byte[]> t,PcodeOp op,AddressSpace space,byte[] offset,int size) {
            long a=Utils.bytesToLong(offset,offset.length,false);
            require(within(a,size,entrySp-64,entrySp+8),"Unexpected data read "+Long.toHexString(a));
        }
        @Override public void beforeStore(PcodeThread<byte[]> t,PcodeOp op,AddressSpace space,byte[] offset,int size,byte[] value) {
            long a=Utils.bytesToLong(offset,offset.length,false);
            require(within(a,size,entrySp-64,entrySp),"Unexpected write "+Long.toHexString(a));
        }
        long call(boolean rebuiltPath,long[] args,long response,long seed) throws Exception {
            executing=false;
            entrySp=STACK-(seed%2)*0x100;
            Random random=new Random(seed);
            byte[] stack=new byte[0x1080]; random.nextBytes(stack);
            put(stack,(int)(entrySp-STACK+0x1000),args[4]);
            put(stack,(int)(entrySp-STACK+0x1004),args[5]);
            memory(STACK-0x1000,stack);
            for(var r:currentProgram.getLanguage().getRegisters())
                if(r.isBaseRegister() && !r.isProcessorContext()) register(r,0);
            long[] saved=new long[13];
            for(int r=0;r<=12;r++) { saved[r]=Integer.toUnsignedLong(random.nextInt()); register("r"+r,saved[r]); }
            register("cpsr",0x10|((seed&15)<<28)); register("sp",entrySp); register("lr",RETURN);
            for(int r=0;r<4;r++) register("r"+r,args[r]);
            thread.overrideContext(new RegisterValue(currentProgram.getProgramContext().getBaseContextRegister(),BigInteger.ZERO));
            thread.overrideCounter(toAddr(rebuiltPath ? rebuilt[0] : ENTRY)); executing=true;
            int steps=0,calls=0;long payload=0;
            while(thread.getCounter().getOffset()!=RETURN) {
                long pc=thread.getCounter().getOffset();
                require(rebuiltPath ? within(pc,4,BUILD,BUILD+codeSize) : within(pc,4,ENTRY,END),"Unexpected PC");
                if(!rebuiltPath) visited.add(pc);
                require(++steps<=32,"Instruction budget"); monitor.checkCancelled();
                long bits=word(memory(pc,4),0);
                if((bits&0x0f000000L)==0x0f000000L) {
                    require(bits==0xef000022L && ++calls==1,"Wrong SVC/count");
                    for(int r=0;r<6;r++) require(register("r"+r)==args[r],"SVC argument r"+r);
                    require((register("sp")&7)==0 && register("lr")==RETURN,"SVC stack/LR");
                    // Returning-kernel model: stress all argument registers and flags.
                    // r6-r11, SP, LR and memory are preserved by this boundary model.
                    for(int r=0;r<=5;r++) register("r"+r,Integer.toUnsignedLong(random.nextInt()));
                    register("r12",Integer.toUnsignedLong(random.nextInt()));
                    payload=register("r2");register("r0",response); register("cpsr",0xa0000010L);
                    thread.overrideContext(new RegisterValue(currentProgram.getProgramContext().getBaseContextRegister(),BigInteger.ZERO));
                    thread.overrideCounter(toAddr(pc+4));
                } else thread.stepInstruction();
            }
            require(register("r2")==payload,"Arbitration returned r2");
            require(calls==1 && register("r0")==response,"Missing SVC/result changed");
            require(register("sp")==entrySp,"SP restoration");
            for(int r=4;r<=11;r++) require(register("r"+r)==saved[r],"Callee saved r"+r);
            byte[] actual=memory(STACK-0x1000,stack.length);
            for(int i=0;i<stack.length;i++) {
                long a=STACK-0x1000+i;
                if(a<entrySp-64 || a>=entrySp) require(actual[i]==stack[i],"Stack guard/arguments");
            }
            maxSteps=Math.max(maxSteps,steps);
            return register("r0");
        }
    }
    void compare(ArbitrationMachine a,ArbitrationMachine b,PrintWriter log,long[] args,long response) throws Exception {
        long seed=ENTRY+cases;
        try {
            require(a.call(false,args,response,seed)==b.call(true,args,response,seed),"Result difference");
        } catch(Exception ex) { throw new IllegalStateException("Case "+cases+" args="+Arrays.toString(args),ex); }
        log.printf("%d\t%s\t%d%n",++cases,Arrays.toString(args),response);
    }
    @Override public void run() throws Exception {
        Path out=Path.of(getScriptArgs()[0]); require(!Files.exists(out.resolve("comparison.json")),"Existing output");
        byte[] mapped=new byte[0x377000];
        require(currentProgram.getMemory().getBytes(toAddr(0x100000),mapped)==mapped.length,"Map");
        require(HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(mapped)).equals(
            "834938d18d2b7c688311c46c27bed813d0d7a9f8e3cbb61da8a6a3f23d360ebd"),"Hash");
        byte[] binary=Files.readAllBytes(out.resolve("resource-arbitration.bin")); codeSize=binary.length;
        require(codeSize>0 && codeSize<=0x1000,"Binary size");
        List<String> lines=Files.readAllLines(out.resolve("entries.txt")); require(lines.size()==1,"Entries");
        rebuilt[0]=Long.parseLong(lines.get(0)); require(within(rebuilt[0],4,BUILD,BUILD+codeSize),"Entry extent");
        ArbitrationMachine a=new ArbitrationMachine(mapped,binary),b=new ArbitrationMachine(mapped,binary);
        try(PrintWriter log=new PrintWriter(Files.newBufferedWriter(out.resolve("results.tsv")))) {
            log.println("case\targument_words\tresult");
            for(long low:WORDS) for(long high:WORDS) for(long result:WORDS)
                compare(a,b,log,new long[]{WORDS[cases%8],WORDS[(cases/8)%8],WORDS[(cases/64)%8],result,low,high},result);
            for(int slot=0;slot<6;slot++) for(int bit=0;bit<32;bit++) for(int invert=0;invert<2;invert++) {
                long[] args={0x13579bdfL,0x2468ace0L,0x87654321L,0xfedcba98L,0x11223344L,0xaabbccddL};
                args[slot]=((1L<<bit)^(invert==0 ? 0 : MASK));
                compare(a,b,log,args,args[slot]);
            }
            Random random=new Random(ENTRY);
            for(int i=0;i<1024;i++) {
                long[] args=new long[6]; for(int r=0;r<6;r++) args[r]=Integer.toUnsignedLong(random.nextInt());
                compare(a,b,log,args,Integer.toUnsignedLong(random.nextInt()));
            }
        }
        StringBuilder listing=new StringBuilder();
        for(long pc=ENTRY;pc<END;pc+=4) {
            require(visited.contains(pc),"Unvisited original instruction");
            var instruction=currentProgram.getListing().getInstructionAt(toAddr(pc));
            require(instruction!=null,"Missing Ghidra disassembly");
            listing.append(String.format("%08x %s%n",pc,instruction));
        }
        Files.writeString(out.resolve("original-ghidra.txt"),listing);
        Files.writeString(out.resolve("comparison.json"),String.format(Locale.ROOT,
            "{\"arbitration_cases\":%d,\"original_instruction_addresses\":%d,\"max_steps\":%d,\"svc_calls_both_paths\":%d,\"r2_transport_checked\":true,\"svc_intercepted\":true,\"kernel_implemented\":false,\"live_verified\":false}\n",
            cases,visited.size(),maxSteps,2*cases));
        println("SMT4_ARBITRATION_COMPARE_OK");
    }
}
