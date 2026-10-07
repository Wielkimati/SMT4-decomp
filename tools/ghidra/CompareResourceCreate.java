// Descriptor creation with explicit allocator, synchronization and string models.
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

public class CompareResourceCreate extends CompareResourceLifecycle {
    static final long DESC=0x900000, PATH=0x901000, NODES=0x902000;
    static final long HEAD=0x46500c, HANDLE=0x465010, START=0x2b0494, STOP=0x2b0630;
    static final long ACQUIRE=0x2c4350, RELEASE=0x2c54a4, CHECK=0x2c54bc;
    static final long ALLOCATE=0x2c4bd8, CLEAR=0x2c4b84, LENGTH=0x2c32e4;
    static final long COPY=0x2bf8c0, FORMAT=0x2be850;
    long entry, dependencyCalls;
    int cases;
    static void record(List<String> writes,long a,int n,long value) {
        for(int i=0;i<n;i++) writes.add(Long.toHexString(a+i)+":"+((value >>> (i*8))&255));
    }
    class CreateMachine extends Machine {
        List<String> writes=new ArrayList<>();
        int nodes;
        CreateMachine(byte[] mapped,byte[] binary) { super(mapped,binary); }
        @Override public void beforeStore(PcodeThread<byte[]> t,PcodeOp op,
                AddressSpace space,byte[] offset,int size,byte[] value) {
            long a=Utils.bytesToLong(offset,offset.length,false);
            if(within(a,size,STACK-0x1000,STACK)) return;
            require(within(a,size,DESC,DESC+0x144) || within(a,size,HEAD,HEAD+4) ||
                    (nodes>0 && within(a,size,NODES+(nodes-1)*0x200+0x13c,NODES+(nodes-1)*0x200+0x140)),
                    "Unexpected store "+Long.toHexString(a));
            require(size<=8,"Store width");
            record(writes,a,size,Utils.bytesToLong(value,size,false));
        }
        @Override public void beforeLoad(PcodeThread<byte[]> t,PcodeOp op,
                AddressSpace space,byte[] offset,int size) {
            long a=Utils.bytesToLong(offset,offset.length,false);
            require(within(a,size,DESC,DESC+0x144) || within(a,size,PATH,PATH+256) ||
                    within(a,size,NODES,NODES+nodes*0x200) || within(a,size,0x100000,0x477000) ||
                    within(a,size,BUILD,BUILD+codeSize) || within(a,size,STACK-0x1000,STACK),
                    "Unexpected read "+Long.toHexString(a));
        }
        void externalReturn(long result) {
            long lr=register("lr");
            for(String r:new String[]{"r0","r1","r2","r3","r12"}) register(r,0xdeadbeefL);
            register("r0",result); register("cpsr",0xa0000010L);
            thread.overrideContext(new RegisterValue(currentProgram.getProgramContext().getBaseContextRegister(),BigInteger.ZERO));
            thread.overrideCounter(toAddr(lr & ~1L));
        }
        void call(boolean rebuiltPath,byte[] path,int nodeCount,long mode,long acquireResult,
                  long releaseResult,Random rng) throws Exception {
            executing=false; writes.clear(); nodes=nodeCount;
            byte[] initial=new byte[0x144]; rng.nextBytes(initial); memory(DESC,initial);
            byte[] list=new byte[nodes*0x200]; rng.nextBytes(list);
            for(int i=0;i<nodes;i++) {
                put(list,i*0x200+0x13c,i+1<nodes ? NODES+(i+1)*0x200 : 0);
                put(list,i*0x200+0x140,i==0 ? 0 : NODES+(i-1)*0x200);
            }
            memory(NODES,list); writeWord(HEAD,nodes==0 ? 0 : NODES);
            long handle=Integer.toUnsignedLong(rng.nextInt()), laterHandle=handle^0x87654321L;
            writeWord(HANDLE,handle);
            byte[] input=new byte[256]; Arrays.fill(input,(byte)0xd7);
            System.arraycopy(path,0,input,0,path.length); input[path.length]=0; memory(PATH,input);
            byte[] stack=new byte[0x1000]; Arrays.fill(stack,(byte)0x96); memory(STACK-0x1000,stack);
            for(var r:currentProgram.getLanguage().getRegisters())
                if(r.isBaseRegister() && !r.isProcessorContext()) register(r,0);
            for(int r=0;r<=12;r++) register("r"+r,0x12340000L+r);
            register("cpsr",0x10); register("sp",STACK); register("lr",RETURN);
            register("r0",PATH); register("r1",mode);
            thread.overrideContext(new RegisterValue(currentProgram.getProgramContext().getBaseContextRegister(),BigInteger.ZERO));
            thread.overrideCounter(toAddr(rebuiltPath ? entry : START));

            boolean prefix=false;
            for(int i=0;i<Math.min(path.length,8);i++) if(path[i]==':') prefix=true;
            List<Long> calls=new ArrayList<>(); calls.add(ACQUIRE);
            if((acquireResult&0x80000000L)!=0) calls.add(CHECK);
            calls.addAll(List.of(ALLOCATE,CLEAR,LENGTH,prefix ? COPY : FORMAT,RELEASE));
            if((releaseResult&0x80000000L)!=0) calls.add(CHECK);
            byte[] linked=new byte[0x144];
            if(nodes>0) put(linked,0x140,NODES+(nodes-1)*0x200);
            byte[] expected=linked.clone();
            byte[] lead=prefix ? new byte[0] : "rom:/".getBytes(java.nio.charset.StandardCharsets.US_ASCII);
            System.arraycopy(lead,0,expected,0x2c,lead.length);
            System.arraycopy(path,0,expected,0x2c+lead.length,path.length);
            expected[0x20]=(byte)mode; put(expected,4,1); put(expected,0x28,0x80);
            byte[] expectedList=list.clone();
            if(nodes>0) put(expectedList,(nodes-1)*0x200+0x13c,DESC);
            List<String> expectedWrites=new ArrayList<>();
            if(nodes==0) record(expectedWrites,HEAD,4,DESC);
            else {
                record(expectedWrites,NODES+(nodes-1)*0x200+0x13c,4,DESC);
                record(expectedWrites,DESC+0x140,4,NODES+(nodes-1)*0x200);
            }
            for(int offset:new int[]{0,12,16,20,24,0x12c,8}) record(expectedWrites,DESC+offset,4,0);
            record(expectedWrites,DESC+0x20,1,mode&255);
            record(expectedWrites,DESC+0x28,4,0x80); record(expectedWrites,DESC+4,4,1);
            int next=0,steps=0; long lastResult=0;
            executing=true;
            while(thread.getCounter().getOffset()!=RETURN) {
                long pc=thread.getCounter().getOffset();
                if(List.of(ACQUIRE,RELEASE,CHECK,ALLOCATE,CLEAR,LENGTH,COPY,FORMAT).contains(pc)) {
                    require(next<calls.size() && calls.get(next++)==pc,"Dependency order at "+Long.toHexString(pc));
                    require((register("sp")&7)==0,"Dependency stack alignment"); dependencyCalls++;
                    long result=0;
                    if(pc==ACQUIRE) {
                        require(within(register("r0"),4,register("sp"),STACK-16),"Acquire output");
                        require(within(register("r1"),4,register("sp"),STACK-16),"Acquire handle pointer");
                        require(word(memory(register("r1"),4),0)==handle,"Acquire handle");
                        require(register("r2")==1 && register("r3")==0,"Acquire count/mode");
                        require(word(memory(register("sp"),8),0)==0xffffffffL &&
                                word(memory(register("sp"),8),4)==0xffffffffL,"Acquire timeout");
                        require(writes.isEmpty() && Arrays.equals(memory(DESC,0x144),initial),"Early mutation");
                        writeWord(register("r0"),0x13579bdf); result=acquireResult;
                        // Proves release rereads the global handle rather than retaining its first value.
                        writeWord(HANDLE,laterHandle); lastResult=result;
                    } else if(pc==CHECK) {
                        require(register("r0")==lastResult && register("r1")==1,"Result handler arguments");
                    } else if(pc==ALLOCATE) {
                        require(register("r0")==0x100 && register("r1")==0x100 && register("r2")==0 &&
                                register("r3")==0x144 && word(memory(register("sp"),4),0)==1,"Allocation arguments");
                        require(writes.isEmpty(),"Write before allocation"); result=DESC;
                    } else if(pc==CLEAR) {
                        require(register("r0")==DESC && register("r1")==0x144,"Clear arguments");
                        require(writes.isEmpty() && Arrays.equals(memory(DESC,0x144),initial),"Write before clear");
                        memory(DESC,new byte[0x144]);
                    } else if(pc==LENGTH || pc==COPY || pc==FORMAT) {
                        require(Arrays.equals(memory(DESC,0x144),linked),"Descriptor before strings");
                        require(Arrays.equals(memory(NODES,list.length),expectedList),"Append before strings");
                        require(word(memory(HEAD,4),0)==(nodes==0 ? DESC : NODES),"Head before strings");
                        if(pc==LENGTH) { require(register("r0")==PATH,"Length argument"); result=path.length; }
                        else {
                            require(register("r0")==DESC+0x2c,"Stored path destination");
                            require(register("r1")== (prefix ? PATH : 0x2b066c),"String source/format");
                            if(!prefix) require(register("r2")==PATH,"Format path");
                            byte[] formatted=new byte[lead.length+path.length+1];
                            System.arraycopy(lead,0,formatted,0,lead.length);
                            System.arraycopy(path,0,formatted,lead.length,path.length);
                            memory(DESC+0x2c,formatted); result=prefix ? DESC+0x2c : formatted.length-1;
                        }
                    } else {
                        require(within(register("r0"),4,register("sp"),STACK-16),"Release output");
                        require(register("r1")==laterHandle,"Release must reload handle");
                        require(Arrays.equals(memory(DESC,0x144),expected),"Descriptor before release");
                        writeWord(register("r0"),0x2468ace0); result=releaseResult; lastResult=result;
                    }
                    externalReturn(result); continue;
                }
                require(rebuiltPath ? within(pc,4,BUILD,BUILD+codeSize) : within(pc,4,START,STOP),
                        "Unexpected PC "+Long.toHexString(pc));
                if(!rebuiltPath) visited.add(pc);
                require(++steps<=512,"Instruction budget"); monitor.checkCancelled(); thread.stepInstruction();
            }
            require(next==calls.size(),"Missing dependency"); require(register("r0")==DESC,"Return descriptor");
            require(Arrays.equals(memory(DESC,0x144),expected),"Final descriptor");
            require(Arrays.equals(memory(NODES,list.length),expectedList),"Final list");
            require(Arrays.equals(memory(PATH,256),input),"Input preservation");
            require(word(memory(HEAD,4),0)==(nodes==0 ? DESC : NODES),"Final head");
            require(word(memory(HANDLE,4),0)==laterHandle,"Handle preservation");
            Collections.sort(writes); Collections.sort(expectedWrites);
            require(writes.equals(expectedWrites),"Store multiset (including redundant zero stores)");
            require(register("sp")==STACK,"SP restoration");
            for(int r=4;r<=11;r++) require(register("r"+r)==0x12340000L+r,"Callee-saved register");
            maxSteps=Math.max(maxSteps,steps);
        }
    }
    @Override public void run() throws Exception {
        Path out=Path.of(getScriptArgs()[0]); require(!Files.exists(out.resolve("comparison.json")),"Existing output");
        byte[] mapped=new byte[0x377000];
        require(currentProgram.getMemory().getBytes(toAddr(0x100000),mapped)==mapped.length,"Map");
        require(HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(mapped)).equals(
            "834938d18d2b7c688311c46c27bed813d0d7a9f8e3cbb61da8a6a3f23d360ebd"),"Hash");
        byte[] binary=Files.readAllBytes(out.resolve("resource-create.bin")); codeSize=binary.length;
        require(codeSize>0 && codeSize<=0x1000,"Binary size");
        List<String> lines=Files.readAllLines(out.resolve("entries.txt")); require(lines.size()==1,"Entries");
        entry=Long.parseLong(lines.get(0)); require(within(entry,4,BUILD,BUILD+codeSize),"Entry extent");
        CreateMachine a=new CreateMachine(mapped,binary),b=new CreateMachine(mapped,binary);
        List<byte[]> paths=new ArrayList<>();
        for(int length=0;length<=10;length++) for(int colon=-1;colon<length;colon++) paths.add(path(length,colon));
        for(int length:new int[]{31,127,250}) for(int colon:new int[]{-1,0,7,8,length-1}) paths.add(path(length,colon));
        for(int colon:new int[]{0,3,7}) paths.add(path(255,colon));
        require(paths.size()==84,"Path corpus");
        long[][] results={{0,0},{1,0x7fffffffL},{0x80000000L,0},{0,0xffffffffL},{0xffffffffL,0x80000000L}};
        try(PrintWriter log=new PrintWriter(Files.newBufferedWriter(out.resolve("results.tsv")))) {
            log.println("case\tpath_case\tnodes\tmode\tacquire_result\trelease_result");
            for(int p=0;p<paths.size();p++) for(int count:new int[]{0,1,2,7})
            for(long mode:new long[]{0,1,255,256,0x800000abL,0xffffffffL}) for(long[] status:results) {
                long seed=0x2b0494L+cases;
                a.call(false,paths.get(p),count,mode,status[0],status[1],new Random(seed));
                b.call(true,paths.get(p),count,mode,status[0],status[1],new Random(seed));
                require(a.writes.equals(b.writes),"Original/rebuilt stores");
                log.printf("%d\t%d\t%d\t%d\t%d\t%d%n",++cases,p,count,mode,status[0],status[1]);
            }
        }
        for(long pc=START;pc<STOP;pc+=4) require(visited.contains(pc),"Unvisited original instruction "+Long.toHexString(pc));
        Files.writeString(out.resolve("visited.txt"),String.join("\n",visited.stream().map(v->String.format("%08x",v)).toList())+"\n");
        Files.writeString(out.resolve("comparison.json"),String.format(Locale.ROOT,
            "{\"create_cases\":%d,\"original_instruction_addresses\":%d,\"max_steps\":%d,\"dependency_calls_both_paths\":%d,\"allocation_sync_strings_intercepted\":true,\"live_verified\":false}\n",
            cases,visited.size(),maxSteps,dependencyCalls));
        println("SMT4_CREATE_COMPARE_OK");
    }
    static byte[] path(int length,int colon) {
        byte[] path=new byte[length]; Arrays.fill(path,(byte)'x');
        if(colon>=0) path[colon]=':'; return path;
    }
}
