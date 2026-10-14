// Original/rebuilt instructions with explicit create/wait/string dependency models.
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

public class CompareResourceSync extends CompareResourceLifecycle {
    static final long DESC=0x900000, SIZE=0x901000, PATH=0x902000, MODE=0x465040;
    static final long[] START={0x2c5e90,0x2c3344,0x2b0468,0x2b0478,0x14e744,0x14e634};
    static final long[] STOP ={0x2c5f9c,0x2c334c,0x2b0478,0x2b0494,0x14e760,0x14e648};
    static final long[] EXTERNAL={0x2c3b98,0x2b0674,0x2be850,0x2b0494,0x1181b0};
    long[] entries=new long[6];
    long dependencyCalls;
    boolean recoverPrefix;
    long prefixEntry;
    int directPrefixCases, integratedPrefixCalls, uqsub8Instructions;
    boolean prefixCode(long pc) {
        return recoverPrefix && (within(pc,4,0x2b0674,0x2b0700) || within(pc,4,0x2c32e4,0x2c3340));
    }
    void configurePrefix(Path out) throws Exception {
        recoverPrefix=getScriptArgs().length>1 && getScriptArgs()[1].equals("prefix");
        if(recoverPrefix) {
            prefixEntry=Long.parseLong(Files.readString(out.resolve("prefix-entry.txt")).trim());
            require(within(prefixEntry,4,BUILD,BUILD+codeSize),"Prefix entry extent");
            for(long[] range:new long[][]{{0x2b0674,0x2b0700},{0x2c32e4,0x2c3340}}) {
                var f=getFunctionAt(toAddr(range[0]));
                require(f!=null && f.getBody().getNumAddresses()==range[1]-range[0] &&
                    f.getBody().getMinAddress().getOffset()==range[0] &&
                    f.getBody().getMaxAddress().getOffset()==range[1]-1,"Prefix/length saved membership");
            }
        }
    }
    void prefixEvidence(Path out) throws Exception {
        if(!recoverPrefix)return;
        for(long[] range:new long[][]{{0x2b0674,0x2b0700},{0x2c32e4,0x2c3340}})
            for(long pc=range[0];pc<range[1];pc+=4)require(visited.contains(pc),"Unvisited prefix/length site "+Long.toHexString(pc));
        Files.writeString(out.resolve("prefix-comparison.json"),String.format(Locale.ROOT,
            "{\"direct_pairs\":%d,\"integrated_calls_both_paths\":%d,\"ordered_reads_checked\":true,\"uqsub8_host_instructions\":%d,\"new_contracts\":1,\"reused_length_contracts\":1,\"new_and_reused_sites\":58,\"live_verified\":false}\n",
            directPrefixCases,integratedPrefixCalls,uqsub8Instructions));
    }
    int syncCases, helperCases;
    boolean originalCode(long pc) {
        for(int i=0;i<START.length;i++) if(within(pc,4,START[i],STOP[i])) return true;
        return prefixCode(pc);
    }
    class SyncMachine extends Machine {
        List<String> writes=new ArrayList<>();
        List<String> pathReads=new ArrayList<>(), expectedPathReads=new ArrayList<>();
        long prefixReturn=-1, prefixResult;
        int prefixCalls;
        boolean checkPathReads;
        void preparePrefix(byte[] bytes,int offset,boolean scan) {
            checkPathReads=recoverPrefix;
            if(!recoverPrefix)return;
            int length=0;while(bytes[offset+length]!=0)length++;
            int colon=-1;for(int i=0;i<Math.min(8,length);i++)if(bytes[offset+i]==':'){colon=i;break;}
            prefixResult=colon<0 ? 0 : 1;
            if(!scan)return;
            int cursor=offset;
            while((cursor&3)!=0) {
                expectedPathReads.add((PATH+cursor)+":1");
                if(bytes[cursor++]==0)break;
            }
            if(cursor<=offset+length) {
                for(;;cursor+=4) {
                    expectedPathReads.add((PATH+cursor)+":4");
                    if(cursor+4>offset+length)break;
                }
            }
            for(int i=0;i<(colon<0 ? Math.min(8,length) : colon+1);i++)
                expectedPathReads.add((PATH+offset+i)+":1");
        }
        long boundaryPC(boolean rebuiltPath) {
            long pc=thread.getCounter().getOffset();
            if(recoverPrefix && pc==prefixReturn) {
                require(register("r0")==prefixResult,"Prefix exact result");prefixReturn=-1;
            }
            return recoverPrefix && rebuiltPath && pc==prefixEntry ? 0x2b0674 : pc;
        }
        void beginPrefix() {
            require(prefixReturn==-1 && ++prefixCalls==1,"Prefix call count");
            require(register("r0")==PATH,"Concrete prefix argument");
            prefixReturn=register("lr");integratedPrefixCalls++;
        }
        void checkPrefix(boolean scan) {
            if(!recoverPrefix)return;
            require(prefixReturn==-1 && prefixCalls==(scan ? 1 : 0),"Prefix short circuit/return");
            require(pathReads.equals(expectedPathReads),"Prefix ordered read trace");
        }
        void directPrefix(boolean rebuiltPath,byte[] bytes,int offset) throws Exception {
            initialize(rebuiltPath,0,new byte[0x144]);
            memory(PATH,bytes);preparePrefix(bytes,offset,true);
            register("r0",PATH+offset);
            thread.overrideCounter(toAddr(rebuiltPath ? prefixEntry : 0x2b0674));
            int steps=0;executing=true;
            while(thread.getCounter().getOffset()!=RETURN)step(rebuiltPath,++steps);
            require(register("r0")==prefixResult,"Prefix exact result");
            require(pathReads.equals(expectedPathReads),"Prefix ordered read trace");
            require(writes.isEmpty() && Arrays.equals(bytes,memory(PATH,bytes.length)),"Prefix input preservation");
            finish(steps);
        }
        SyncMachine(byte[] mapped,byte[] binary) { super(mapped,binary); }
        long descriptorAddress() { return DESC; }
        long sizeAddress() { return SIZE; }
        long pathAddress() { return PATH; }
        @Override public void beforeStore(PcodeThread<byte[]> t,PcodeOp op,
                AddressSpace space,byte[] offset,int size,byte[] value) {
            long a=Utils.bytesToLong(offset,offset.length,false);
            if(within(a,size,STACK-0x1000,STACK)) return;
            require(size==4 && (a==SIZE || a==DESC+8 || a==DESC+12 || a==DESC+36 || a==DESC+40),
                    "Unexpected store "+Long.toHexString(a));
            writes.add(Long.toHexString(a)+":"+Long.toHexString(Utils.bytesToLong(value,size,false)));
        }
        @Override public void beforeLoad(PcodeThread<byte[]> t,PcodeOp op,
                AddressSpace space,byte[] offset,int size) {
            long DESC=descriptorAddress(), SIZE=sizeAddress(), PATH=pathAddress();
            long a=Utils.bytesToLong(offset,offset.length,false);
            if(checkPathReads && within(a,size,PATH,PATH+256)) {
                String access=a+":"+size;
                require(pathReads.size()<expectedPathReads.size() && access.equals(expectedPathReads.get(pathReads.size())),
                    "Prefix read boundary/order "+access);
                pathReads.add(access);
            }
            require(within(a,size,DESC,DESC+0x144) || within(a,size,SIZE,SIZE+4) ||
                    within(a,size,PATH,PATH+256) || within(a,size,0x100000,0x477000) ||
                    within(a,size,BUILD,BUILD+codeSize) || within(a,size,STACK-0x1000,STACK),
                    "Unexpected read "+Long.toHexString(a));
        }
        void initialize(boolean rebuiltPath,int kind,byte[] initial) {
            executing=false; writes.clear();
            pathReads.clear();expectedPathReads.clear();prefixReturn=-1;prefixCalls=0;checkPathReads=false;
            memory(DESC,initial); writeWord(SIZE,0xa55a5aa5L);
            byte[] stack=new byte[0x1000]; Arrays.fill(stack,(byte)0x96); memory(STACK-0x1000,stack);
            for(var r:currentProgram.getLanguage().getRegisters())
                if(r.isBaseRegister() && !r.isProcessorContext()) register(r,0);
            for(int r=0;r<=12;r++) register("r"+r,0x12340000L+r);
            register("cpsr",0x10); register("sp",STACK); register("lr",RETURN);
            thread.overrideContext(new RegisterValue(currentProgram.getProgramContext().getBaseContextRegister(),BigInteger.ZERO));
            thread.overrideCounter(toAddr(rebuiltPath ? entries[kind] : START[kind]));
        }
        void finish(int steps) {
            require(register("sp")==STACK,"SP restoration");
            for(int r=4;r<=11;r++) require(register("r"+r)==0x12340000L+r,"Callee-saved register");
            maxSteps=Math.max(maxSteps,steps);
        }
        void step(boolean rebuiltPath,int steps) throws Exception {
            long pc=thread.getCounter().getOffset();
            require(rebuiltPath ? within(pc,4,BUILD,BUILD+codeSize) : originalCode(pc),
                    "Unexpected PC "+Long.toHexString(pc));
            if(!rebuiltPath) visited.add(pc);
            // Concrete mode includes the full word-scanning length helper (paths <= 250 bytes).
            require(steps<=(recoverPrefix ? 4096 : 512),"Instruction budget");
            monitor.checkCancelled();
            if(recoverPrefix && !rebuiltPath && pc==0x2c330c) {
                require(word(memory(pc,4),0)==0xe6621ff1L,"Pinned UQSUB8 encoding");
                long left=register("r2"),right=register("r1"),result=0;
                for(int shift=0;shift<32;shift+=8)
                    result|=(long)Math.max(0,((int)(left>>>shift)&255)-((int)(right>>>shift)&255))<<shift;
                register("r1",result);uqsub8Instructions++;thread.overrideCounter(toAddr(pc+4));return;
            }
            thread.stepInstruction();
        }
        void externalReturn(long result) {
            long lr=register("lr");
            for(String r:new String[]{"r0","r1","r2","r3","r12"}) register(r,0xdeadbeefL);
            register("r0",result);
            register("cpsr",0xa0000010L); // clobber caller condition flags; return to ARM
            thread.overrideContext(new RegisterValue(currentProgram.getProgramContext().getBaseContextRegister(),BigInteger.ZERO));
            thread.overrideCounter(toAddr(lr & ~1L));
        }
        void helper(boolean rebuiltPath,int kind,byte[] initial,long value) throws Exception {
            initialize(rebuiltPath,kind,initial);
            register("r0",DESC); register("r1",value); executing=true;
            int steps=0;
            while(thread.getCounter().getOffset()!=RETURN) step(rebuiltPath,++steps);
            byte[] expected=initial.clone();
            long result=0;
            if(kind==2) put(expected,8,(word(initial,8)+1)&0xffffffffL);
            if(kind==3 || kind==4) {
                result=word(initial,0)==0 ? 1 : 0;
                if(result==1) put(expected,kind==3 ? 36 : 40,value);
            }
            if(kind==5) result=word(initial,0)==5 ? 1 : 0;
            require(Arrays.equals(expected,memory(DESC,expected.length)),"Helper descriptor");
            require(kind==2 || register("r0")==result,"Helper result");
            require(word(memory(SIZE,4),0)==0xa55a5aa5L,"Helper touched size");
            require(writes.size()==(kind==2 || ((kind==3 || kind==4) && result==1) ? 1 : 0),"Helper write count");
            finish(steps);
        }
        void sync(boolean rebuiltPath,int kind,byte[] initial,int mode,long prefix,long flags,
                  boolean hasSize,long terminal,long data,long length,long parameter) throws Exception {
            initialize(rebuiltPath,kind,initial);
            memory(MODE,new byte[]{(byte)mode});
            byte[] path=new byte[256];
            String pathString=recoverPrefix ? prefix==0 ? "12345678:x" : prefix==1 ? "1234567:x" : ":" : "test/table.tbb";
            byte[] pathText=pathString.getBytes(java.nio.charset.StandardCharsets.US_ASCII);
            System.arraycopy(pathText,0,path,0,pathText.length); memory(PATH,path);
            preparePrefix(path,0,mode==0);
            register("r0",PATH); register("r1",hasSize ? SIZE : 0); register("r2",flags); register("r3",parameter);
            long actualParameter=kind==1 ? 4 : parameter;
            List<Long> expectedCalls=new ArrayList<>(List.of(EXTERNAL[0]));
            if(mode==0) expectedCalls.add(EXTERNAL[1]);
            expectedCalls.addAll(List.of(EXTERNAL[2],EXTERNAL[3],EXTERNAL[4]));
            byte[] configured=initial.clone();
            if(word(initial,0)==0) {
                put(configured,36,(flags&1)|((flags&2)<<3)); put(configured,40,actualParameter);
            }
            byte[] completed=configured.clone();
            put(completed,0,terminal); put(completed,12,data); put(completed,24,length);
            byte[] beforeCleanup=completed.clone();
            if(terminal!=5) put(beforeCleanup,12,0);
            byte[] expected=beforeCleanup.clone(); put(expected,8,(word(initial,8)+1)&0xffffffffL);
            int calls=0,steps=0,cleanups=0;
            long buffer=0;
            boolean direct=mode!=0 || prefix!=0;
            executing=true;
            while(thread.getCounter().getOffset()!=RETURN) {
                long pc=boundaryPC(rebuiltPath);
                if(pc==(rebuiltPath ? entries[2] : START[2])) {
                    cleanups++;
                    require(Arrays.equals(beforeCleanup,memory(DESC,initial.length)),"Ownership before cleanup");
                    require(word(memory(SIZE,4),0)==(hasSize ? terminal==5 ? 0 : length : 0xa55a5aa5L),"Size before cleanup");
                }
                int ext=-1; for(int i=0;i<EXTERNAL.length;i++) if(pc==EXTERNAL[i]) ext=i;
                if(ext>=0) {
                    require(calls<expectedCalls.size() && pc==expectedCalls.get(calls++),"Dependency order");
                    require((register("sp")&7)==0,"Dependency stack alignment");
                    if(recoverPrefix && ext==1) {beginPrefix();step(rebuiltPath,++steps);continue;}
                    dependencyCalls++;
                    long result=0;
                    if(ext==0) {
                        buffer=register("r0");
                        require(register("r1")==256 && within(buffer,256,register("sp"),STACK-16),"Scratch buffer");
                        memory(buffer,new byte[256]);
                    } else if(ext==1) {
                        require(register("r0")==PATH,"Prefix argument"); result=prefix;
                    } else if(ext==2) {
                        require(register("r0")==buffer,"Format destination");
                        require(register("r1")== (direct ? PATH : 0x409740),"Format selection");
                        if(!direct) require(register("r2")==PATH,"Format path argument");
                        require(Arrays.equals(memory(buffer,256),new byte[256]),"Scratch was not cleared");
                        byte[] formatted=((direct ? pathString : "rom:/"+pathString)+"\0").getBytes(java.nio.charset.StandardCharsets.US_ASCII);
                        memory(buffer,formatted); result=formatted.length-1;
                    } else if(ext==3) {
                        require(register("r0")==buffer && register("r1")==0,"Create arguments");
                        require(Arrays.equals(memory(DESC,initial.length),initial),"Early descriptor mutation");
                        require(writes.isEmpty(),"Early write"); result=DESC;
                    } else {
                        require(register("r0")==DESC,"Wait argument");
                        require(Arrays.equals(memory(DESC,initial.length),configured),"Configuration before wait");
                        require(word(memory(SIZE,4),0)==0xa55a5aa5L,"Size written before wait");
                        memory(DESC,completed);
                    }
                    externalReturn(result); continue;
                }
                step(rebuiltPath,++steps);
            }
            checkPrefix(mode==0);
            require(calls==expectedCalls.size() && cleanups==1,"Missing dependency/cleanup");
            require(register("r0")== (terminal==5 ? 0 : data),"Load result");
            require(Arrays.equals(memory(DESC,initial.length),expected),"Final descriptor");
            require(Arrays.equals(memory(PATH,256),path),"Input path changed");
            int expectedWrites=(word(initial,0)==0 ? 2 : 0)+(hasSize ? 1 : 0)+(terminal==5 ? 0 : 1)+1;
            require(writes.size()==expectedWrites,"Unexpected write count");
            finish(steps);
        }
    }
    void directPrefixCases(Path out,SyncMachine a,SyncMachine b) throws Exception {
        if(!recoverPrefix)return;
        try(PrintWriter log=new PrintWriter(Files.newBufferedWriter(out.resolve("prefix-results.tsv")))) {
            log.println("pair\toffset\tlength\tcolon\tresult\tordered_accesses");
            for(int offset=0;offset<4;offset++)
            for(int length:new int[]{0,1,2,3,4,5,6,7,8,9,10,15,31,63,247})
            for(int colon=-1;colon<Math.min(length,10);colon++) {
                byte[] bytes=new byte[256];Arrays.fill(bytes,(byte)0xff);
                for(int i=0;i<length;i++)bytes[offset+i]=(byte)(i%2==0 ? 0x80 : 'x');
                bytes[offset+length]=0;bytes[offset+length+1]=':';
                if(colon>=0)bytes[offset+colon]=':';
                a.directPrefix(false,bytes,offset);b.directPrefix(true,bytes,offset);
                require(a.pathReads.equals(b.pathReads),"Direct prefix access trace");directPrefixCases++;
                log.printf("%d\t%d\t%d\t%d\t%d\t%s%n",directPrefixCases,offset,length,colon,a.prefixResult,a.pathReads);
            }
        }
    }
    @Override public void run() throws Exception {
        Path out=Path.of(getScriptArgs()[0]);
        require(!Files.exists(out.resolve("comparison.json")),"Existing output");
        byte[] mapped=new byte[0x377000];
        require(currentProgram.getMemory().getBytes(toAddr(0x100000),mapped)==mapped.length,"Map");
        require(HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(mapped)).equals(
            "834938d18d2b7c688311c46c27bed813d0d7a9f8e3cbb61da8a6a3f23d360ebd"),"Hash");
        byte[] binary=Files.readAllBytes(out.resolve("resource-sync.bin")); codeSize=binary.length;
        require(codeSize>0 && codeSize<=0x1000,"Binary size");
        List<String> lines=Files.readAllLines(out.resolve("entries.txt")); require(lines.size()==6,"Entries");
        for(int i=0;i<6;i++) {
            entries[i]=Long.parseLong(lines.get(i)); require(within(entries[i],4,BUILD,BUILD+codeSize),"Entry extent");
        }
        configurePrefix(out);
        SyncMachine a=new SyncMachine(mapped,binary),b=new SyncMachine(mapped,binary);
        Random rng=new Random(0x2c5e90);
        long[] values={0,1,4,5,0x80,0x7fffffffL,0x80000000L,0xffffffffL};
        try(PrintWriter log=new PrintWriter(Files.newBufferedWriter(out.resolve("results.tsv")))) {
            directPrefixCases(out,a,b);
            log.println("kind\tcase\tstate\tflags_or_value\tterminal\tdata\tsize\tmode\tprefix\thas_size\tparameter");
            for(int kind=2;kind<6;kind++) for(long state:values) for(long value:values)
            for(long counter:new long[]{0,0x7fffffffL,0xffffffffL}) {
                byte[] initial=new byte[0x144]; rng.nextBytes(initial); put(initial,0,state); put(initial,8,counter);
                a.helper(false,kind,initial,value); b.helper(true,kind,initial,value);
                require(a.writes.equals(b.writes),"Helper write trace");
                log.printf("%d\t%d\t%d\t%d%n",kind,++helperCases,state,value);
            }
            for(int kind=0;kind<2;kind++) for(int mode:new int[]{0,1,255})
            for(long prefix:new long[]{0,1,0xffffffffL}) for(long flags:new long[]{0,1,2,3,0xfc,0x80000002L,0xffffffffL})
            for(boolean size:new boolean[]{false,true}) for(long terminal:new long[]{4,5})
            for(long data:new long[]{0,0x81234560L}) for(long parameter:kind==0 ? new long[]{0,4,0x80,0xffffffffL} : new long[]{0xdeadbeefL}) {
                byte[] initial=new byte[0x144]; rng.nextBytes(initial);
                // Include descriptors that refuse setters, though create normally returns state zero.
                long state=syncCases%3==0 ? 1 : 0; put(initial,0,state);
                put(initial,8,syncCases%2==0 ? 0xffffffffL : Integer.toUnsignedLong(rng.nextInt()));
                long length=syncCases%7==0 ? 0 : syncCases%7==1 ? 0xffffffffL : Integer.toUnsignedLong(rng.nextInt());
                a.sync(false,kind,initial,mode,prefix,flags,size,terminal,data,length,parameter);
                b.sync(true,kind,initial,mode,prefix,flags,size,terminal,data,length,parameter);
                require(a.writes.equals(b.writes),"Load write trace");
                log.printf("%d\t%d\t%d\t%d\t%d\t%d\t%d\t%d\t%d\t%b\t%d%n",
                    kind,++syncCases,state,flags,terminal,data,length,mode,prefix,size,parameter);
            }
        }
        for(int i=0;i<6;i++) for(long pc=START[i];pc<STOP[i];pc+=4)
            require(visited.contains(pc),"Unvisited original instruction "+Long.toHexString(pc));
        prefixEvidence(out);
        Files.writeString(out.resolve("visited.txt"),String.join("\n",visited.stream().map(v->String.format("%08x",v)).toList())+"\n");
        Files.writeString(out.resolve("comparison.json"),String.format(Locale.ROOT,
            "{\"sync_cases\":%d,\"helper_cases\":%d,\"original_instruction_addresses\":%d,\"max_steps\":%d,\"dependency_calls_both_paths\":%d,\"create_wait_strings_intercepted\":true,\"live_verified\":false}\n",
            syncCases,helperCases,visited.size(),maxSteps,dependencyCalls));
        if(recoverPrefix) Files.writeString(out.resolve("comparison.json"),
            Files.readString(out.resolve("comparison.json")).replace("create_wait_strings_intercepted","create_wait_clear_format_intercepted"));
        println("SMT4_SYNC_COMPARE_OK");
    }
}
