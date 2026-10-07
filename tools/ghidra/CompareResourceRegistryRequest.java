// Registry submission and completion execute on retained memory; dispatch is modeled.
// @category SMT4
import ghidra.pcode.emu.PcodeThread;
import ghidra.pcode.utils.Utils;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.pcode.PcodeOp;
import java.nio.file.*;
import java.security.MessageDigest;
import java.util.*;
import java.io.*;

public class CompareResourceRegistryRequest extends CompareResourceSync {
    static final long HEAD=0x46500c, HANDLE=0x465010, POOL=0x910000, PACKETS=0x920000, PATHS=0x930000;
    static final long ACQUIRE=0x2c4350, RELEASE=0x2c54a4, CHECK=0x2c54bc;
    static final long ALLOC=0x2c4bd8, CLEAR=0x2c4b84, LENGTH=0x2c32e4;
    static final long COPY=0x2bf8c0, FORMAT=0x2be850, PREFIX=0x2b0674, FREE=0x2c43b4;
    static final long[][] RANGES={{0x33c844,0x33c898},{0x19f990,0x19f99c},
        {0x2ae72c,0x2ae834},{0x2b6820,0x2b6840},{0x155b30,0x155bd8},
        {0x2b0468,0x2b0630},{0x14e634,0x14e648},{0x14e744,0x14e760}};
    static final long HEAP=0x465120, HEAP_ACQUIRE=0x2c3afc, HEAP_RELEASE=0x2c3a78;
    static final long CONVERT=0x1245f0, HEAP_FREE=0x1244e8, MASK=0xffffffffL;
    long[] linked=new long[5];
    boolean recoverRelease;
    int releaseExecutions, directReleases, convertedReleases;
    int scenarios, submissions, completions, skipped;
    @Override boolean originalCode(long pc) {
        if(recoverRelease && within(pc,4,FREE,0x2c4424)) return true;
        for(long[] range:RANGES) if(within(pc,4,range[0],range[1])) return true;
        return false;
    }
    static byte[] z(String s) { return (s+"\0").getBytes(java.nio.charset.StandardCharsets.US_ASCII); }
    static boolean prefix(String s) { int i=s.indexOf(':'); return i>=0 && i<8; }
    static String[] PATH_TEXT={"", "test/table.tbb", "rom:/test.tbb", "1234567:x", "12345678:x", "x".repeat(250)};
    static long[] releaseRanges(long packet,int profile) {
        // Pairs are base/length; exact boundaries, exclusions and overflowing endpoints.
        return switch(profile) {
            case 0 -> new long[]{packet,24,0,0};
            case 1 -> new long[]{packet-24,24,0,0};
            case 2 -> new long[]{0,0,packet,24};
            case 3 -> new long[]{0,0,packet-24,24};
            case 4 -> new long[]{packet+1,24,packet+1,0};
            case 5 -> new long[]{packet-25,24,packet-1,0};
            case 6 -> new long[]{packet-1,MASK,0,0};
            case 7 -> new long[]{0,0,packet-1,MASK};
            case 8 -> new long[]{packet-1,2,packet-2,4};
            case 9 -> new long[]{0,MASK,0,0};
            case 10 -> new long[]{packet,0,0,0};
            case 11 -> new long[]{0,0,packet,0};
            default -> throw new IllegalArgumentException("Release profile");
        };
    }
    static boolean directRelease(long packet,long[] ranges) {
        for(int i=0;i<4;i+=2) {
            long end=ranges[i]+ranges[i+1];
            if(end<=MASK && packet>=ranges[i] && packet<=end) return true;
        }
        return false;
    }

    class RegistryMachine extends SyncMachine {
        final Map<Long,byte[]> expected=new LinkedHashMap<>();
        final List<String> want=new ArrayList<>(), registryWrites=new ArrayList<>(), wantRegistry=new ArrayList<>();
        final List<Long> descriptors=new ArrayList<>();
        final List<Integer> ids=new ArrayList<>();
        final List<Boolean> freed=new ArrayList<>();
        boolean rebuiltPath;
        int mode, initialNodes;
        long seed, handle;
        RegistryMachine(byte[] mapped,byte[] binary) { super(mapped,binary); }
        @Override public void beforeLoad(PcodeThread<byte[]> t,PcodeOp op,AddressSpace space,byte[] offset,int size) {
            long a=Utils.bytesToLong(offset,offset.length,false);
            boolean allowed=within(a,size,0x100000,0x477000) || within(a,size,BUILD,BUILD+codeSize) || within(a,size,STACK-0x1000,STACK);
            for(var r:expected.entrySet()) allowed|=within(a,size,r.getKey(),r.getKey()+r.getValue().length);
            require(allowed,"Unexpected integrated read "+Long.toHexString(a));
        }
        @Override public void beforeStore(PcodeThread<byte[]> t,PcodeOp op,AddressSpace space,byte[] offset,int size,byte[] value) {
            long a=Utils.bytesToLong(offset,offset.length,false);
            if(within(a,size,STACK-0x1000,STACK)) return;
            boolean allowed=within(a,size,REG,REG+67*16) || within(a,size,HEAD,HEAD+4);
            for(long d:descriptors) allowed|=within(a,size,d,d+0x144);
            for(int i=0;i<ids.size();i++) allowed|=within(a,size,packetAddress(i),packetAddress(i)+24);
            require(allowed,"Unexpected integrated store "+Long.toHexString(a));
            long v=Utils.bytesToLong(value,size,false);
            CompareResourceCreate.record(writes,a,size,v);
            if(within(a,size,REG,REG+67*16)) CompareResourceCreate.record(registryWrites,a,size,v);
        }
        void region(long address,int size,Random rng) {
            byte[] bytes=new byte[size]; rng.nextBytes(bytes); expected.put(address,bytes); memory(address,bytes);
        }
        void set(long address,int size,long value,boolean store) {
            for(var r:expected.entrySet()) if(within(address,size,r.getKey(),r.getKey()+r.getValue().length)) {
                int offset=(int)(address-r.getKey());
                for(int i=0;i<size;i++) r.getValue()[offset+i]=(byte)(value >>> (i*8));
                if(store) {
                    CompareResourceCreate.record(want,address,size,value);
                    if(within(address,size,REG,REG+67*16)) CompareResourceCreate.record(wantRegistry,address,size,value);
                }
                return;
            }
            throw new IllegalStateException("Missing oracle region");
        }
        void setBytes(long address,byte[] bytes) {
            for(int i=0;i<bytes.length;i++) set(address+i,1,bytes[i]&255,false);
        }
        void compareMemory(String stage) {
            for(var r:expected.entrySet()) require(Arrays.equals(memory(r.getKey(),r.getValue().length),r.getValue()),
                stage+" memory/guards at "+Long.toHexString(r.getKey()));
        }
        void setup(boolean rebuilt,int pathMode,long caseSeed,int nodes) {
            rebuiltPath=rebuilt; seed=caseSeed; mode=pathMode; initialNodes=nodes;
            executing=false; expected.clear(); descriptors.clear(); ids.clear(); freed.clear();
            Random rng=new Random(seed); region(REG-16,67*16+32,rng); region(PATHS,67*256,rng);
            for(int id=0;id<67;id++) {
                set(REG+id*16,4,PATHS+id*256,false); set(REG+id*16+4,4,0,false); set(REG+id*16+12,1,0,false);
                setBytes(PATHS+id*256,z(PATH_TEXT[(id+(int)(seed%6))%6]));
            }
            region(HEAD,4,rng); region(HANDLE,4,rng); region(MODE,1,rng);
            if(recoverRelease) region(HEAP-16,0x60,rng);
            set(MODE,1,mode,false); handle=0xfedcba98L; set(HANDLE,4,handle,false);
            for(int i=0;i<nodes;i++) {
                long d=POOL+i*0x400; region(d-16,0x164,rng); descriptors.add(d);
                set(d+0x13c,4,i+1<nodes ? d+0x400 : 0,false); set(d+0x140,4,i==0 ? 0 : d-0x400,false);
            }
            set(HEAD,4,nodes==0 ? 0 : POOL,false);
            for(var r:expected.entrySet()) memory(r.getKey(),r.getValue());
        }
        void entryState(long id,long address,int policy) {
            set(REG+id*16+4,4,address,false); set(REG+id*16+12,1,policy,false);
            memory(REG-16,expected.get(REG-16));
        }
        void begin(long pc,long arg) {
            executing=false; writes.clear(); want.clear(); registryWrites.clear(); wantRegistry.clear();
            byte[] stack=new byte[0x1000]; Arrays.fill(stack,(byte)0x96); memory(STACK-0x1000,stack);
            for(var r:currentProgram.getLanguage().getRegisters()) if(r.isBaseRegister() && !r.isProcessorContext()) register(r,0);
            for(int r=0;r<=12;r++) register("r"+r,0x12340000L+r);
            register("sp",STACK-16); register("lr",RETURN); register("cpsr",0x10);
            register("s16",0x81234567L); register("s17",0xfedcba98L); register("r0",arg);
            thread.overrideContext(new ghidra.program.model.lang.RegisterValue(currentProgram.getProgramContext().getBaseContextRegister(),java.math.BigInteger.ZERO));
            thread.overrideCounter(toAddr(pc)); executing=true;
        }
        void end(int steps) {
            compareMemory("Final");
            Collections.sort(writes); Collections.sort(want); require(writes.equals(want),"Integrated external stores");
            require(registryWrites.equals(wantRegistry),"Registry publication order");
            require(register("sp")==STACK-16,"SP restoration");
            for(int r=4;r<=11;r++) require(register("r"+r)==0x12340000L+r,"Callee-saved register");
            require(register("s16")==0x81234567L && register("s17")==0xfedcba98L,"d8 preservation");
            byte[] caller=new byte[16]; Arrays.fill(caller,(byte)0x96);
            require(Arrays.equals(memory(STACK-16,16),caller),"Caller stack preservation");
            maxSteps=Math.max(maxSteps,steps);
        }
        String string(long address) {
            byte[] b=memory(address,256); int n=0; while(n<b.length && b[n]!=0) n++;
            require(n<256,"Unterminated modeled string"); return new String(b,0,n,java.nio.charset.StandardCharsets.US_ASCII);
        }
        long packetAddress(int index) { return PACKETS+index*0x100; }
        long newDescriptorAddress(int index) { return POOL+descriptors.size()*0x400; }
        void allocationRegion(long address,int size,Random rng) { region(address-16,size+32,rng); }
        void allocated(long address,int size) { }
        long allocationEntry() { return ALLOC; }
        boolean executeAllocation(long address,int size) throws Exception {
            allocated(address,size); return false;
        }
        void submit(long id) throws Exception {
            boolean valid=id<67;
            long e=REG+id*16, prior=valid ? word(memory(e+4,4),0) : 0;
            boolean eligible=valid && prior==0 && memory(e+12,1)[0]==0;
            long result=valid && (prior!=0 || eligible) ? 1 : 0;
            begin(rebuiltPath ? linked[0] : 0x33c844,id);
            int steps=0;
            if(!eligible) {
                while(thread.getCounter().getOffset()!=RETURN) step(rebuiltPath,++steps);
                require(register("r0")==result,"Skipped registry result"); end(steps); skipped++; return;
            }
            int index=ids.size(); ids.add((int)id); freed.add(false);
            long packet=packetAddress(index), descriptor=newDescriptorAddress(index);
            long tail=descriptors.isEmpty() ? 0 : descriptors.get(descriptors.size()-1);
            descriptors.add(descriptor);
            Random rng=new Random(seed+index+123); allocationRegion(packet,24,rng); allocationRegion(descriptor,0x144,rng);
            String path=string(PATHS+id*256), formatted=mode!=0 || prefix(path) ? path : "rom:/"+path;
            String stored=prefix(formatted) ? formatted : "rom:/"+formatted;
            long acquire=(seed%2==0 ? 0 : 0x80000001L), release=(seed%3==0 ? 0xffffffffL : 0);
            List<Long> calls=new ArrayList<>(List.of(CLEAR));
            if(mode==0) calls.add(PREFIX);
            calls.addAll(List.of(FORMAT,ALLOC,ACQUIRE)); if(acquire!=0) calls.add(CHECK);
            calls.addAll(List.of(ALLOC,CLEAR,LENGTH,prefix(formatted) ? COPY : FORMAT,RELEASE));
            if(release!=0) calls.add(CHECK);
            int next=0,allocs=0,clears=0,formats=0,callbacks=0; long buffer=0,lastResult=0;
            boolean constructed=false;
            while(thread.getCounter().getOffset()!=RETURN) {
                long pc=thread.getCounter().getOffset();
                if(pc==allocationEntry()) pc=ALLOC;
                if(pc==(rebuiltPath ? linked[3] : 0x2b0494)) {
                    require(++callbacks==1 && register("r0")==buffer && register("r1")==0,"Integrated constructor arguments");
                    set(packet+4,4,rebuiltPath ? linked[1] : 0x19f990,true);
                    set(packet+8,4,e,true); set(packet+12,4,0,true); set(packet+16,4,4,true); set(packet+20,4,e+4,true);
                    set(e+4,4,0,true); compareMemory("Before constructor");
                }
                if(List.of(CLEAR,PREFIX,FORMAT,ALLOC,ACQUIRE,CHECK,LENGTH,COPY,RELEASE).contains(pc)) {
                    require(next<calls.size() && calls.get(next++)==pc,"Integrated dependency order");
                    require((register("sp")&7)==0,"Boundary alignment"); dependencyCalls++; long ret=0;
                    if(pc==CLEAR) {
                        if(clears++==0) {
                            buffer=register("r0"); require(register("r1")==256 && within(buffer,256,register("sp"),STACK-16),"Request buffer");
                            memory(buffer,new byte[256]);
                        } else {
                            require(register("r0")==descriptor && register("r1")==0x144,"Descriptor clear");
                            compareMemory("Before descriptor clear"); memory(descriptor,new byte[0x144]); setBytes(descriptor,new byte[0x144]);
                        }
                    } else if(pc==PREFIX) {
                        require(register("r0")==PATHS+id*256,"Prefix path"); ret=prefix(path) ? 1 : 0;
                    } else if(pc==FORMAT && formats++==0) {
                        boolean direct=mode!=0 || prefix(path);
                        require(register("r0")==buffer && register("r1")== (direct ? PATHS+id*256 : 0x409740),"Request format");
                        if(!direct) require(register("r2")==PATHS+id*256,"Request format source");
                        require(Arrays.equals(memory(buffer,256),new byte[256]),"Request clear before format");
                        memory(buffer,z(formatted)); ret=formatted.length();
                    } else if(pc==ALLOC) {
                        boolean packetAllocation=allocs++==0;
                        require(register("r0")==256 && register("r1")==256 && register("r2")==0 &&
                            register("r3")== (packetAllocation ? 24 : 0x144) && word(memory(register("sp"),4),0)==(packetAllocation ? 0 : 1),"Allocation arguments");
                        compareMemory("Before allocation"); ret=packetAllocation ? packet : descriptor;
                        if(executeAllocation(ret,packetAllocation ? 24 : 0x144)) continue;
                    } else if(pc==ACQUIRE) {
                        require(within(register("r0"),4,register("sp"),STACK-16) && within(register("r1"),4,register("sp"),STACK-16),"Acquire outputs");
                        require(word(memory(register("r1"),4),0)==handle && register("r2")==1 && register("r3")==0,"Acquire arguments");
                        require(word(memory(register("sp"),4),0)==0xffffffffL && word(memory(register("sp")+4,4),0)==0xffffffffL,"Acquire timeout");
                        writeWord(register("r0"),0x13579bdf); handle^=0x87654321L; writeWord(HANDLE,handle); set(HANDLE,4,handle,false);
                        ret=lastResult=acquire;
                    } else if(pc==CHECK) {
                        require(register("r0")==lastResult && register("r1")==1,"Result arguments");
                    } else if(pc==LENGTH) {
                        if(tail==0) set(HEAD,4,descriptor,true);
                        else { set(tail+0x13c,4,descriptor,true); set(descriptor+0x140,4,tail,true); }
                        compareMemory("List append"); require(register("r0")==buffer && string(buffer).equals(formatted),"Constructor path"); ret=formatted.length();
                    } else if(pc==COPY || pc==FORMAT) {
                        require(register("r0")==descriptor+0x2c && register("r1")== (pc==COPY ? buffer : 0x2b066c),"Constructor string destination/source");
                        if(pc==FORMAT) require(register("r2")==buffer,"Constructor format input");
                        memory(descriptor+0x2c,z(stored)); setBytes(descriptor+0x2c,z(stored)); ret=pc==COPY ? descriptor+0x2c : stored.length();
                    } else {
                        require(within(register("r0"),4,register("sp"),STACK-16) && register("r1")==handle,"Release reloaded handle");
                        for(int offset:new int[]{0,12,16,20,24,0x12c,8}) set(descriptor+offset,4,0,true);
                        set(descriptor+0x20,1,0,true); set(descriptor+40,4,128,true); set(descriptor+4,4,1,true);
                        compareMemory("Before constructor release"); writeWord(register("r0"),0x2468ace0); ret=lastResult=release; constructed=true;
                    }
                    externalReturn(ret); continue;
                }
                step(rebuiltPath,++steps);
            }
            require(constructed && next==calls.size() && callbacks==1 && register("r0")==1,"Submission return/boundaries");
            set(descriptor+0x130,4,rebuiltPath ? linked[2] : 0x155b30,true); set(descriptor+0x134,4,packet,true);
            set(packet,4,descriptor,true); set(descriptor+36,4,0,true); set(descriptor+40,4,4,true);
            end(steps); submissions++;
        }
        void complete(int index,long state,long data,long length) throws Exception {
            complete(index,state,data,length,(int)((seed+index)%12),(int)((seed+index)%3));
        }
        void heapRanges(long[] ranges) {
            int[] offsets={0x24,0x34,0x28,0x38};
            for(int i=0;i<4;i++) {
                writeWord(HEAP+offsets[i],ranges[i]); set(HEAP+offsets[i],4,ranges[i],false);
            }
        }
        void complete(int index,long state,long data,long length,int profile,int effect) throws Exception {
            require(!freed.get(index),"Fixture dispatched freed packet");
            long d=descriptors.get(initialNodes+index), packet=PACKETS+index*0x100, e=REG+ids.get(index)*16;
            // Explicit worker model: no worker instructions or scheduler are claimed.
            for(int offset:new int[]{0,12,24}) {
                long value=offset==0 ? state : offset==12 ? data : length;
                writeWord(d+offset,value); set(d+offset,4,value,false);
            }
            long callback=word(memory(d+0x130,4),0), context=word(memory(d+0x134,4),0);
            require(callback==(rebuiltPath ? linked[2] : 0x155b30) && context==packet,"Stored dispatch fields");
            long[] ranges=releaseRanges(packet,profile);
            boolean direct=directRelease(packet,ranges);
            long lockBefore=0,lockAfter=0,converted=new long[]{0,1,0x80000000L,MASK}[profile%4];
            List<Long> lower=new ArrayList<>(List.of(HEAP_ACQUIRE));
            if(!direct) lower.add(CONVERT);
            lower.add(HEAP_FREE); lower.add(HEAP_RELEASE);
            if(recoverRelease) {
                lockBefore=word(memory(HEAP+4,4),0); lockAfter=lockBefore^0x88888888L;
                long[] before=effect==0 ? ranges : effect==1 ? new long[]{packet,0,packet,0} :
                    new long[]{packet+1,0,packet+1,0};
                heapRanges(before);
            }
            begin(callback,context);
            long address=state==5 ? 0 : data, size=state==5 ? 0 : length;
            set(e+4,4,address,true);
            int steps=0,callbacks=0,frees=0,lowerCalls=0;
            while(thread.getCounter().getOffset()!=RETURN) {
                long pc=thread.getCounter().getOffset();
                if(pc==(rebuiltPath ? linked[1] : 0x19f990)) {
                    require(++callbacks==1 && register("r0")==address && register("r1")==e && register("r2")==size,"Registry callback arguments");
                    compareMemory("Output publication before callback");
                    set(e+4,4,address,true); set(e+8,4,size,true);
                }
                if(pc==(recoverRelease && rebuiltPath ? linked[4] : FREE)) {
                    require(++frees==1 && callbacks==1 && register("r0")==packet,"Packet release/order");
                    if(state!=5) set(d+12,4,0,true);
                    set(d+8,4,1,true); compareMemory("Ownership before packet release");
                    if(!recoverRelease) { externalReturn(0x55555555L); continue; }
                    releaseExecutions++;
                    if(direct) directReleases++; else convertedReleases++;
                }
                if(recoverRelease && List.of(HEAP_ACQUIRE,CONVERT,HEAP_FREE,HEAP_RELEASE).contains(pc)) {
                    require(frees==1 && lowerCalls<lower.size() && lower.get(lowerCalls++)==pc,"Integrated release dependency order");
                    long arg=pc==HEAP_ACQUIRE ? lockBefore : pc==HEAP_RELEASE ? lockAfter :
                        pc==CONVERT || direct ? packet : converted;
                    require(register("r0")==arg,"Integrated release dependency argument at "+Long.toHexString(pc));
                    require((register("sp")&7)==0,"Integrated release boundary alignment");
                    compareMemory("Before allocator dependency"); dependencyCalls++;
                    if(pc==HEAP_ACQUIRE) heapRanges(ranges);
                    if(pc==HEAP_FREE) {
                        writeWord(HEAP+4,lockAfter); set(HEAP+4,4,lockAfter,false);
                    }
                    externalReturn(pc==CONVERT ? converted : 0x55555555L); continue;
                }
                step(rebuiltPath,++steps);
            }
            require(callbacks==1 && frees==1 && (!recoverRelease || lowerCalls==lower.size()),"Completion boundaries");
            end(steps); freed.set(index,true); completions++;
        }
    }
    @Override public void run() throws Exception {
        Path out=Path.of(getScriptArgs()[0]); require(!Files.exists(out.resolve("comparison.json")),"Existing output");
        byte[] mapped=new byte[0x377000];
        require(currentProgram.getMemory().getBytes(toAddr(0x100000),mapped)==mapped.length,"Map");
        require(HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(mapped)).equals(
            "834938d18d2b7c688311c46c27bed813d0d7a9f8e3cbb61da8a6a3f23d360ebd"),"Hash");
        byte[] binary=Files.readAllBytes(out.resolve("registry-request.bin")); codeSize=binary.length;
        require(codeSize>0 && codeSize<=0x2000,"Binary extent");
        List<String> lines=Files.readAllLines(out.resolve("entries.txt")); require(lines.size()==4 || lines.size()==5,"Entries");
        recoverRelease=lines.size()==5;
        for(int i=0;i<lines.size();i++) { linked[i]=Long.parseLong(lines.get(i)); require(within(linked[i],4,BUILD,BUILD+codeSize),"Entry extent"); }
        RegistryMachine[] machines={new RegistryMachine(mapped,binary),new RegistryMachine(mapped,binary)};
        try(PrintWriter log=new PrintWriter(Files.newBufferedWriter(out.resolve("results.tsv")))) {
            log.println("scenario\tkind\tid");
            for(int id=0;id<67;id++) for(int policy:new int[]{0,1,128,255}) for(long loaded:new long[]{0,0x81234560L}) {
                for(int side=0;side<2;side++) {
                    RegistryMachine m=machines[side]; m.setup(side==1,scenarios%3==0 ? 255 : 0,0x334400L+scenarios,scenarios%4);
                    m.entryState(id,loaded,policy); m.submit(id);
                    if(loaded==0 && policy==0) m.complete(0,4,0x81234560L,0xffffffffL);
                }
                log.printf("%d\teligibility\t%d%n",++scenarios,id);
            }
            for(int id=0;id<67;id++) for(int mode:new int[]{0,1,255}) for(int outcome=0;outcome<3;outcome++) {
                for(int side=0;side<2;side++) {
                    RegistryMachine m=machines[side]; m.setup(side==1,mode,0x334400L+scenarios,scenarios%4);
                    m.submit(id); m.complete(0,outcome==2 ? 5 : 4,outcome==1 ? 0 : 0xffffffffL,
                        outcome==0 ? 0 : outcome==1 ? 0x80000000L : 0xffffffffL);
                    // A completed nonnull pointer suppresses another request.
                    if(outcome==0) m.submit(id);
                }
                log.printf("%d\tcompletion\t%d%n",++scenarios,id);
            }
            for(int order=0;order<6;order++) for(int variant=0;variant<4;variant++) {
                int[][] permutations={{0,1,2},{0,2,1},{1,0,2},{1,2,0},{2,0,1},{2,1,0}};
                for(int side=0;side<2;side++) {
                    RegistryMachine m=machines[side]; m.setup(side==1,variant%2==0 ? 0 : 255,0x334400L+scenarios,variant);
                    m.submit(0); m.submit(0); m.submit(66);
                    for(int index:permutations[order]) m.complete(index,index==variant ? 5 : 4,
                        index==1 ? 0 : 0x80000000L+index,0xffffffffL-index);
                    for(long id:new long[]{67,68,0x7fffffffL,0x80000000L,0xffffffffL}) m.submit(id);
                }
                log.printf("%d\tretained-requests\t0%n",++scenarios);
            }
            if(recoverRelease) for(int profile=0;profile<12;profile++) for(int effect=0;effect<3;effect++) for(int outcome=0;outcome<3;outcome++) {
                for(int side=0;side<2;side++) {
                    RegistryMachine m=machines[side]; m.setup(side==1,profile%2,0x334400L+scenarios,effect);
                    m.submit(1); m.complete(0,outcome==2 ? 5 : 4,outcome==1 ? 0 : 0x81234560L,
                        0xffffffffL,profile,effect);
                }
                log.printf("%d\trelease-profile-%d-effect-%d-outcome-%d\t1%n",++scenarios,profile,effect,outcome);
            }
        }
        // Visiting a predicated instruction does not claim every condition outcome.
        for(int i=0;i<RANGES.length;i++) for(long pc=RANGES[i][0];pc<RANGES[i][1];pc+=4)
            require(visited.contains(pc),"Unvisited integrated instruction "+Long.toHexString(pc));
        if(recoverRelease) {
            for(long pc=FREE;pc<0x2c4424;pc+=4) require(visited.contains(pc),"Unvisited release instruction "+Long.toHexString(pc));
            require(releaseExecutions==completions && directReleases>0 && convertedReleases>0,"Release execution counts");
        }
        Files.writeString(out.resolve("visited.txt"),String.join("\n",visited.stream().map(v->String.format("%08x",v)).toList())+"\n");
        Files.writeString(out.resolve("comparison.json"),String.format(Locale.ROOT,
            "{\"scenarios\":%d,\"submissions_both_paths\":%d,\"completions_both_paths\":%d,\"skipped_calls_both_paths\":%d,\"original_instruction_addresses\":%d,\"max_steps\":%d,\"lower_dependency_calls_both_paths\":%d,\"release_executions_both_paths\":%d,\"direct_releases_both_paths\":%d,\"converted_releases_both_paths\":%d,\"release_routing_executed\":%b,\"worker_dispatch_modeled\":true,\"live_verified\":false}\n",
            scenarios,submissions,completions,skipped,visited.size(),maxSteps,dependencyCalls,
            releaseExecutions,directReleases,convertedReleases,recoverRelease));
        println("SMT4_REGISTRY_REQUEST_COMPARE_OK");
    }
}
