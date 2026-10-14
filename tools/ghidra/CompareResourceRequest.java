// Asynchronous orchestration with modeled allocation/create/strings/callback/free.
// @category SMT4
import ghidra.pcode.emu.PcodeThread;
import ghidra.pcode.utils.Utils;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.pcode.PcodeOp;
import java.nio.file.*;
import java.security.MessageDigest;
import java.util.*;
import java.io.*;

public class CompareResourceRequest extends CompareResourceSync {
    static final long PACK=0x904000, OTHER=0x905000, CALLBACK=0x710000;
    static final long CLEAR=0x2c4b84, ALLOC=0x2c4bd8, CREATE=0x2b0494, FREE=0x2c43b4;
    static final long[] REQUEST={0x2ae72c,0x2b6820,0x155bbc,0x155b30};
    static final long[] LIMIT={0x2ae834,0x2b6840,0x155bd8,0x155bbc};
    long[] recovered=new long[8];
    int requestCases, createCases, completionCases;
    @Override boolean originalCode(long pc) {
        for(int i=0;i<4;i++) if(within(pc,4,REQUEST[i],LIMIT[i])) return true;
        for(int i=2;i<6;i++) if(within(pc,4,START[i],STOP[i])) return true;
        return prefixCode(pc);
    }
    static byte[] z(String s) { return CompareResourceChain.z(s); }
    static boolean prefix(String s) { return CompareResourceChain.prefix(s); }
    class RequestMachine extends SyncMachine {
        List<Long> calls=new ArrayList<>();
        RequestMachine(byte[] mapped,byte[] binary) { super(mapped,binary); }
        @Override public void beforeLoad(PcodeThread<byte[]> t,PcodeOp op,AddressSpace space,byte[] offset,int size) {
            long a=Utils.bytesToLong(offset,offset.length,false);
            if(within(a,size,PACK,PACK+24) || within(a,size,OTHER,OTHER+0x144)) return;
            super.beforeLoad(t,op,space,offset,size);
        }
        @Override public void beforeStore(PcodeThread<byte[]> t,PcodeOp op,AddressSpace space,byte[] offset,int size,byte[] value) {
            long a=Utils.bytesToLong(offset,offset.length,false);
            if(within(a,size,STACK-0x1000,STACK)) return;
            require(within(a,size,PACK,PACK+24) || within(a,size,DESC,DESC+0x144) ||
                within(a,size,OTHER,OTHER+0x144) || within(a,size,SIZE,SIZE+4),"Unexpected request store");
            CompareResourceCreate.record(writes,a,size,Utils.bytesToLong(value,size,false));
        }
        void setup(boolean rebuiltPath,int kind,byte[] descriptor,long seed) {
            initialize(rebuiltPath,0,descriptor); calls.clear();
            Random rng=new Random(seed); byte[] packet=new byte[56]; rng.nextBytes(packet); memory(PACK-16,packet);
            byte[] other=new byte[0x144]; rng.nextBytes(other); memory(OTHER,other);
            byte[] output=new byte[36]; rng.nextBytes(output); put(output,16,0xa55a5aa5L); memory(SIZE-16,output);
            register("sp",STACK-16); register("s16",0x81234567L); register("s17",0xfedcba98L);
            thread.overrideCounter(toAddr(rebuiltPath ? recovered[kind] : REQUEST[kind]));
        }
        void done(int steps,byte[] callerStack) {
            require(register("sp")==STACK-16,"SP restoration");
            for(int r=4;r<=11;r++) require(register("r"+r)==0x12340000L+r,"Callee-saved register");
            require(register("s16")==0x81234567L && register("s17")==0xfedcba98L,"d8 preservation");
            require(Arrays.equals(memory(STACK-16,16),callerStack),"Caller stack preservation");
            maxSteps=Math.max(maxSteps,steps);
        }
        void checkWrites(List<String> expected) {
            Collections.sort(writes); Collections.sort(expected); require(writes.equals(expected),"External stores");
        }
        void request(boolean rebuiltPath,int kind,String path,int mode,long flags,boolean out,boolean callback,long state,long parameter,long seed) throws Exception {
            Random rng=new Random(seed); byte[] descriptor=new byte[0x144]; rng.nextBytes(descriptor); put(descriptor,0,state);
            setup(rebuiltPath,kind,descriptor,seed);
            byte[] packetGuard=memory(PACK-16,56), outputGuard=memory(SIZE-16,36), other=memory(OTHER,0x144);
            byte[] packet=Arrays.copyOfRange(packetGuard,16,40);
            long context=seed%3==0 ? 0 : seed%3==1 ? 0x80000000L : 0xffffffffL;
            long completion=rebuiltPath ? recovered[3] : REQUEST[3];
            long actualParameter=kind==1 ? 4 : parameter;
            for(int offset:new int[]{4,8,12,16,20}) put(packet,offset,
                offset==4 ? callback ? CALLBACK : 0 : offset==8 ? context : offset==12 ? flags : offset==16 ? actualParameter : out ? SIZE : 0);
            byte[] input=new byte[256]; Arrays.fill(input,(byte)0xd7); System.arraycopy(z(path),0,input,0,path.length()+1);
            memory(PATH,input); memory(MODE,new byte[]{(byte)mode});
            preparePrefix(input,0,mode==0);
            register("r0",PATH); register("r1",out ? SIZE : 0); register("r2",flags); register("r3",callback ? CALLBACK : 0);
            writeWord(STACK-16,context); writeWord(STACK-12,parameter); byte[] callerStack=memory(STACK-16,16);
            List<Long> expectedCalls=new ArrayList<>(List.of(CLEAR));
            if(mode==0) expectedCalls.add(0x2b0674L);
            expectedCalls.addAll(List.of(0x2be850L,ALLOC,CREATE));
            String formatted=mode!=0 || prefix(path) ? path : "rom:/"+path;
            long buffer=0; int steps=0; executing=true;
            while(thread.getCounter().getOffset()!=RETURN) {
                long pc=boundaryPC(rebuiltPath);
                if(expectedCalls.contains(pc)) {
                    require(calls.size()<expectedCalls.size() && pc==expectedCalls.get(calls.size()),"Request boundary order");
                    calls.add(pc); require((register("sp")&7)==0,"Boundary stack alignment");
                    if(recoverPrefix && pc==0x2b0674) {beginPrefix();step(rebuiltPath,++steps);continue;}
                    dependencyCalls++; long result=0;
                    if(pc==CLEAR) {
                        buffer=register("r0"); require(register("r1")==256 && within(buffer,256,register("sp"),STACK-16),"Request scratch");
                        memory(buffer,new byte[256]);
                    } else if(pc==0x2b0674) {
                        require(register("r0")==PATH,"Prefix argument"); result=prefix(path) ? 0xffffffffL : 0;
                    } else if(pc==0x2be850) {
                        boolean direct=mode!=0 || prefix(path);
                        require(register("r0")==buffer && register("r1")== (direct ? PATH : 0x409740),"Request format");
                        if(!direct) require(register("r2")==PATH,"Request format path");
                        require(Arrays.equals(memory(buffer,256),new byte[256]),"Request scratch clearing");
                        memory(buffer,z(formatted)); result=formatted.length();
                    } else if(pc==ALLOC) {
                        require(register("r0")==256 && register("r1")==256 && register("r2")==0 && register("r3")==24 && word(memory(register("sp"),4),0)==0,"Packet allocation arguments");
                        require(writes.isEmpty(),"Write before packet allocation"); result=PACK;
                    } else {
                        require(register("r0")==buffer && register("r1")==0,"Callback constructor arguments");
                        require(Arrays.equals(memory(buffer,formatted.length()+1),z(formatted)),"Constructor path");
                        require(Arrays.equals(memory(PACK,24),packet),"Packet before constructor");
                        require(word(memory(SIZE,4),0)==(out ? 0 : 0xa55a5aa5L),"Output cleared before constructor");
                        require(Arrays.equals(memory(DESC,descriptor.length),descriptor),"Descriptor before constructor");
                        result=DESC;
                    }
                    externalReturn(result); continue;
                }
                step(rebuiltPath,++steps);
            }
            checkPrefix(mode==0);
            require(calls.equals(expectedCalls),"Missing request boundary");
            List<String> expectedWrites=new ArrayList<>();
            put(packet,0,DESC);
            for(int i=0;i<24;i+=4) CompareResourceCreate.record(expectedWrites,PACK+i,4,word(packet,i));
            put(descriptor,0x130,completion); put(descriptor,0x134,PACK);
            CompareResourceCreate.record(expectedWrites,DESC+0x130,4,completion); CompareResourceCreate.record(expectedWrites,DESC+0x134,4,PACK);
            if(state==0) {
                put(descriptor,36,(flags&1)|((flags&2)<<3)); put(descriptor,40,actualParameter);
                CompareResourceCreate.record(expectedWrites,DESC+36,4,word(descriptor,36)); CompareResourceCreate.record(expectedWrites,DESC+40,4,actualParameter);
            }
            if(out) { put(outputGuard,16,0); CompareResourceCreate.record(expectedWrites,SIZE,4,0); }
            System.arraycopy(packet,0,packetGuard,16,24);
            require(Arrays.equals(memory(PACK-16,56),packetGuard),"Final packet/guards");
            require(Arrays.equals(memory(DESC,descriptor.length),descriptor),"Final request descriptor");
            require(Arrays.equals(memory(SIZE-16,36),outputGuard),"Request output/guards");
            require(Arrays.equals(memory(PATH,256),input) && Arrays.equals(memory(OTHER,other.length),other),"Request input preservation");
            require(memory(MODE,1)[0]==(byte)mode,"Request mode preservation");
            checkWrites(expectedWrites); done(steps,callerStack);
        }
        void create(boolean rebuiltPath,long mode,long callback,long context,long seed) throws Exception {
            byte[] descriptor=new byte[0x144]; new Random(seed).nextBytes(descriptor);
            setup(rebuiltPath,2,descriptor,seed);
            register("r0",PATH); register("r1",mode); register("r2",callback); register("r3",context);
            byte[] callerStack=memory(STACK-16,16); int steps=0,creates=0; executing=true;
            while(thread.getCounter().getOffset()!=RETURN) {
                if(thread.getCounter().getOffset()==CREATE) {
                    require(++creates==1 && register("r0")==PATH && register("r1")==mode && writes.isEmpty(),"Direct callback constructor");
                    externalReturn(DESC); continue;
                }
                step(rebuiltPath,++steps);
            }
            put(descriptor,0x130,callback); put(descriptor,0x134,context);
            require(creates==1 && register("r0")==DESC && Arrays.equals(memory(DESC,descriptor.length),descriptor),"Callback constructor result");
            List<String> expected=new ArrayList<>(); CompareResourceCreate.record(expected,DESC+0x130,4,callback); CompareResourceCreate.record(expected,DESC+0x134,4,context);
            checkWrites(expected); done(steps,callerStack);
        }
        void complete(boolean rebuiltPath,long state,boolean out,boolean callback,long data,long length,int effect,long counter,long seed) throws Exception {
            byte[] descriptor=new byte[0x144]; new Random(seed).nextBytes(descriptor);
            put(descriptor,0,state); put(descriptor,8,counter); put(descriptor,12,data); put(descriptor,24,length);
            setup(rebuiltPath,3,descriptor,seed);
            byte[] packetGuard=memory(PACK-16,56), outputGuard=memory(SIZE-16,36), other=memory(OTHER,0x144);
            byte[] packet=Arrays.copyOfRange(packetGuard,16,40); long context=seed%2==0 ? 0 : 0xffffffffL;
            put(packet,0,DESC); put(packet,4,callback ? CALLBACK : 0); put(packet,8,context); put(packet,20,out ? SIZE : 0); memory(PACK,packet);
            register("r0",PACK); byte[] callerStack=memory(STACK-16,16);
            boolean failed=state==5; int steps=0,callbacks=0,frees=0;
            List<String> expectedWrites=new ArrayList<>();
            if(out) { put(outputGuard,16,failed ? 0 : data); CompareResourceCreate.record(expectedWrites,SIZE,4,failed ? 0 : data); }
            byte[] beforeCallback=descriptor.clone(); executing=true;
            while(thread.getCounter().getOffset()!=RETURN) {
                long pc=thread.getCounter().getOffset();
                if(pc==CALLBACK) {
                    require(callback && ++callbacks==1 && register("r0")== (failed ? 0 : data) && register("r1")==context && register("r2")== (failed ? 0 : length),"Completion callback arguments");
                    require(Arrays.equals(memory(DESC,descriptor.length),beforeCallback),"Detach/cleanup before callback");
                    require(Arrays.equals(memory(SIZE-16,36),outputGuard),"Publication before callback");
                    require(Arrays.equals(memory(PACK,24),packet),"Packet before callback");
                    if(effect==1) { put(packet,0,OTHER); memory(PACK,packet); }
                    if(effect==2) { put(descriptor,12,0xcafebabeL); memory(DESC,descriptor); }
                    externalReturn(0xabcdef01L); continue;
                }
                if(pc==FREE) {
                    require(++frees==1 && register("r0")==PACK && callbacks==(callback ? 1 : 0),"Packet release/order");
                    if(!failed) { put(descriptor,12,0); CompareResourceCreate.record(expectedWrites,DESC+12,4,0); }
                    long cleanup=word(packet,0); byte[] target=cleanup==DESC ? descriptor : other;
                    put(target,8,(word(target,8)+1)&0xffffffffL); CompareResourceCreate.record(expectedWrites,cleanup+8,4,word(target,8));
                    require(Arrays.equals(memory(DESC,descriptor.length),descriptor) && Arrays.equals(memory(OTHER,other.length),other),"Completion ownership/cleanup");
                    require(Arrays.equals(memory(PACK,24),packet),"Completion packet preservation");
                    externalReturn(0x55555555L); continue;
                }
                step(rebuiltPath,++steps);
            }
            require(frees==1 && callbacks==(callback ? 1 : 0),"Completion boundary counts");
            System.arraycopy(packet,0,packetGuard,16,24);
            require(Arrays.equals(memory(PACK-16,56),packetGuard) && Arrays.equals(memory(SIZE-16,36),outputGuard),"Completion guards");
            checkWrites(expectedWrites); done(steps,callerStack);
        }
    }
    @Override public void run() throws Exception {
        Path out=Path.of(getScriptArgs()[0]); require(!Files.exists(out.resolve("comparison.json")),"Existing output");
        byte[] mapped=new byte[0x377000];
        require(currentProgram.getMemory().getBytes(toAddr(0x100000),mapped)==mapped.length,"Map");
        require(HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(mapped)).equals(
            "834938d18d2b7c688311c46c27bed813d0d7a9f8e3cbb61da8a6a3f23d360ebd"),"Hash");
        byte[] binary=Files.readAllBytes(out.resolve("resource-request.bin")); codeSize=binary.length;
        require(codeSize>0 && codeSize<=0x1000,"Binary extent");
        List<String> lines=Files.readAllLines(out.resolve("entries.txt")); require(lines.size()==8,"Entries");
        for(int i=0;i<8;i++) { recovered[i]=Long.parseLong(lines.get(i)); require(within(recovered[i],4,BUILD,BUILD+codeSize),"Entry extent"); }
        configurePrefix(out);
        RequestMachine a=new RequestMachine(mapped,binary),b=new RequestMachine(mapped,binary);
        directPrefixCases(out,a,b);
        String[] paths={"", "test/table.tbb", "rom:/test.tbb", "1234567:x", "12345678:x", "x".repeat(250)};
        long[] values={0,1,4,5,0x80,0x7fffffffL,0x80000000L,0xffffffffL};
        try(PrintWriter log=new PrintWriter(Files.newBufferedWriter(out.resolve("results.tsv")))) {
            log.println("kind\tcase\tseed");
            for(int kind=0;kind<2;kind++) for(String path:paths) for(int mode:new int[]{0,1,255})
            for(long flags:new long[]{0,1,2,3,0xfc,0x80000002L,0xffffffffL})
            for(boolean output:new boolean[]{false,true}) for(boolean callback:new boolean[]{false,true}) for(long state:new long[]{0,5}) {
                long seed=0x2ae72c00L+requestCases, parameter=values[requestCases%values.length];
                a.request(false,kind,path,mode,flags,output,callback,state,parameter,seed);
                b.request(true,kind,path,mode,flags,output,callback,state,parameter,seed);
                require(a.calls.equals(b.calls),"Request boundary trace"); log.printf("request-%d\t%d\t%d%n",kind,++requestCases,seed);
            }
            for(long mode:new long[]{0,1,0xffffffffL}) for(long callback:new long[]{0,CALLBACK,CALLBACK+1,0xffffffffL})
            for(long context:new long[]{0,1,0x80000000L,0xffffffffL}) {
                long seed=0x155bbc00L+createCases;
                a.create(false,mode,callback,context,seed); b.create(true,mode,callback,context,seed);
                require(a.writes.equals(b.writes),"Constructor writes"); log.printf("create\t%d\t%d%n",++createCases,seed);
            }
            for(long state:values) for(boolean output:new boolean[]{false,true}) for(boolean callback:new boolean[]{false,true})
            for(long data:new long[]{0,0x81234560L,0xffffffffL}) for(long length:new long[]{0,0x80000000L,0xffffffffL})
            for(int effect:callback ? new int[]{0,1,2} : new int[]{0}) for(long counter:new long[]{0,0x7fffffffL,0xffffffffL}) {
                long seed=0x155b3000L+completionCases;
                a.complete(false,state,output,callback,data,length,effect,counter,seed);
                b.complete(true,state,output,callback,data,length,effect,counter,seed);
                require(a.writes.equals(b.writes),"Completion writes"); log.printf("complete\t%d\t%d%n",++completionCases,seed);
            }
        }
        for(int i=0;i<4;i++) for(long pc=REQUEST[i];pc<LIMIT[i];pc+=4) require(visited.contains(pc),"Unvisited request instruction "+Long.toHexString(pc));
        for(int i=2;i<6;i++) for(long pc=START[i];pc<STOP[i];pc+=4) require(visited.contains(pc),"Unvisited helper instruction");
        prefixEvidence(out);
        Files.writeString(out.resolve("visited.txt"),String.join("\n",visited.stream().map(v->String.format("%08x",v)).toList())+"\n");
        Files.writeString(out.resolve("comparison.json"),String.format(Locale.ROOT,
            "{\"request_cases\":%d,\"callback_constructor_cases\":%d,\"completion_cases\":%d,\"original_instruction_addresses\":%d,\"max_steps\":%d,\"allocation_create_strings_callback_release_modeled\":true,\"live_verified\":false}\n",
            requestCases,createCases,completionCases,visited.size(),maxSteps));
        if(recoverPrefix) Files.writeString(out.resolve("comparison.json"),
            Files.readString(out.resolve("comparison.json")).replace("allocation_create_strings_callback_release_modeled","allocation_create_clear_format_callback_release_modeled"));
        println("SMT4_REQUEST_COMPARE_OK");
    }
}
