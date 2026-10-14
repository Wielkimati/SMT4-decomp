// Constructed-registry reload comparison; file, release and copy explicitly modeled.
// @category SMT4
import ghidra.pcode.emu.*;
import ghidra.pcode.utils.Utils;
import ghidra.program.model.address.*;
import ghidra.program.model.lang.*;
import ghidra.program.model.pcode.PcodeOp;
import java.math.BigInteger;
import java.nio.file.*;
import java.util.*;
import java.io.*;
import java.security.MessageDigest;

public class CompareTableResourceReload extends CompareResourceLifecycle {
    static final long STATE=0x465040, GATE=0x446da8, OLD=0x900100, NEW=0x900300;
    long[] entries=new long[5];
    static final long[][] RANGES={{0x25c848,0x25c8f4},{0x25b9d8,0x25b9e4},{0x25b9e8,0x25b9f4},{0x2c5890,0x2c589c}};
    ReloadMachine newMachine(byte[] map,byte[] binary){return new ReloadMachine(map,binary);}
    long copyEntry(boolean rebuilt){return 0x2c6048;}
    void extraComparisons(ReloadMachine a,ReloadMachine b,Path out)throws Exception{}
    String modelFields(){return "\"file_release_copy_modeled\":true";}
    class ReloadMachine extends Machine {
        boolean construct,trace;
        List<String> events=new ArrayList<>(); int gateReads;
        ReloadMachine(byte[] map,byte[] binary){super(map,binary);}
        @Override public void beforeLoad(PcodeThread<byte[]> t,PcodeOp op,AddressSpace space,byte[] offset,int size){
            long at=Utils.bytesToLong(offset,offset.length,false);
            if(trace&&(at==STATE||within(at,size,REG,REG+1072)))events.add("read:"+Long.toHexString(at)+":"+size);
            if(trace&&at==GATE){require(size==4,"Gate width");gateReads++;events.add("gate");}
            super.beforeLoad(t,op,space,offset,size);
        }
        @Override public void beforeStore(PcodeThread<byte[]> t,PcodeOp op,AddressSpace space,byte[] offset,int size,byte[] value){
            long at=Utils.bytesToLong(offset,offset.length,false);
            if(within(at,size,STACK-0x1000,STACK))return;
            require(construct?(within(at,size,REG,REG+1072)||within(at,size,0x446518,0x446528)):
                (within(at,size,writableEntry+4,writableEntry+12)||at==STATE&&size==1),"Store extent "+Long.toHexString(at));
            if(trace)events.add("store:"+Long.toHexString(at)+":"+size+":"+Utils.bytesToLong(value,value.length,false));
        }
        void setup(long pc,long arg){
            executing=false;
            byte[] stack=new byte[4096];Arrays.fill(stack,(byte)0x96);memory(STACK-4096,stack);
            for(var r:currentProgram.getLanguage().getRegisters())if(r.isBaseRegister()&&!r.isProcessorContext())register(r,0);
            for(int i=0;i<=12;i++)register("r"+i,0x12340000L+i);
            register("sp",STACK);register("lr",RETURN);register("cpsr",0x10);register("r0",arg);
            thread.overrideContext(new RegisterValue(currentProgram.getProgramContext().getBaseContextRegister(),BigInteger.ZERO));
            thread.overrideCounter(toAddr(pc));executing=true;
        }
        void finish(){
            require(register("sp")==STACK,"SP");
            require(register("cpsr")%64<32,"Return ARM mode");
            for(int i=4;i<=11;i++)require(register("r"+i)==0x12340000L+i,"Saved register");
            for(byte b:memory(STACK-4096,0xe00))require(b==(byte)0x96,"Stack guard");
        }
        void externalReturn(long result){long lr=register("lr");for(String r:new String[]{"r0","r1","r2","r3","r12"})register(r,0xdeadbeefL);register("r0",result);thread.overrideCounter(toAddr(lr));}
        void copyCall(boolean rebuilt,long replacement,long size)throws Exception{
            if(size>0){require(replacement!=0&&size<=128,"Copy domain");memory(OLD,memory(NEW,(int)size));}
            externalReturn(0);
        }
        void instruction(boolean rebuilt,boolean initializer,int steps)throws Exception{
            long pc=thread.getCounter().getOffset();boolean allowed=rebuilt?within(pc,4,BUILD,BUILD+codeSize):false;
            if(!rebuilt){if(initializer)allowed=within(pc,4,0x3f05f0,0x3f090c)||within(pc,4,0x3f0cb8,0x3f0f50);
                else for(long[] r:RANGES)allowed|=within(pc,4,r[0],r[1]);}
            require(allowed&&steps<5000,"PC/budget "+Long.toHexString(pc));
            if(!rebuilt&&!initializer)visited.add(pc);thread.stepInstruction();
        }
        byte[] initialize(boolean rebuilt)throws Exception{
            byte[] bytes=new byte[1104];Arrays.fill(bytes,(byte)0xa5);memory(REG-16,bytes);
            construct=true;trace=false;setup(rebuilt?entries[4]:0x3f05f0,0);int steps=0;
            while(thread.getCounter().getOffset()!=RETURN)instruction(rebuilt,true,++steps);
            finish();construct=false;return memory(REG-16,1104);
        }
        long accessor(boolean rebuilt,int kind,long value)throws Exception{
            byte[] guard=new byte[33];Arrays.fill(guard,(byte)0xa7);guard[16]=(byte)value;memory(STATE-16,guard);if(kind==1)memory(STATE,new byte[]{(byte)(value^0xff)});
            trace=false;writableEntry=0x800000;setup(rebuilt?entries[kind]:RANGES[kind][0],value);int n=0;
            while(thread.getCounter().getOffset()!=RETURN)instruction(rebuilt,false,++n);
            finish();require(Arrays.equals(memory(STATE-16,33),guard),"Accessor guard/value");
            return register("r0");
        }
        List<String> reload(boolean rebuilt,long id,long gate,int state,long oldSize,long newSize,boolean loaded,boolean nullResult)throws Exception{
            byte[] initial=initialize(rebuilt);int off=id<67?(int)id*16+16:16;
            long entry=REG+id*16;writableEntry=id<67?entry:0x800000;
            if(id<67){put(initial,off+4,loaded?OLD:0);put(initial,off+8,oldSize);}memory(REG-16,initial);
            byte[] stateGuard=new byte[33];Arrays.fill(stateGuard,(byte)0x6a);stateGuard[16]=(byte)state;memory(STATE-16,stateGuard);
            writeWord(GATE,gate);byte[] payload=new byte[1024];for(int i=0;i<payload.length;i++)payload[i]=(byte)(i*7+i/256);memory(0x900000,payload);
            byte[] expectedPayload=payload.clone();boolean active=gate==0&&id<67&&loaded,equal=oldSize==newSize;
            long replacement=nullResult?0:NEW;
            List<String> expected=new ArrayList<>();expected.add("gate");
            if(gate==0&&id<67)expected.add("read:"+Long.toHexString(entry+4)+":4");
            if(active){expected.add("read:465040:1");expected.add("store:465040:1:1");expected.add("read:"+Long.toHexString(entry)+":4");expected.add("load");expected.add("read:"+Long.toHexString(entry+8)+":4");expected.add("read:"+Long.toHexString(entry+4)+":4");
                if(equal)expected.add("copy");expected.add("release");
                if(!equal){expected.add("store:"+Long.toHexString(entry+4)+":4:"+replacement);expected.add("store:"+Long.toHexString(entry+8)+":4:"+newSize);put(initial,off+4,replacement);put(initial,off+8,newSize);}
                if(state==0)expected.add("store:465040:1:0");stateGuard[16]=(byte)(state==0?0:1);
                if(equal&&newSize>0)System.arraycopy(payload,0x300,expectedPayload,0x100,(int)newSize);
            }
            byte[] before=memory(REG-16,1104);events.clear();gateReads=0;trace=true;setup(rebuilt?entries[0]:RANGES[0][0],id);int steps=0,phase=0;
            while(thread.getCounter().getOffset()!=RETURN){long pc=thread.getCounter().getOffset();
                if(pc==0x2c3344||pc==0x2c43b4||pc==copyEntry(rebuilt)){
                    require(active&&(register("sp")&7)==0,"Unexpected service/alignment");
                    require(Arrays.equals(memory(REG-16,1104),before),"Publication before release");
                    require((memory(STATE,1)[0]&255)==1,"State enabled at service");
                    if(pc==0x2c3344){require(phase++==0&&register("r0")==word(before,off)&&register("r2")==0,"Load arguments/order");
                        require(within(register("r1"),4,register("sp"),STACK),"Size local");writeWord(register("r1"),newSize);events.add("load");externalReturn(replacement);
                    }else if(pc==copyEntry(rebuilt)){require(equal&&phase++==1&&register("r0")==OLD&&register("r1")==replacement&&register("r2")==newSize,"Copy arguments/order");
                        events.add("copy");copyCall(rebuilt,replacement,newSize);
                    }else {require(phase++==(equal?2:1)&&register("r0")== (equal?replacement:OLD),"Release argument/order");events.add("release");externalReturn(0);}
                    continue;
                }instruction(rebuilt,false,++steps);
            }
            finish();trace=false;require(gateReads==1&&events.equals(expected),"Ordered events "+events+" expected "+expected);
            require(Arrays.equals(memory(REG-16,1104),initial),"Registry/guards");require(Arrays.equals(memory(STATE-16,33),stateGuard),"State/guards");
            require(Arrays.equals(memory(0x900000,1024),expectedPayload),"Payload/guards");require(word(memory(GATE,4),0)==gate,"Gate preserved");return new ArrayList<>(events);
        }
    }
    @Override public void run()throws Exception{
        Path out=Path.of(getScriptArgs()[0]);byte[] map=new byte[0x377000];currentProgram.getMemory().getBytes(toAddr(0x100000),map);
        require(HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(map)).equals("834938d18d2b7c688311c46c27bed813d0d7a9f8e3cbb61da8a6a3f23d360ebd"),"Reference hash");
        byte[] binary=Files.readAllBytes(out.resolve("resource-lifecycle.bin"));codeSize=binary.length;
        var lines=Files.readAllLines(out.resolve("entries.txt"));entries=new long[lines.size()];for(int i=0;i<entries.length;i++)entries[i]=Long.parseLong(lines.get(i));
        ReloadMachine a=newMachine(map,binary),b=newMachine(map,binary);require(Arrays.equals(a.initialize(false),b.initialize(true)),"Constructed states");
        int accessors=0,cases=0,gatePairs=0;
        for(long index:new long[]{0,1,2,0x40000002L,0xc0000002L})for(long value:new long[]{0,0x87654321L}){
            long at=(0x446da0+index*4)&0xffffffffL;
            for(ReloadMachine m:new ReloadMachine[]{a,b}){m.writeWord(at,value);m.trace=false;m.setup(m==a?0x2c5890:entries[3],index);int n=0;
                while(m.thread.getCounter().getOffset()!=RETURN)m.instruction(m==b,false,++n);
                m.finish();require(m.register("r0")==value,"Gate indexed/wrapping read");}
            gatePairs++;
        }
        for(long value:new long[]{0,1,127,128,255,256,0xffffffffL}){
            a.accessor(false,1,value);b.accessor(true,1,value);accessors++;
            long x=a.accessor(false,2,value),y=b.accessor(true,2,value);require(x==y&&x==((long)(byte)value&0xffffffffL),"Signed state getter");accessors++;
        }
        try(PrintWriter log=new PrintWriter(Files.newBufferedWriter(out.resolve("results.tsv")))){
            log.println("id\tgate\tstate\told_size\tnew_size\tloaded\tnull_result");
            for(long id:new long[]{0,1,13,66,67,0xffffffffL})for(long gate:new long[]{0,0x80000000L})
            for(int state:new int[]{0,1,128,255})for(int scenario=0;scenario<6;scenario++){
                long oldSize=scenario==0?0:scenario==1?1:scenario==2?17:scenario==3?128:0xffffffffL;
                long newSize=scenario<4?oldSize:scenario==4?3:0;
                boolean loaded=scenario!=0,empty=scenario==5;
                require(a.reload(false,id,gate,state,oldSize,newSize,loaded,empty).equals(b.reload(true,id,gate,state,oldSize,newSize,loaded,empty)),"Pair events");cases++;
                log.printf("%d\t%d\t%d\t%d\t%d\t%b\t%b%n",id,gate,state,oldSize,newSize,loaded,empty);
            }
            // Loaded zero-size copy with null source: no payload dereference.
            require(a.reload(false,1,0,0,0,0,true,true).equals(b.reload(true,1,0,0,0,0,true,true)),"Zero copy pair");cases++;
        }
        extraComparisons(a,b,out);
        for(long[] r:RANGES)for(long pc=r[0];pc<r[1];pc+=4)require(visited.contains(pc),"Unvisited "+Long.toHexString(pc));
        Files.writeString(out.resolve("visited.txt"),visited.toString());
        Files.writeString(out.resolve("comparison.json"),"{\"reload_pairs\":"+cases+",\"accessor_pairs\":"+accessors+",\"gate_pairs\":"+gatePairs+",\"original_sites\":"+visited.size()+",\"constructed_registry\":true,"+modelFields()+",\"live_verified\":false}\n");
        println("SMT4_TABLE_RELOAD_COMPARE_OK");
    }
}
