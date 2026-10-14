// Table constructor and persistent lifecycle consumers; file/index calls modeled.
// @category SMT4
import ghidra.pcode.emu.PcodeThread;
import ghidra.pcode.utils.Utils;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.pcode.PcodeOp;
import java.nio.file.*;
import java.util.*;
import java.io.*;

public class CompareTableResourceInitialize extends CompareStartupDispatch {
    static final long TSTART=0x3f05f0, REGISTRY=0x49382c, ANC=0x446518;
    long[] tableEntries=new long[4];
    long[] paths=new long[67]; int[] policies=new int[67];
    int tableCalls,consumerCalls,loads; Set<Long> tableVisited=new TreeSet<>();
    List<Access> tableEvents=new ArrayList<>();
    // Decode only reviewed MOV/MVN/ADD/LDR/STR forms to bind the oracle to
    // instruction constants. Actual original execution remains independently checked.
    void bind(byte[] map) {
        long[] r=new long[16];
        tableEvents.add(new Access("w",ANC,MASK));tableEvents.add(new Access("w",ANC+4,MASK));
        tableEvents.add(new Access("w",ANC+8,0));tableEvents.add(new Access("w",ANC+12,0));
        for(long[] range:new long[][]{{TSTART,0x3f090c},{0x3f0cb8,0x3f0f50}})for(long pc=range[0];pc<range[1];pc+=4) {
            long w=word(map,(int)(pc-0x100000));r[15]=pc+8;
            if(w==0xe1c200f0L||w==0xe8800006L||(w>>>24)==0xea||w==0xe12fff1eL)continue;
            int rn=(int)(w>>>16)&15,rd=(int)(w>>>12)&15;
            if((w&0x0c000000)==0x04000000) {
                long at=r[rn]+(w&4095);
                if((w&(1<<20))!=0)r[rd]=word(map,(int)(at-0x100000));
                else {
                    boolean narrow=(w&(1<<22))!=0;
                    tableEvents.add(new Access(narrow?"b":"w",at,r[rd]));
                    int off=(int)(at-REGISTRY);require(off>=0&&off<1072,"Registry store extent");
                    if(off%16==0)paths[off/16]=r[rd];
                    if(off%16==12)policies[off/16]=(int)r[rd];
                }
            } else {
                int op=(int)(w>>>21)&15;
                long v=(w&(1<<25))!=0?Integer.toUnsignedLong(Integer.rotateRight((int)w&255,((int)(w>>>8)&15)*2)):r[(int)w&15];
                if(op==13)r[rd]=v;else if(op==15)r[rd]=v^MASK;else {require(op==4,"Reviewed opcode");r[rd]=(r[rn]+v)&MASK;}
            }
        }
        require(tableEvents.size()==272&&paths[1]==0x3f0930&&policies[1]==1,"Binding count/slot one");
    }
    @Override State poisoned(int fill) {
        State s=super.poisoned(fill);s.add(REGISTRY-16,1104,fill);s.add(ANC-16,48,fill^0x67);return s;
    }
    void byteSet(State s,long at,int value) {var e=s.blocks.floorEntry(at);e.getValue()[(int)(at-e.getKey())]=(byte)value;}
    State initialized(State s) {
        State result=new State(s);
        for(Access e:tableEvents) {if(e.kind().equals("b"))byteSet(result,e.at(),(int)e.value());else result.set(e.at(),e.value());}
        return result;
    }
    @Override DispatchMachine newDispatchMachine(byte[] map,byte[] binary) {return new TableMachine(map,binary);}
    class TableMachine extends DispatchMachine {
        boolean tableActive,consumerActive;int storeIndex;State state;
        TableMachine(byte[] map,byte[] binary){super(map,binary);}
        @Override public void beforeLoad(PcodeThread<byte[]> t,PcodeOp op,AddressSpace space,byte[] offset,int size) {
            if(!tableActive&&!consumerActive){super.beforeLoad(t,op,space,offset,size);return;}
            long at=Utils.bytesToLong(offset,offset.length,false);
            require(within(at,size,REGISTRY,REGISTRY+1072)||within(at,size,STACK-0x1000,STACK)||
                within(at,size,BUILD,BUILD+codeSize)||within(at,size,0x100000,0x477000),"Table/consumer read extent");
        }
        @Override public void beforeStore(PcodeThread<byte[]> t,PcodeOp op,AddressSpace space,byte[] offset,int size,byte[] value) {
            if(!tableActive&&!consumerActive){super.beforeStore(t,op,space,offset,size,value);return;}
            long at=Utils.bytesToLong(offset,offset.length,false);
            if(within(at,size,STACK-0x1000,STACK))return;
            if(tableActive) {
                require(size==1||size==4||size==8,"Constructor store width");
                for(int i=0;i<size;i+=size==1?1:4) {
                    Access actual=new Access(size==1?"b":"w",at+i,size==1?value[0]&255:word(value,i));
                    require(storeIndex<tableEvents.size()&&tableEvents.get(storeIndex++).equals(actual),"Ordered constructor store "+actual);
                }
            } else require(within(at,size,REGISTRY,REGISTRY+1072),"Consumer store extent");
        }
        State constructTable(State s) throws Exception {
            long ret=register("lr")&~1L,sp=register("sp");int retMode=(int)(register("lr")&1);
            long[] saved=new long[8];for(int i=0;i<8;i++)saved[i]=register("r"+(i+4));
            tableActive=true;storeIndex=0;
            if(isRebuilt)thread.overrideCounter(toAddr(tableEntries[0]));int steps=0;
            do {
                long pc=thread.getCounter().getOffset();
                require(isRebuilt?within(pc,4,BUILD,BUILD+codeSize):within(pc,4,TSTART,0x3f090c)||within(pc,4,0x3f0cb8,0x3f0f50),"Table constructor PC");
                require(mode()==0&&++steps<5000,"Table constructor mode/budget");
                if(!isRebuilt)tableVisited.add(pc);thread.stepInstruction();
            }while(thread.getCounter().getOffset()!=ret);
            require(storeIndex==tableEvents.size()&&register("sp")==sp&&mode()==retMode,"Table constructor completion");
            for(int i=0;i<8;i++)require(register("r"+(i+4))==saved[i],"Table saved registers");
            State result=initialized(s);check(result,"Table full guarded state");tableActive=false;tableCalls++;return result;
        }
        @Override State otherCallback(State s,long target,int index) throws Exception {
            return target==TSTART?constructTable(s):super.otherCallback(s,target,index);
        }
        void direct(State s,boolean rebuilt) throws Exception {
            seed(s,rebuilt);initialize(rebuilt,0,new byte[0x144]);thread.overrideCounter(toAddr(TSTART));
            state=constructTable(s);finish(0);
        }
        void consumer(int kind,long id,int resultMode,boolean sizeWrite,boolean high) throws Exception {
            initialize(isRebuilt,0,new byte[0x144]);register("r0",id);
            long[] starts={0x33c8a0,0x297714,0x2a49e0},ends={0x33c958,0x297770,0x2a4a38};
            thread.overrideCounter(toAddr(isRebuilt?tableEntries[kind+1]:starts[kind]));consumerActive=true;
            List<Integer> order=new ArrayList<>();for(int i=0;i<67;i++)order.add(i);
            for(int i=0;i<33;i++)Collections.swap(order,i,high?66:i+1);
            List<Integer> loadIds=new ArrayList<>();long result=1;
            if(kind==0){for(int i:order)if(state.get(REGISTRY+i*16+4)==0&&policies[i]!=0)loadIds.add(i);}
            else if(id>=67)result=0;
            else {
                long at=REGISTRY+id*16,loaded=state.get(at+4);
                if(kind==1&&loaded==0){if(policies[(int)id]!=0)result=0;else loadIds.add((int)id);}
                if(kind==2&&loaded!=0&&policies[(int)id]!=0)result=0;
            }
            int indices=0,loadedCount=0,releases=0,steps=0;
            boolean release=kind==2&&id<67&&state.get(REGISTRY+id*16+4)!=0&&policies[(int)id]==0;
            while(thread.getCounter().getOffset()!=RETURN) {
                long pc=thread.getCounter().getOffset();
                if(pc==0x29706c||pc==0x2c3344||pc==0x2c43b4) {
                    require((register("sp")&7)==0,"Consumer dependency alignment");check(state,"Consumer boundary state");
                    if(pc==0x29706c){require(kind==0&&indices<33&&loadedCount==0&&register("r0")==indices+1&&register("r1")==66,"Index model arguments");externalReturn(high?66:++indices);if(high)indices++;}
                    else if(pc==0x2c3344) {
                        require(loadedCount<loadIds.size(),"Unexpected file load");int slot=loadIds.get(loadedCount++);long at=REGISTRY+slot*16;
                        require(register("r0")==paths[slot]&&register("r1")==at+8&&register("r2")==0,"File model arguments/order");
                        long value=resultMode==0||(resultMode==2&&slot%2==0)?0:0x81230000L+slot*256;
                        if(sizeWrite){long size=0xdead0000L+slot*17;writeWord(at+8,size);state.set(at+8,size);}
                        state.set(at+4,value);externalReturn(value);loads++;
                    } else {require(release&&releases++==0&&register("r0")==state.get(REGISTRY+id*16+4),"Release model arguments");state.set(REGISTRY+id*16+4,0);externalReturn(0);}
                    continue;
                }
                require(isRebuilt?within(pc,4,BUILD,BUILD+codeSize):within(pc,4,starts[kind],ends[kind]),"Consumer PC "+Long.toHexString(pc));
                require(++steps<10000&&mode()==0,"Consumer mode/budget");thread.stepInstruction();
            }
            require(loadedCount==loadIds.size()&&indices==(kind==0?33:0)&&releases==(release?1:0),"Consumer model counts");
            require(register("r0")==result,"Consumer result");check(state,"Consumer final guarded state");finish(steps);
            for(byte v:memory(STACK-0x1000,0xd00))require(v==(byte)0x96,"Consumer stack guard");
            consumerActive=false;consumerCalls++;
        }
    }
    @Override public void run() throws Exception {
        Path out=Path.of(getScriptArgs()[0]);byte[] map=new byte[0x377000];currentProgram.getMemory().getBytes(toAddr(0x100000),map);
        var lines=Files.readAllLines(out.resolve("table-entries.txt"));for(int i=0;i<4;i++)tableEntries[i]=Long.parseLong(lines.get(i));bind(map);
        try {
            super.run();
            byte[] binary=Files.readAllBytes(out.resolve("resource-worker-backend.bin"));
            for(int fill:new int[]{0,0xff,0xa5}) {
                TableMachine a=new TableMachine(map,binary),b=new TableMachine(map,binary);State s=poisoned(fill);
                a.direct(s,false);b.direct(s,true);
                for(TableMachine m:new TableMachine[]{a,b}) {
                    // Initial policy-one denial, policy-zero null return, retry,
                    // loaded skip, release with stale size, and bulk repeat.
                    m.consumer(1,1,1,true,false);m.consumer(1,13,0,false,false);
                    m.consumer(1,13,1,true,false);m.consumer(1,13,1,true,false);
                    m.consumer(2,13,1,true,false);m.consumer(2,1,1,true,false);
                    for(long id:new long[]{67,0xffffffffL}){m.consumer(1,id,1,true,false);m.consumer(2,id,1,true,false);}
                    m.consumer(0,0,fill==0?0:fill==255?1:2,fill!=0,fill==255);
                    m.consumer(0,0,1,true,false);m.consumer(2,1,1,true,false);
                }
                for(var e:a.state.blocks.entrySet())require(Arrays.equals(e.getValue(),b.state.blocks.get(e.getKey())),"Persistent pair state");
            }
            for(long[] range:new long[][]{{TSTART,0x3f090c},{0x3f0cb8,0x3f0f50}})for(long pc=range[0];pc<range[1];pc+=4)require(tableVisited.contains(pc),"Table coverage");
            Files.writeString(out.resolve("table-visited.txt"),tableVisited.toString());
            String prior=Files.readString(out.resolve("comparison.json")).trim();
            Files.writeString(out.resolve("comparison.json"),prior.substring(0,prior.length()-1)+String.format(Locale.ROOT,
                ",\"table_constructor_calls_both\":%d,\"table_original_sites\":%d,\"table_stores_per_call\":272,\"direct_pairs\":3,\"persistent_consumer_pairs\":%d,\"modeled_file_loads_both\":%d,\"remaining_constructors_per_pinned_traversal\":634,\"index_and_file_services_modeled\":true}\n",tableCalls,tableVisited.size(),consumerCalls/2,loads));
            println("SMT4_TABLE_REGISTRY_COMPARE_OK");
        }catch(Exception e){throw new IllegalStateException("Table registry case",e);}
    }
}
