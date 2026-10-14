// Registry startup slice and array/record constructors; retained break corpus.
// @category SMT4
import ghidra.pcode.emu.PcodeThread;
import ghidra.pcode.utils.Utils;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.pcode.PcodeOp;
import java.nio.file.*;
import java.util.*;
import java.io.*;

public class CompareResourceRegistryInitialize extends CompareResourceBreak {
    static final long ARRAY=0x2c5fac, RECORD=0x3561f0, STARTUP=0x3f3570, STARTUP_END=0x3f3584;
    static final long ARENA=0x914000, ARM_CTOR=0x790000, THUMB_CTOR=0x790101;
    long arrayEntry,recordEntry,startupEntry;
    int initPairs,initSequences,connectedInitializations,constructorCalls;
    Set<Long> initVisited=new TreeSet<>();
    @Override IoMachine makeMachine(byte[] mapped,byte[] binary) { return new InitMachine(mapped,binary); }

    class InitMachine extends RegistryMachine {
        boolean initializing;
        Set<Long> recordWrites=new TreeSet<>();
        InitMachine(byte[] mapped,byte[] binary) { super(mapped,binary); memory(ARENA-16,new byte[1056]); }
        @Override public void beforeStore(PcodeThread<byte[]> t,PcodeOp op,AddressSpace space,byte[] offset,int size,byte[] value) {
            long a=Utils.bytesToLong(offset,offset.length,false);
            if(initializing && !within(a,size,STACK-0x1000,STACK)) {
                require(within(a,size,ARENA,ARENA+1024) || within(a,size,PREFIX_TABLE,PREFIX_TABLE+512),"Initializer write boundary");
                for(int i=0;i<size;i++) recordWrites.add(a+i);
                return;
            }
            super.beforeStore(t,op,space,offset,size,value);
        }
        @Override public void beforeLoad(PcodeThread<byte[]> t,PcodeOp op,AddressSpace space,byte[] offset,int size) {
            long a=Utils.bytesToLong(offset,offset.length,false);
            if(initializing && within(a,size,ARENA-16,ARENA+1040)) return;
            super.beforeLoad(t,op,space,offset,size);
        }
        @Override void initializeConnectedRegistry(boolean rebuilt) throws Exception {
            // Poison keys/pointers and retain arbitrary flags/padding before actual startup.
            memory(PREFIX_TABLE,occupied());
            initializeCall(rebuilt,2,PREFIX_TABLE,RECORD,16,32);
            connectedInitializations++;
        }
        List<Long> initializeCall(boolean rebuilt,int kind,long base,long constructor,long stride,long count) throws Exception {
            long sp=register("sp"); long[] saved=new long[8];
            for(int r=4;r<=11;r++) saved[r-4]=register("r"+r);
            byte[] expectedArena=memory(ARENA-16,1056),expectedTable=memory(PREFIX_TABLE-16,544);
            Set<Long> expectedWrites=new TreeSet<>(); List<Long> calls=new ArrayList<>();
            long effectiveCount=kind==1 ? 1 : constructor==0 ? 0 : count;
            if(constructor==RECORD || kind==1) for(int i=0;i<effectiveCount;i++) {
                long at=(base+i*stride)&MASK;
                byte[] target=at>=PREFIX_TABLE && at<PREFIX_TABLE+512 ? expectedTable : expectedArena;
                int offset=(int)(at-(target==expectedTable ? PREFIX_TABLE : ARENA))+16;
                Arrays.fill(target,offset,offset+12,(byte)0);
                for(int j=0;j<12;j++) expectedWrites.add(at+j);
            }
            long ctor=rebuilt && constructor==RECORD ? recordEntry : constructor;
            register("r0",base); register("r1",ctor); register("r2",stride); register("r3",count); register("lr",RETURN);
            select(rebuilt ? new long[]{arrayEntry,recordEntry,startupEntry}[kind] : new long[]{ARRAY,RECORD,STARTUP}[kind],!rebuilt && kind==0);
            initializing=true; executing=true; recordWrites.clear(); int steps=0,helpers=0;
            long end=!rebuilt && kind==2 ? STARTUP_END : RETURN;
            while(thread.getCounter().getOffset()!=end) {
                long pc=thread.getCounter().getOffset();
                if(pc==(rebuilt ? arrayEntry : ARRAY) && kind==2) {
                    require(++helpers==1 && register("r0")==PREFIX_TABLE && register("r1")==ctor && register("r2")==16 && register("r3")==32,"Startup constructor/base/stride/count binding");
                }
                if(pc==(rebuilt ? recordEntry : RECORD) || pc==(ARM_CTOR&~1L) || pc==(THUMB_CTOR&~1L)) {
                    long at=(base+calls.size()*stride)&MASK;
                    require(calls.size()<effectiveCount && register("r0")==at,"Initializer callback order/receiver");
                    require((register("sp")&7)==0,"Initializer callback stack alignment");
                    calls.add(at); constructorCalls++;
                    if(pc==ARM_CTOR || pc==(THUMB_CTOR&~1L)) {
                        require(pc==(constructor&~1L) && thread.getContext().getRegisterValue(currentProgram.getRegister("TMode")).getUnsignedValue().longValue()==(constructor&1),"Constructor ARM/Thumb interworking");
                        long lr=register("lr");
                        for(String r:new String[]{"r0","r1","r2","r3","r12"}) register(r,(0x81234567L+calls.size())&MASK);
                        select(lr,(lr&1)!=0); continue;
                    }
                }
                require(rebuilt ? within(pc,4,BUILD,BUILD+codeSize) : within(pc,2,ARRAY,0x2c5fce) || within(pc,4,RECORD,0x356204) || kind==2 && within(pc,4,STARTUP,STARTUP_END),"Initializer PC "+Long.toHexString(pc));
                if(!rebuilt) initVisited.add(pc);
                require(++steps<2000,"Initializer instruction budget"); monitor.checkCancelled(); thread.stepInstruction();
            }
            initializing=false;
            require(calls.size()==effectiveCount,"Initializer exact callback count");
            require(recordWrites.equals(expectedWrites),"Initializer exact twelve-byte record write footprint");
            require(Arrays.equals(expectedArena,memory(ARENA-16,1056)) && Arrays.equals(expectedTable,memory(PREFIX_TABLE-16,544)),"Initializer guarded memory and preserved tails");
            require(register("r0")==base,"Initializer original base return");
            require(register("sp")==sp,"Initializer stack restoration");
            for(int r=4;r<=11;r++) require(register("r"+r)==saved[r-4],"Initializer callee-saved register");
            for(byte v:memory(STACK-0x1000,0xe00)) require(v==(byte)0x96,"Initializer stack guard");
            return calls;
        }
        void resetInit(boolean rebuilt) {
            resetRegistry(rebuilt,occupied(),BACKEND);
            byte[] arena=new byte[1056]; new Random(RECORD).nextBytes(arena); memory(ARENA-16,arena);
        }
    }
    void initProbe(InitMachine a,InitMachine b,int kind,long base,long ctor,long stride,long count,PrintWriter log) throws Exception {
        a.resetInit(false); b.resetInit(true);
        var x=a.initializeCall(false,kind,base,ctor,stride,count);
        var y=b.initializeCall(true,kind,base,ctor,stride,count);
        require(x.equals(y) && Arrays.equals(a.memory(PREFIX_TABLE-16,544),b.memory(PREFIX_TABLE-16,544)),"Initializer original/rebuilt state and callback agreement");
        log.printf("%d\t%d\t%x\t%x\t%x\t%d\t%s%n",++initPairs,kind,base,ctor,stride,count,x);
    }
    @Override void preChecks(byte[] mapped,byte[] binary,Path out) throws Exception {
        try {
            InitMachine a=new InitMachine(mapped,binary),b=new InitMachine(mapped,binary);
            try(PrintWriter log=new PrintWriter(Files.newBufferedWriter(out.resolve("registry-initialize-results.tsv")))) {
                log.println("case\tkind\tbase\tconstructor\tstride\tcount\taddresses");
                for(long count:new long[]{0,1,32,0x80000000L,MASK}) initProbe(a,b,0,0x81234567L,0,MASK,count,log);
                for(long ctor:new long[]{ARM_CTOR,THUMB_CTOR}) for(long count:new long[]{0,1,3,32})
                    for(long[] layout:new long[][]{{0x81234567L,0},{0xfffffff8L,16},{7,0xfffffff0L},{0x12345678L,1}})
                        initProbe(a,b,0,layout[0],ctor,layout[1],count,log);
                for(int offset:new int[]{0,4,12}) initProbe(a,b,1,ARENA+offset,RECORD,16,1,log);
                for(long count:new long[]{0,1,3,32}) for(long stride:new long[]{0,12,16,20})
                    initProbe(a,b,0,ARENA+4,RECORD,stride,count,log);
                initProbe(a,b,2,PREFIX_TABLE,RECORD,16,32,log);
                // Persistent lifetime: startup replaces poisoned occupied records; no resets between operations.
                for(int retain:new int[]{0,1}) {
                    for(boolean rebuilt:new boolean[]{false,true}) {
                        InitMachine m=rebuilt ? b : a; m.resetInit(rebuilt);
                        m.initializeCall(rebuilt,2,PREFIX_TABLE,RECORD,16,32);
                        byte[] name=name('r',0); int[] prefix={'r'};
                        m.persistentOpen(rebuilt,prefix,false);
                        m.mutate(rebuilt,0,name,0,BACKEND,0xff,retain,false,0); m.persistentOpen(rebuilt,prefix,true);
                        m.mutate(rebuilt,0,name,0,BACKEND+32,0,1,false,0);
                        m.mutate(rebuilt,1,name,0,0,0,0,false,1); m.persistentOpen(rebuilt,prefix,false);
                        m.mutate(rebuilt,0,name,0,BACKEND+32,0x123,retain,false,0); m.persistentOpen(rebuilt,prefix,true);
                        m.mutate(rebuilt,1,name,0,0,0,0,false,2); m.persistentOpen(rebuilt,prefix,false);
                        initSequences++;
                    }
                    require(Arrays.equals(a.memory(PREFIX_TABLE-16,544),b.memory(PREFIX_TABLE-16,544)),"Initialized lifecycle final agreement");
                    log.printf("lifecycle\tretain=%d\toriginal/rebuilt passed%n",retain);
                }
            }
        } catch(Exception e) { throw new IllegalStateException("Worker I/O case registry initialization pair="+initPairs,e); }
        super.preChecks(mapped,binary,out);
    }
    @Override String extraChecks(byte[] mapped,byte[] binary,Path out) throws Exception {
        String inherited=super.extraChecks(mapped,binary,out); StringBuilder listing=new StringBuilder();
        for(long[] range:new long[][]{{ARRAY,0x2c5fce,2},{RECORD,0x356204,4},{STARTUP,STARTUP_END,4}}) {
            var f=getFunctionContaining(toAddr(range[0]));
            listing.append(String.format("range %08x..%08x saved=%s%n",range[0],range[1],f==null ? "none" : f.getBody()));
            for(long pc=range[0];pc<range[1];pc+=range[2]) {
                require(initVisited.contains(pc),"Unvisited initializer site");
                listing.append(String.format("%08x %s %s TMode=%s visited=true%n",pc,HexFormat.of().formatHex(getBytes(toAddr(pc),(int)range[2])),getInstructionAt(toAddr(pc)),currentProgram.getProgramContext().getValue(currentProgram.getRegister("TMode"),toAddr(pc),false)));
            }
        }
        require(initVisited.size()==27,"Initializer instruction membership");
        require(getInt(toAddr(0x3f36f0))==RECORD && getInt(toAddr(0x3f36f4))==PREFIX_TABLE,"Startup original literals");
        Files.writeString(out.resolve("original-registry-initialize-ghidra.txt"),listing);
        return inherited+String.format(Locale.ROOT,",\"registry_initialization_recovered\":true,\"direct_initializer_pairs\":%d,\"initialized_lifecycle_sequences_both\":%d,\"connected_initializations_both\":%d,\"initializer_constructor_calls_both\":%d,\"new_initializer_instruction_sites\":%d",initPairs,initSequences,connectedInitializations,constructorCalls,initVisited.size());
    }
    @Override public void run() throws Exception {
        var lines=Files.readAllLines(Path.of(getScriptArgs()[0]).resolve("registry-initialize-entries.txt"));
        arrayEntry=Long.parseLong(lines.get(0)); recordEntry=Long.parseLong(lines.get(1)); startupEntry=Long.parseLong(lines.get(2));
        super.run();
    }
}
