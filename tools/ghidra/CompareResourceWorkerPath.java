// Worker byte conversion; locale callbacks remain explicit scripted dependencies.
// @category SMT4
import ghidra.pcode.emu.PcodeThread;
import ghidra.pcode.utils.Utils;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.lang.RegisterValue;
import java.math.BigInteger;
import java.nio.file.*;
import java.util.*;
import java.io.*;

public class CompareResourceWorkerPath extends CompareResourceWorkerFileCleanup {
    static final long[] PATH_START={0x2b9486,0x2b9468,0x2c63dc,0x1008c8,0x2c6936,0x2c6894,0x2c6c48,0x2c6c94};
    static final long[] PATH_END={0x2b9498,0x2b9486,0x2c644c,0x100908,0x2c693e,0x2c689c,0x2c6c50,0x2c6ca4};
    static final long BANK=0x4efc90, CONTEXT=0x4efca0, ERROR=0x4efce0, SLOTS=0x4efce4;
    static final long LOCALE=0x90c000, STATE=0x90d000, CALLBACK=0x760000;
    long[] pathEntries=new long[8];
    int pathCases,connectedPaths,pathSteps,callbackCalls;
    boolean pathCode(long pc) {
        for(int i=0;i<8;i++) if(within(pc,i<5 ? 2 : 4,PATH_START[i],PATH_END[i])) return true;
        return false;
    }
    @Override boolean originalCode(long pc) { return pathCode(pc) || super.originalCode(pc); }
    @Override IoMachine makeMachine(byte[] mapped,byte[] binary) { return new PathMachine(mapped,binary); }
    class PathMachine extends CleanupMachine {
        long callbackTarget,callbackState;
        int callbackIndex;
        int[] callbackBytes,callbackUnits;
        long[] callbackResults;
        PathMachine(byte[] mapped,byte[] binary) { super(mapped,binary); }
        @Override int pathCount(int profile) { return new int[]{0,1,4,0,2,120}[profile]; }
        @Override int pathFailure(int profile) { return -1; }
        @Override int pathStride(int index) { return 1; }
        @Override int convertedUnit(int index) { return index==0 ? 'r' : index==1 ? ':' : 'a'+index%26; }
        @Override long pathTarget(boolean rebuilt,int kind) { return rebuilt ? pathEntries[kind] : PATH_START[kind]; }
        @Override void checkPathState(long state,int converted) { require(get(state)==0 && get(state+4)==0,"Table decoder preserves state"); }
        @Override void advancePathState(long state,int converted) { checkPathState(state,converted); }
        void fillPath(byte[] descriptor,int count) {
            for(int i=0;i<count;i++) descriptor[0x2c+i]=(byte)convertedUnit(i);
            descriptor[0x2c+count]=0;
        }
        @Override void call(boolean rebuilt,byte[] initial,long open,long read,long handle,long length,long allocation,int profile,int effect) throws Exception {
            byte[] descriptor=initial.clone(); int count=pathCount(profile);
            fillPath(descriptor,count);
            super.call(rebuilt,descriptor,open,read,handle,length,allocation,profile,effect);
        }
        void pathFixtures(int mode,boolean invalid,boolean thumb,int residue) {
            byte[] bank=new byte[192]; new Random(CONTEXT).nextBytes(bank); memory(BANK,bank);
            byte[] locale=new byte[320]; Arrays.fill(locale,(byte)1);
            locale[16+residue+0x101]=(byte)mode;
            if(invalid) for(int i=0;i<256;i++) if(i%3==2) locale[16+residue+i]=0;
            callbackTarget=CALLBACK+(thumb ? 5 : 0);
            put(locale,16+residue+0x103,(callbackTarget-(LOCALE+residue+0x103))&MASK);
            memory(LOCALE-16,locale); writeWord(CONTEXT+4,LOCALE+residue);
            writeWord(ERROR,0xa55a5aa5L);
            for(int slot:new int[]{4,5}) { writeWord(SLOTS+slot*8,0x10203040L+slot); writeWord(SLOTS+slot*8+4,0x55667788L+slot); }
            callbackIndex=0; callbackResults=null;
        }
        @Override void setupAllocation(byte[] initial,long length,long allocation) {
            super.setupAllocation(initial,length,allocation); pathFixtures(0,false,false,0);
        }
        @Override public void beforeLoad(PcodeThread<byte[]> t,PcodeOp op,AddressSpace space,byte[] offset,int size) {
            long a=Utils.bytesToLong(offset,offset.length,false);
            if(within(a,size,BANK,BANK+192) || within(a,size,LOCALE-16,LOCALE+304) ||
               within(a,size,STATE-16,STATE+24) || within(a,size,SIZE-16,SIZE+24)) return;
            super.beforeLoad(t,op,space,offset,size);
        }
        @Override public void beforeStore(PcodeThread<byte[]> t,PcodeOp op,AddressSpace space,byte[] offset,int size,byte[] value) {
            long a=Utils.bytesToLong(offset,offset.length,false);
            if(a==ERROR && size==4 || a==SIZE && size==2) return;
            super.beforeStore(t,op,space,offset,size,value);
        }
        void select(long target,boolean thumb) {
            register("cpsr",thumb ? 0x30 : 0x10);
            thread.overrideContext(new RegisterValue(currentProgram.getProgramContext().getBaseContextRegister(),BigInteger.ZERO));
            if(thumb) thread.overrideContext(new RegisterValue(currentProgram.getRegister("TMode"),BigInteger.ONE));
            thread.overrideCounter(toAddr(target&~1L));
        }
        void callbackReturn(long result) {
            long lr=register("lr"); externalReturn(result);
            if((lr&1)!=0) {
                register("cpsr",0xa0000030L);
                thread.overrideContext(new RegisterValue(currentProgram.getRegister("TMode"),BigInteger.ONE));
            }
        }
        void pathInstruction(long pc,boolean rebuilt) {}
        long executePath(boolean rebuilt) throws Exception {
            long caller=register("lr"),sp=register("sp");
            long[] saved=new long[8]; for(int r=4;r<=11;r++) saved[r-4]=register("r"+r);
            int steps=0;
            while(thread.getCounter().getOffset()!=(caller&~1L)) {
                long pc=thread.getCounter().getOffset();
                if(pc==(callbackTarget&~1L)) {
                    require(callbackResults!=null && callbackIndex<callbackResults.length,"Unexpected locale callback");
                    int i=callbackIndex++;
                    require(register("r1")==callbackBytes[i] && register("r2")==callbackState,"Locale byte/state ABI");
                    long out=register("r0");
                    require(out==SIZE || within(out,2,register("sp"),sp),"Locale output ABI");
                    require((register("sp")&7)==0,"Locale callback stack alignment");
                    long first=0,second=0;
                    if(callbackState!=0) {
                        first=(get(callbackState)+callbackBytes[i]+1)&MASK; second=get(callbackState+4)^0x1020304;
                        writeWord(callbackState,first); writeWord(callbackState+4,second);
                    }
                    memory(out,new byte[]{(byte)callbackUnits[i],(byte)(callbackUnits[i]>>8)});
                    trace.add("locale:"+callbackBytes[i]+":"+callbackState+":"+first+":"+second+":"+callbackResults[i]+":"+callbackUnits[i]);
                    callbackCalls++; dependencyCalls++; callbackReturn(callbackResults[i]); continue;
                }
                require(rebuilt ? within(pc,4,BUILD,BUILD+codeSize) : pathCode(pc),"Path PC "+Long.toHexString(pc));
                pathInstruction(pc,rebuilt);
                if(!rebuilt) visited.add(pc);
                require(++steps<20000,"Path instruction budget"); monitor.checkCancelled(); thread.stepInstruction();
            }
            require(register("sp")==sp,"Path stack restoration");
            for(int r=4;r<=11;r++) require(register("r"+r)==saved[r-4],"Path saved register");
            pathSteps=Math.max(pathSteps,steps);
            long result=register("r0"); register("lr",caller); return result;
        }
        @Override long initializePath(boolean rebuilt,long state) throws Exception {
            long result=executePath(rebuilt); require(result==1,"Initial predicate result");
            checkPathState(state,0); connectedPaths++; return result;
        }
        @Override long measurePath(boolean rebuilt,long expected) throws Exception {
            long result=executePath(rebuilt); require(result==expected,"Connected measured byte count"); connectedPaths++; return result;
        }
        @Override long convertPath(boolean rebuilt,long ignored,int ch) throws Exception {
            long out=register("r0"),result=executePath(rebuilt);
            byte[] unit=memory(out,2);
            require(result==1 && ((unit[0]&255)|((unit[1]&255)<<8))==ch,"Connected byte/output conversion");
            connectedPaths++; return result;
        }
        void direct(boolean rebuilt,int kind,int mode,boolean invalid,int[] input,long limit,int stateKind,
                    boolean nullInput,boolean nullOutput,long first,long second,long[] results,int[] units,boolean thumb,int residue) throws Exception {
            releasedObject=false; initialize(rebuilt,0,new byte[0x144]); destroyed=false; active=false; trace.clear();
            pathFixtures(mode,invalid,thumb,residue);
            byte[] in=new byte[2048]; Arrays.fill(in,(byte)0x69);
            for(int i=0;i<input.length;i++) in[i]=(byte)input[i]; memory(PATH,in);
            byte[] output=new byte[40]; Arrays.fill(output,(byte)0x5a); memory(SIZE-16,output);
            byte[] state=new byte[40]; Arrays.fill(state,(byte)0x97); put(state,16,first); put(state,20,second); memory(STATE-16,state);
            long statePointer=stateKind==0 ? 0 : STATE;
            callbackState=kind==3 ? statePointer : statePointer!=0 ? statePointer : SLOTS+8*(kind==1 ? 4 : 5);
            callbackResults=results; callbackUnits=units; callbackBytes=nullInput && kind!=3 ? new int[]{0} : input;
            byte[] expectedBank=memory(BANK,192),locale=memory(LOCALE-16,320);
            long expected=0; int processed=0; Integer outputUnit=null;
            if(kind==0) expected=statePointer==0 || first==0 ? 1 : 0;
            else if(kind==4) expected=(SLOTS+limit*8)&MASK;
            else if(kind==5) expected=ERROR;
            else if(kind==6) expected=CONTEXT;
            else if(kind==7) expected=CONTEXT+4;
            else {
                int cap=kind==3 ? 1 : (int)Math.min(nullInput ? 1 : limit,callbackBytes.length);
                int terminal=-1;
                for(int i=0;i<cap;i++) {
                    long status=mode==1 ? results[i] : invalid && callbackBytes[i]%3==2 ? MASK : 1;
                    processed++;
                    if(kind==3 || status!=MASK-1) { terminal=i; break; }
                }
                if(terminal<0) expected=MASK-1;
                else {
                    long status=mode==1 ? results[terminal] : invalid && callbackBytes[terminal]%3==2 ? MASK : 1;
                    int unit=mode==1 ? units[terminal] : callbackBytes[terminal];
                    if(kind==3) { expected=status; if(mode==1 || status!=MASK) outputUnit=unit; }
                    else if(status==MASK) { expected=MASK; put(expectedBank,(int)(ERROR-BANK),4); }
                    else { expected=unit==0 ? 0 : processed; if(kind==2 && !nullInput && !nullOutput) outputUnit=unit; }
                }
                if(mode==1 && callbackState!=0) {
                    long x=get(callbackState),y=get(callbackState+4);
                    for(int i=0;i<processed;i++) { x=(x+callbackBytes[i]+1)&MASK; y^=0x1020304; }
                    byte[] target=statePointer==0 ? expectedBank : state;
                    int offset=statePointer==0 ? (int)(callbackState-BANK) : 16;
                    put(target,offset,x); put(target,offset+4,y);
                }
            }
            if(outputUnit!=null) { output[16]=(byte)(int)outputUnit; output[17]=(byte)(outputUnit>>8); }
            long inputPointer=nullInput ? 0 : PATH;
            register("r0",kind==0 ? statePointer : kind==1 ? inputPointer : nullOutput ? 0 : SIZE);
            register("r1",kind==1 || kind==4 ? limit : kind==3 ? input[0] : inputPointer);
            register("r2",kind==1 || kind==3 ? statePointer : limit); register("r3",statePointer);
            select(rebuilt ? pathEntries[kind] : PATH_START[kind],!rebuilt && kind<5); executing=true;
            long actual=executePath(rebuilt);
            require(actual==expected,"Path exact result kind="+kind+" expected="+expected+" actual="+actual);
            require(callbackIndex==(mode==1 && kind>=1 && kind<=3 ? processed : 0),"Locale callback count");
            require(Arrays.equals(output,memory(SIZE-16,40)),"Path output and guards");
            require(Arrays.equals(state,memory(STATE-16,40)),"Explicit state and guards");
            require(Arrays.equals(expectedBank,memory(BANK,192)),"Default state/error/context and guards");
            require(Arrays.equals(locale,memory(LOCALE-16,320)) && Arrays.equals(in,memory(PATH,2048)),"Locale/input immutability");
            for(byte value:memory(STACK-0x1000,0xe00)) require(value==(byte)0x96,"Path stack guard");
            trace.add("path-end:"+actual+":"+HexFormat.of().formatHex(output)+":"+HexFormat.of().formatHex(state)+":"+HexFormat.of().formatHex(expectedBank));
        }
    }
    void compare(PathMachine a,PathMachine b,int kind,int mode,boolean invalid,int[] input,long limit,int stateKind,
                 boolean nullInput,boolean nullOutput,long first,long second,long[] results,int[] units,boolean thumb,int residue,PrintWriter log) throws Exception {
        try {
            a.direct(false,kind,mode,invalid,input,limit,stateKind,nullInput,nullOutput,first,second,results,units,thumb,residue);
            b.direct(true,kind,mode,invalid,input,limit,stateKind,nullInput,nullOutput,first,second,results,units,thumb,residue);
            require(a.trace.equals(b.trace),"Path original/rebuilt transcript");
        } catch(Exception e) { throw new IllegalStateException("Worker I/O case path="+pathCases+" kind="+kind+" mode="+mode+" input="+Arrays.toString(input)+" limit="+limit,e); }
        log.printf("%d\t%d\t%d\t%s\t%d\t%d\t%s\t%s\t%s\t%d%n",++pathCases,kind,mode,Arrays.toString(input),limit,stateKind,nullInput,nullOutput,thumb,residue);
    }
    @Override void preChecks(byte[] mapped,byte[] binary,Path out) throws Exception {
        PathMachine a=new PathMachine(mapped,binary),b=new PathMachine(mapped,binary);
        try(PrintWriter log=new PrintWriter(Files.newBufferedWriter(out.resolve("path-results.tsv")))) {
            log.println("case\tkind\tmode\tinput\tlimit\tstate\tnull_input\tnull_output\tthumb_callback\tresidue");
            for(int state=0;state<2;state++) for(long first:new long[]{0,1,0x80000000L,MASK}) for(long second:new long[]{0,MASK})
                compare(a,b,0,0,false,new int[]{0},0,state,false,false,first,second,null,null,false,0,log);
            for(long slot:new long[]{0,4,5,0x1fffffffL,0x20000000L,MASK})
                compare(a,b,4,0,false,new int[]{0},slot,1,false,false,1,2,null,null,false,0,log);
            for(int kind=5;kind<8;kind++) compare(a,b,kind,0,false,new int[]{0},0,1,false,false,1,2,null,null,false,0,log);
            // Every input byte, accepted/rejected table cells, and non-callback selector values.
            for(int byteValue=0;byteValue<256;byteValue++) for(int mode:new int[]{0,2,255})
                compare(a,b,3,mode,true,new int[]{byteValue},1,1,false,false,0x12345678L,MASK,null,null,false,byteValue%4,log);
            for(int kind:new int[]{1,2}) for(int state=0;state<2;state++) for(boolean nullIn:new boolean[]{false,true})
            for(boolean nullOut:new boolean[]{false,true}) for(long limit:new long[]{0,1,2,0x105,MASK}) for(int value:new int[]{0,65,128,255})
                compare(a,b,kind,0,true,new int[]{value},limit,state,nullIn,nullOut,0x12345678L,MASK,null,null,false,0,log);
            long[][] statuses={{1},{0},{0x7fffffffL},{MASK},{MASK-1},{MASK-1,1},{MASK-1,MASK},{MASK-1,MASK-1,3}};
            for(int kind:new int[]{1,2,3}) for(int state=0;state<2;state++) for(boolean thumb:new boolean[]{false,true})
            for(int scenario=0;scenario<statuses.length;scenario++) for(boolean zero:new boolean[]{false,true}) {
                long[] result=statuses[scenario]; int[] input={0x80,0xff,0x41},units={zero ? 0 : 0x1234,zero ? 0 : 0xd800,zero ? 0 : 0xffff};
                compare(a,b,kind,1,false,input,result.length,state,false,false,0x12345678L,MASK,result,units,thumb,scenario%4,log);
            }
            // Explicit exhaustion after a callback, null-input forcing one byte, and no-output measurement.
            for(int kind:new int[]{1,2}) for(int state=0;state<2;state++) for(long status:new long[]{1,MASK,MASK-1})
            for(boolean nullIn:new boolean[]{false,true}) for(boolean nullOut:new boolean[]{false,true})
                compare(a,b,kind,1,false,new int[]{0,0xff},nullIn ? 0 : 1,state,nullIn,nullOut,0,0,new long[]{status},new int[]{0x4321},true,3,log);
        }
    }
    @Override String extraChecks(byte[] mapped,byte[] binary,Path out) throws Exception {
        String inherited=super.extraChecks(mapped,binary,out);
        StringBuilder listing=new StringBuilder(); int count=0;
        for(int i=0;i<8;i++) {
            var f=getFunctionAt(toAddr(PATH_START[i])); require(f!=null && f.getBody().getMaxAddress().getOffset()==PATH_END[i]-1,"Path saved extent");
            for(var instruction:currentProgram.getListing().getInstructions(f.getBody(),true)) {
                long pc=instruction.getAddress().getOffset(); require(visited.contains(pc),"Unvisited path instruction "+Long.toHexString(pc)); count++;
                listing.append(String.format("%08x %s %s visited=true%n",pc,HexFormat.of().formatHex(instruction.getBytes()),instruction));
            }
        }
        for(long[] literal:new long[][]{{0x2c6c50,CONTEXT},{0x2c6940,SLOTS},{0x2c689c,ERROR},{0x2c644c,0}})
            require(Integer.toUnsignedLong(currentProgram.getMemory().getInt(toAddr(literal[0])))==literal[1],"Path literal identity");
        Files.writeString(out.resolve("original-path-ghidra.txt"),listing);
        return inherited+String.format(Locale.ROOT,",\"direct_path_cases\":%d,\"connected_path_calls_both\":%d,\"locale_callback_calls_both\":%d,\"path_max_steps\":%d,\"new_path_instruction_addresses\":%d,\"path_conversion_recovered\":true,\"locale_callbacks_modeled\":true,\"locale_initialization_recovered\":false,\"legacy_direct_modes_retain_path_models\":true",pathCases,connectedPaths,callbackCalls,pathSteps,count);
    }
    @Override public void run() throws Exception {
        var lines=Files.readAllLines(Path.of(getScriptArgs()[0]).resolve("entries.txt"));
        for(int i=0;i<8;i++) pathEntries[i]=Long.parseLong(lines.get(19+i));
        super.run();
    }
}
