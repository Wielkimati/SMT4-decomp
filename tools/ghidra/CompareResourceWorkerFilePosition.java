// Lower file size/cache, seek-origin and tail position entry, with OS size modeled.
// @category SMT4
import ghidra.pcode.emu.PcodeThread;
import ghidra.pcode.utils.Utils;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.pcode.PcodeOp;
import java.nio.file.*;
import java.util.*;
import java.io.*;

public class CompareResourceWorkerFilePosition extends CompareResourceWorkerFileMethods {
    static final long[] POSITION={0x2bb8ec,0x2aca78,0x146458};
    static final long[] POSITION_END={0x2bb944,0x2acb24,0x1464f4};
    static final long OS_SIZE=0x2a8914, BAD_POSITION=0xe0e046c1L, BAD_ORIGIN=0xe0e046bdL;
    long[] positionEntries=new long[3];
    int positionCases, positionSteps, osCalls, connectedPositionCalls, persistentSequences;
    long sizeServiceTarget(boolean path) { return OS_SIZE; }
    @Override boolean originalCode(long pc) {
        for(int k=0;k<3;k++) if(within(pc,4,POSITION[k],POSITION_END[k])) return true;
        return super.originalCode(pc);
    }
    @Override long lowerTarget(boolean path,int kind) {
        return path && kind<2 ? positionEntries[kind] : LOWER[kind];
    }
    @Override IoMachine makeMachine(byte[] mapped,byte[] binary) { return new PositionMachine(mapped,binary); }
    static long pair(byte[] b,int offset) { return word(b,offset) | (word(b,offset+4)<<32); }
    static void pair(byte[] b,int offset,long value) { put(b,offset,value&MASK); put(b,offset+4,value>>>32); }
    class Plan {
        byte[] object;
        long result, output;
        boolean outputWritten;
        List<byte[]> beforeService=new ArrayList<>();
        long[] statuses, sizes;
        Plan(byte[] initial,long[] statuses,long[] sizes) {
            object=initial.clone(); this.statuses=statuses; this.sizes=sizes;
        }
        long query() {
            int i=beforeService.size(); require(i<statuses.length,"Oracle service domain");
            beforeService.add(object.clone()); result=statuses[i];
            long size=(result&0x80000000L)==0 ? sizes[i] : 0;
            pair(object,16,size); return size;
        }
    }
    // Independent signed Java-long oracle; Java addition has defined wraparound.
    Plan oracle(int kind,byte[] initial,long offset,long origin,long[] statuses,long[] sizes) {
        Plan p=new Plan(initial,statuses,sizes);
        if(kind==0 || kind==3) {
            p.output=p.query(); p.outputWritten=(p.result&0x80000000L)==0; return p;
        }
        long target=offset;
        if(kind!=2) {
            if(origin==1) target+=pair(initial,8);
            else if(origin==2) {
                target+=p.query();
                if((p.result&0x80000000L)!=0) return p;
            } else if(origin!=0) { p.result=BAD_ORIGIN; return p; }
        }
        if(target<0) { p.result=BAD_POSITION; return p; }
        if(target>=pair(p.object,16)) {
            long size=p.query();
            if((p.result&0x80000000L)!=0) return p;
            if(size<target) { p.result=BAD_POSITION; return p; }
        }
        pair(p.object,8,target); p.result=0; return p;
    }
    class PositionMachine extends MethodMachine {
        byte[] finalFileState;
        PositionMachine(byte[] mapped,byte[] binary) { super(mapped,binary); }
        @Override void setupAllocation(byte[] initial,long length,long allocation) {
            super.setupAllocation(initial,length,allocation);
            byte[] out=new byte[40]; Arrays.fill(out,(byte)0x5a); memory(SIZE-16,out);
            finalFileState=null;
        }
        @Override public void beforeStore(PcodeThread<byte[]> t,PcodeOp op,AddressSpace space,byte[] offset,int size,byte[] value) {
            long a=Utils.bytesToLong(offset,offset.length,false);
            if(within(a,size,SIZE,SIZE+8)) return;
            super.beforeStore(t,op,space,offset,size,value);
        }
        @Override public void beforeLoad(PcodeThread<byte[]> t,PcodeOp op,AddressSpace space,byte[] offset,int size) {
            long a=Utils.bytesToLong(offset,offset.length,false);
            if(within(a,size,SIZE,SIZE+8)) return;
            super.beforeLoad(t,op,space,offset,size);
        }
        @Override void expectedFileState(byte[] expected) {
            require(finalFileState!=null,"Connected final state oracle");
            System.arraycopy(finalFileState,8,expected,8,16);
        }
        // Optional concrete service chain; the default preserves the original model.
        void executeSizeService(boolean path,long status,long value) throws Exception {
            long out=register("r0");
            if((status&0x80000000L)==0 || (status&1)!=0) {
                if((status&0x80000000L)!=0) value=0xfedcba9876543210L;
                writeWord(out,value&MASK); writeWord(out+4,value>>>32);
            }
            externalReturn(status);
        }
        boolean executePosition(boolean path,int kind,long offset,long origin,long[] statuses,long[] sizes) throws Exception {
            long savedSp=register("sp"),returnPc=register("lr");
            long[] saved=new long[8]; for(int r=4;r<=11;r++) saved[r-4]=register("r"+r);
            byte[] before=memory(OBJ,24), outBefore=memory(SIZE-16,40);
            Plan p=oracle(kind,before,offset,origin,statuses,sizes);
            int query=0,diagnostic=0,steps=0;
            boolean returned=true;
            while(thread.getCounter().getOffset()!=returnPc) {
                long pc=thread.getCounter().getOffset();
                if(pc==sizeServiceTarget(path)) {
                    require(query<p.beforeService.size(),"Unexpected OS size call");
                    require(Arrays.equals(memory(OBJ,24),p.beforeService.get(query)),"Cache/cursor before OS call");
                    require(register("r1")== (word(before,4)&~1L),"OS untagged handle");
                    long out=register("r0");
                    require((register("sp")&7)==0 && (out&7)==0 && within(out,8,register("sp"),savedSp),"OS output/frame layout");
                    long status=statuses[query],value=sizes[query];
                    if((status&0x80000000L)!=0 && (status&1)!=0) value=0xfedcba9876543210L;
                    trace.add("os-size:"+query+":"+register("r1")+":"+status+":"+Long.toUnsignedString(value)+":"+HexFormat.of().formatHex(memory(OBJ,24)));
                    query++; osCalls++; dependencyCalls++; executeSizeService(path,status,value); continue;
                }
                if(pc==0x2bbd70) {
                    require((kind==3 || kind==4) && (p.result&0x80000000L)!=0 && ++diagnostic==1,"Position diagnostic predicate");
                    require(register("r0")==p.result && register("r1")== (kind==3 ? 0x3dfc70 : 0x354f8c),"Position diagnostic arguments");
                    require((register("sp")&7)==0,"Position diagnostic alignment");
                    trace.add("position-diagnostic:"+p.result+":"+register("r1")); dependencyCalls++;
                    if(kind==3) { returned=false; break; }
                    externalReturn(0x87654321L); continue;
                }
                require(path ? within(pc,4,BUILD,BUILD+codeSize) : originalCode(pc),"Position PC "+Long.toHexString(pc));
                if(!path) visited.add(pc);
                require(++steps<256,"Position instruction budget"); monitor.checkCancelled(); thread.stepInstruction();
            }
            require(query==p.beforeService.size(),"Missing OS query / cache equality");
            require(Arrays.equals(memory(OBJ,24),p.object),"Position object/cache/cursor oracle");
            byte[] expectedOut=outBefore.clone();
            if(kind==0 && p.outputWritten) pair(expectedOut,16,p.output);
            require(Arrays.equals(memory(SIZE-16,40),expectedOut),"Size output/failure/guards");
            require(diagnostic==((kind>=3 && (p.result&0x80000000L)!=0) ? 1 : 0),"Position diagnostic count");
            if(returned) {
                require(register("sp")==savedSp,"Position stack restoration");
                for(int r=4;r<=11;r++) require(register("r"+r)==saved[r-4],"Position saved register");
                if(kind<3) require(register("r0")==p.result,"Exact lower result");
                if(kind==3) require(register("r0")== (p.output&MASK) && register("r1")== (p.output>>>32),"Size adapter full return");
            }
            finalFileState=p.object; positionSteps=Math.max(positionSteps,steps);
            trace.add("position-end:"+kind+":"+p.result+":"+HexFormat.of().formatHex(p.object));
            return returned;
        }
        @Override boolean executeMethod(boolean path,int kind,long result,long lo,long hi,
                long origin,long count,long data,long size,boolean terminalFailure) throws Exception {
            if(kind==2) return super.executeMethod(path,kind,result,lo,hi,origin,count,data,size,terminalFailure);
            if(kind==0) hi=cases%3==0 ? 0 : cases%3==1 ? 1 : hi;
            long value=kind==0 ? lo|(hi<<32) : length;
            boolean returned=executePosition(path,kind==0 ? 3 : 4,0,0,new long[]{result,0},new long[]{value,value});
            require(returned,"Connected nonterminal domain"); connectedPositionCalls++; return true;
        }
        void direct(boolean path,int kind,long handle,long cursor,long cache,long offset,long origin,
                long[] statuses,long[] sizes,boolean retain) throws Exception {
            initialize(path,0,new byte[0x144]); destroyed=false; trace.clear();
            if(!retain) {
                byte[] guard=new byte[OLEN]; new Random(0x146458).nextBytes(guard); memory(OBASE,guard);
                byte[] object=new byte[24]; put(object,0,0xa55a1234L); put(object,4,handle);
                pair(object,8,cursor); pair(object,16,cache); memory(OBJ,object);
            }
            byte[] guardBefore=memory(OBASE,OLEN),out=new byte[40]; Arrays.fill(out,(byte)0x5a); memory(SIZE-16,out);
            register("sp",STACK-16); writeWord(STACK-16,origin);
            register("r0",kind>=3 ? OBJ : OBJ+4); register("r1",kind==0 ? SIZE : 0xa1b2c3d4L);
            register("r2",offset&MASK); register("r3",offset>>>32);
            thread.overrideCounter(toAddr(path ? (kind<3 ? positionEntries[kind] : methodEntries[kind-3]) :
                (kind<3 ? POSITION[kind] : METHODS[kind-3]))); executing=true;
            executePosition(path,kind,offset,origin,statuses,sizes);
            System.arraycopy(finalFileState,0,guardBefore,(int)(OBJ-OBASE),24);
            require(Arrays.equals(memory(OBASE,OLEN),guardBefore),"Position object guards");
            for(byte value:memory(STACK-0x1000,0xf00)) require(value==(byte)0x96,"Position stack guard");
            require(get(STACK-16)==origin,"Position fifth-word preservation");
        }
    }
    @Override String extraChecks(byte[] mapped,byte[] binary,Path out) throws Exception {
        // Retain the earlier isolated adapter and allocation probes at their model boundary.
        String inherited=super.extraChecks(mapped,binary,out);
        PositionMachine a=new PositionMachine(mapped,binary),b=new PositionMachine(mapped,binary);
        long[] offsets={0,1,0xffffffffL,0x100000000L,Long.MAX_VALUE,Long.MIN_VALUE,-1};
        long[] caches={0,1,0x100000000L,Long.MAX_VALUE,Long.MIN_VALUE,-1};
        long[] serviceSizes={0,1,0xffffffffL,Long.MAX_VALUE,Long.MIN_VALUE,0x100000001L,7};
        long[] serviceStatuses={0,1,0x7fffffffL,0,0,0x80000000L,MASK};
        try(PrintWriter log=new PrintWriter(Files.newBufferedWriter(out.resolve("position-results.tsv")))) {
            log.println("case\tkind\tcursor\tcache\toffset\torigin\tstatus0\tsize0\tstatus1\tsize1\tretain");
            for(int kind=0;kind<5;kind++) {
                for(int i=0;i<(kind==0 || kind==3 ? 1 : offsets.length);i++)
                for(int c=0;c<(kind==0 || kind==3 ? 3 : caches.length);c++)
                for(int s=0;s<serviceSizes.length;s++) {
                    long offset=offsets[i],cache=(kind==0 || kind==3) ? new long[]{1,0x100000001L,Long.MIN_VALUE}[c] : caches[c],cursor=offsets[(i+c+2)%offsets.length];
                    long[] origins=(kind==1 || kind==4) ? new long[]{0,1,2,3,MASK} : new long[]{0};
                    for(long origin:origins) {
                        long status=serviceStatuses[s],value=serviceSizes[s];
                        // Distinct second response tests end-relative refresh, shrink and failure.
                        long secondStatus=serviceStatuses[(s+1)%serviceStatuses.length];
                        long secondSize=serviceSizes[(s+2)%serviceSizes.length];
                        compare(a,b,kind,cursor,cache,offset,origin,new long[]{status,secondStatus},new long[]{value,secondSize},false,log);
                    }
                }
            }
            // Persistent cache/cursor sequences: hit, equality refresh, failure, recovery,
            // end-relative two-query paths and invalid-origin preservation.
            for(long initialCursor:new long[]{0,0xffffffffL,Long.MAX_VALUE,Long.MIN_VALUE}) {
                compare(a,b,0,initialCursor,99,0,0,new long[]{0,0},new long[]{10,10},false,log);
                for(long[] step:new long[][]{{2,5,0,0,20},{2,10,0,0,20},{2,20,0,MASK,30},
                        {2,0,0,1,3},{1,-1,2,0,7},{1,0,2,0,7},{1,1,2,0,7},{1,0,3,0,100}})
                    compare(a,b,(int)step[0],0,0,step[1],step[2],new long[]{step[3],0},new long[]{step[4],step[4]+1},true,log);
                persistentSequences++;
            }
        }
        StringBuilder listing=new StringBuilder(); int newVisited=0;
        for(int k=0;k<3;k++) for(long pc=POSITION[k];pc<POSITION_END[k];pc+=4) {
            require(visited.contains(pc),"Unvisited position instruction "+Long.toHexString(pc)); newVisited++;
            var ins=currentProgram.getListing().getInstructionAt(toAddr(pc)); require(ins!=null,"Position instruction boundary");
            listing.append(String.format("%08x %s%n",pc,ins));
        }
        require(currentProgram.getMemory().getInt(toAddr(0x1464f4))==(int)BAD_POSITION &&
            currentProgram.getMemory().getInt(toAddr(0x2acb24))==(int)BAD_ORIGIN,"Original error literals");
        var f=getFunctionContaining(toAddr(0x146458));
        require(f!=null && f.getEntryPoint().getOffset()==0x2aca78,"Recorded merged Ghidra boundary");
        Files.writeString(out.resolve("original-position-ghidra.txt"),listing+"Tail entry 00146458 is merged into Ghidra function 002aca78; decoded independently.\n");
        return inherited+String.format(Locale.ROOT,",\"direct_position_cases\":%d,\"persistent_position_sequences\":%d,\"connected_position_calls_both_paths\":%d,\"os_size_calls_both_paths\":%d,\"position_max_steps\":%d,\"new_position_instruction_addresses\":%d,\"size_seek_position_recovered\":true,\"os_size_read_diagnostic_modeled\":true,\"legacy_direct_adapter_lower_calls_modeled\":true",
            positionCases,persistentSequences,connectedPositionCalls,osCalls,positionSteps,newVisited);
    }
    void compare(PositionMachine a,PositionMachine b,int kind,long cursor,long cache,long offset,long origin,
            long[] statuses,long[] sizes,boolean retain,PrintWriter log) throws Exception {
        long handle=new long[]{0,1,0x80000000L,MASK,0x4561}[positionCases%5];
        try {
            a.direct(false,kind,handle,cursor,cache,offset,origin,statuses,sizes,retain);
            b.direct(true,kind,handle,cursor,cache,offset,origin,statuses,sizes,retain);
            require(a.trace.equals(b.trace),"Position original/rebuilt service and state trace");
        } catch(Exception e) { throw new IllegalStateException("Worker I/O case position="+positionCases+" kind="+kind+" offset="+offset+" origin="+origin,e); }
        log.printf("%d\t%d\t%d\t%d\t%d\t%d\t%d\t%d\t%d\t%d\t%s%n",++positionCases,kind,cursor,cache,offset,origin,statuses[0],sizes[0],statuses[1],sizes[1],retain);
    }
    @Override public void run() throws Exception {
        var lines=Files.readAllLines(Path.of(getScriptArgs()[0]).resolve("entries.txt"));
        for(int k=0;k<3;k++) positionEntries[k]=Long.parseLong(lines.get(7+k));
        super.run();
    }
}
