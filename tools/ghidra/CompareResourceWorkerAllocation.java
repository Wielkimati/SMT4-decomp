// Worker I/O with executed object/lower/data allocators and retained guarded bytes.
// @category SMT4
import ghidra.pcode.emu.PcodeThread;
import ghidra.pcode.utils.Utils;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.pcode.PcodeOp;
import java.nio.file.*;
import java.util.*;

public class CompareResourceWorkerAllocation extends CompareResourceWorkerIo {
    static final long DATA=0x908000, OBASE=OBJ-256, DBASE=DATA-256;
    static final int OLEN=464, DLEN=1280;
    long objectEntry,dataEntry,lowerEntry,clearEntry;
    boolean recoverClear; int executedClears;
    int allocations,directCases,allocationSteps;
    @Override boolean originalCode(long pc) {
        return super.originalCode(pc) || within(pc,4,0x2c244c,0x2c2480) ||
            within(pc,4,0x2c5544,0x2c5634) || within(pc,4,0x2bf7ec,0x2bf8ac);
    }
    @Override IoMachine makeMachine(byte[] mapped,byte[] binary) { return new AllocationMachine(mapped,binary); }
    class AllocationMachine extends IoMachine {
        byte[] expectedObject,expectedData;
        long flags,alignment,requestedAlignment,length,buffer,rawObject,rawData;
        boolean active;
        int allocationCount;
        AllocationMachine(byte[] mapped,byte[] binary) { super(mapped,binary); }
        boolean allocationMemory(long a,int size) {
            return within(a,size,OBASE,OBASE+OLEN) || within(a,size,DBASE,DBASE+DLEN);
        }
        @Override public void beforeStore(PcodeThread<byte[]> t,PcodeOp op,AddressSpace space,byte[] offset,int size,byte[] value) {
            long a=Utils.bytesToLong(offset,offset.length,false);
            if(active && allocationMemory(a,size)) return;
            super.beforeStore(t,op,space,offset,size,value);
        }
        @Override public void beforeLoad(PcodeThread<byte[]> t,PcodeOp op,AddressSpace space,byte[] offset,int size) {
            long a=Utils.bytesToLong(offset,offset.length,false);
            if(allocationMemory(a,size)) return;
            super.beforeLoad(t,op,space,offset,size);
        }
        @Override void setupAllocation(byte[] initial,long size,long allocation) {
            flags=word(initial,36); requestedAlignment=word(initial,40);
            alignment=Math.max(128,requestedAlignment); length=size; buffer=word(initial,12);
            require(allocation==DATA && size<=1024,"Connected allocation domain");
            expectedObject=new byte[OLEN]; expectedData=new byte[DLEN];
            new Random(0x244c+cases).nextBytes(expectedObject); new Random(0xf7ec+cases).nextBytes(expectedData);
            memory(OBASE,expectedObject); memory(DBASE,expectedData);
            rawObject=OBJ-184+4*(cases%32); rawData=DATA-60-4*(cases%32);
            // The minimum alignment can put an exactly preceding boundary at DATA-128.
            if((DATA-rawData-60)>=alignment) rawData+=128;
            active=false; allocationCount=0;
        }
        void verifyBytes() {
            require(Arrays.equals(expectedObject,memory(OBASE,OLEN)),"Object allocation guards/metadata/payload");
            require(Arrays.equals(expectedData,memory(DBASE,DLEN)),"Data allocation guards/metadata/payload");
        }
        void syncObjectPayload() {
            System.arraycopy(memory(OBJ,24),0,expectedObject,(int)(OBJ-OBASE),24);
        }
        void modelReadPayload() {
            byte[] content=new byte[(int)length];
            for(int i=0;i<content.length;i++) content[i]=(byte)(i*17+cases);
            memory(DATA,content); System.arraycopy(content,0,expectedData,(int)(DATA-DBASE),content.length);
        }
        @Override void event(long pc) {
            if(!active) {
                syncObjectPayload();
                if(pc==0x73000c) modelReadPayload();
                verifyBytes();
            }
            super.event(pc);
            trace.add("allocation-bytes:"+HexFormat.of().formatHex(memory(OBASE,OLEN))+":"+HexFormat.of().formatHex(memory(DBASE,DLEN)));
        }
        @Override boolean allocationStep(long pc,boolean rebuiltPath) throws Exception {
            boolean object=pc==(rebuiltPath ? objectEntry : 0x2c244c);
            if(!object && pc!=(rebuiltPath ? dataEntry : 0x2bf7ec)) return false;
            require(!active,"Nested allocation wrapper");
            syncObjectPayload(); verifyBytes(); event(object ? 0x2c244c : 0x2bf7ec);
            if(object) require(register("r0")==24,"Object wrapper caller size");
            else require(register("r0")==((flags==1 || flags==17) ? 0x10000 : 0x100) &&
                register("r1")==256 && register("r2")==0 && register("r3")==length &&
                get(register("sp"))==requestedAlignment &&
                get(register("sp")+4)==((flags==16 || flags==17) ? 0 : 1),"Data wrapper caller arguments");
            long returnPc=register("lr"), savedSp=register("sp"), user=object ? OBJ : DATA;
            long raw=object ? rawObject : rawData, size=object ? 24 : length, align=object ? 128 : alignment;
            long rounded=((size+2*align+59)/align)*align;
            long[] saved=new long[8]; for(int r=4;r<=11;r++) saved[r-4]=register("r"+r);
            byte[] expected=object ? expectedObject : expectedData;
            long base=object ? OBASE : DBASE;
            int stage=0,steps=0; active=true;
            long[] services={0x2c3afc,0x2b26f0,0x2b260c,0x2c3b9c,0x2c3a78};
            while(thread.getCounter().getOffset()!=returnPc) {
                pc=thread.getCounter().getOffset();
                if(recoverClear && rebuiltPath && pc==clearEntry)pc=0x2c3b9c;
                final long boundary=pc;
                if(Arrays.stream(services).anyMatch(v->v==boundary)) {
                    require(stage<services.length && pc==services[stage],"Allocation dependency order");
                    require((register("sp")&7)==0,"Allocation call alignment");
                    long result=0;
                    if(stage==0 || stage==4) {
                        require(register("r0")==get(LOCK) && get(GLOBAL+4)==0x1234,"Allocation lock reload/busy");
                        if(stage==4) verifyBytes();
                    } else if(stage==1) {
                        require(register("r0")== (object ? 256 : ((flags==1 || flags==17) ? 0x10000 : 256)) &&
                            register("r1")==256 && register("r2")==0 && register("r3")==rounded &&
                            get(register("sp"))==(object ? 1 : ((flags==16 || flags==17) ? 0 : 1)),"Raw allocation argument oracle");
                        verifyBytes(); result=raw;
                    } else if(stage==2) {
                        require(register("r0")==raw,"Registration raw pointer");
                        put(expected,(int)(raw-base),rounded); put(expected,(int)(raw-base)+4,align);
                        put(expected,(int)(user-base)-4,raw); verifyBytes();
                        // Explicit registration model; retain its unrelated header writes.
                        put(expected,(int)(raw-base)+8,0xa55a1234L); writeWord(raw+8,0xa55a1234L);
                        result=MASK;
                    } else {
                        require(register("r0")==user && register("r1")==size,"Allocation clear arguments");
                        verifyBytes();
                        Arrays.fill(expected,(int)(user-base),(int)(user-base+size),(byte)0);
                        if(recoverClear) {
                            long ret=register("lr"),sp=register("sp"); int clearSteps=0;
                            do {
                                long atPC=thread.getCounter().getOffset();
                                require(rebuiltPath?within(atPC,4,BUILD,BUILD+codeSize):within(atPC,4,0x2c3b9c,0x2c3bdc)||within(atPC,4,0x2c4b88,0x2c4bd8),"Allocation zero PC");
                                if(!rebuiltPath)visited.add(atPC);
                                require(++clearSteps<4096,"Allocation zero budget");thread.stepInstruction();
                            }while(thread.getCounter().getOffset()!=ret);
                            require(register("sp")==sp,"Allocation zero SP");verifyBytes();executedClears++;stage++;
                            trace.add("executed-zero:"+user+":"+size);continue;
                        }
                        memory(user,new byte[(int)size]);
                        result=0x87654321L;
                    }
                    writeWord(LOCK,(get(LOCK)+0x101)&MASK);
                    trace.add("allocator:"+pc+":"+get(LOCK)+":"+HexFormat.of().formatHex(memory(base,expected.length)));
                    dependencyCalls++; stage++; externalReturn(result); continue;
                }
                require(rebuiltPath ? within(pc,4,BUILD,BUILD+codeSize) : originalCode(pc),"Allocation PC "+Long.toHexString(pc));
                if(!rebuiltPath) visited.add(pc);
                require(++steps<256,"Allocation budget"); monitor.checkCancelled(); thread.stepInstruction();
            }
            require(stage==5 && register("r0")==user && register("sp")==savedSp,"Allocation return contract");
            for(int r=4;r<=11;r++) require(register("r"+r)==saved[r-4],"Allocation saved register");
            verifyBytes(); active=false; allocationCount++; allocations++; allocationSteps=Math.max(allocationSteps,steps);
            return true;
        }
        @Override void finishAllocation() {
            syncObjectPayload(); verifyBytes(); require(allocationCount==(buffer==0 ? 2 : 1),"Connected allocation count");
        }
        void directCall(boolean rebuiltPath,long size,long result) throws Exception {
            initialize(rebuiltPath,0,new byte[0x144]); register("r0",size);
            thread.overrideCounter(toAddr(rebuiltPath ? objectEntry : 0x2c244c)); executing=true;
            int calls=0,steps=0;
            while(thread.getCounter().getOffset()!=RETURN) {
                long pc=thread.getCounter().getOffset();
                if(pc==(rebuiltPath ? lowerEntry : 0x2c5544)) {
                    require(++calls==1 && register("r0")==256 && register("r1")==256 &&
                        register("r2")==0 && register("r3")==size && get(register("sp"))==1 &&
                        (register("sp")&7)==0,"Object direct forwarding");
                    externalReturn(result); continue;
                }
                require(rebuiltPath ? within(pc,4,BUILD,BUILD+codeSize) : within(pc,4,0x2c244c,0x2c2480),"Object direct PC");
                if(!rebuiltPath) visited.add(pc);
                require(++steps<32,"Object direct budget"); thread.stepInstruction();
            }
            require(calls==1 && register("r0")==result,"Object direct return"); finish(steps);
            for(byte value:memory(STACK-0x1000,0xf00)) require(value==(byte)0x96,"Object direct stack guard");
        }
    }
    @Override String extraChecks(byte[] mapped,byte[] binary,Path out) throws Exception {
        AllocationMachine a=new AllocationMachine(mapped,binary),b=new AllocationMachine(mapped,binary);
        for(long size:new long[]{0,1,23,24,25,127,128,255,256,0x7fffffffL,0x80000000L,MASK})
            for(long result:new long[]{0,OBJ,0x80000000L,MASK}) {
                try { a.directCall(false,size,result); b.directCall(true,size,result); }
                catch(Exception e) { throw new IllegalStateException("Worker I/O case direct size="+size+" result="+result,e); }
                directCases++;
            }
        var function=currentProgram.getFunctionManager().getFunctionAt(toAddr(0x2c244c));
        require(function!=null && function.getBody().getMaxAddress().getOffset()==0x2c247f,"Object Ghidra boundary");
        require(currentProgram.getMemory().getInt(toAddr(0x2c2480))==0x409b24,"Object literal");
        StringBuilder listing=new StringBuilder();
        for(long pc=0x2c244c;pc<0x2c2480;pc+=4) {
            require(visited.contains(pc),"Unvisited object instruction");
            listing.append(String.format("%08x %s%n",pc,currentProgram.getListing().getInstructionAt(toAddr(pc))));
        }
        Files.writeString(out.resolve("original-object-ghidra.txt"),listing+"Literal 002c2480 = 00409b24\n");
        String summary=String.format(Locale.ROOT,",\"direct_object_cases\":%d,\"executed_allocations_both_paths\":%d,\"allocation_max_steps\":%d,\"allocation_wrappers_recovered\":true,\"raw_registration_zero_locks_modeled\":true",directCases,allocations,allocationSteps);
        if(recoverClear)summary=summary.replace("raw_registration_zero_locks_modeled","raw_registration_locks_modeled")+",\"clearing_recovered\":true,\"executed_clear_calls_both\":"+executedClears;
        return summary;
    }
    @Override public void run() throws Exception {
        recoveredAllocation=true;
        Path clearFile=Path.of(getScriptArgs()[0]).resolve("clear-entry.txt");
        recoverClear=Files.exists(clearFile);
        if(recoverClear)clearEntry=Long.parseLong(Files.readString(clearFile).trim());
        var lines=Files.readAllLines(Path.of(getScriptArgs()[0]).resolve("entries.txt"));
        objectEntry=Long.parseLong(lines.get(1)); dataEntry=Long.parseLong(lines.get(2)); lowerEntry=Long.parseLong(lines.get(3));
        super.run();
    }
}
