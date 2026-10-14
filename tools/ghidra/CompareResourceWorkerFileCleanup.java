// Cleanup/destruction and close dispatch, with explicit service/release boundaries.
// @category SMT4
import ghidra.pcode.emu.PcodeThread;
import ghidra.pcode.utils.Utils;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.pcode.PcodeOp;
import java.nio.file.*;
import java.util.*;
import java.io.*;

public class CompareResourceWorkerFileCleanup extends CompareResourceWorkerFileOpen {
    static final long[] CLEAN={0x2bb81c,0x2bb824,0x354fa4,0x2b9450,0x2b2580};
    static final long[] CLEAN_END={0x2bb824,0x2bb85c,0x354fb8,0x2b9468,0x2b2590};
    static final long CLOSE_OBJECT=0x90b000,CLOSE_VT=0x90b100,CLOSE_SERVICE=0x750000;
    static final long RELEASE=0x2c43b4,DIAGNOSTIC=0x2bce9c;
    long[] cleanEntries=new long[5],breakEntries=new long[3];
    boolean recoverBreak;
    boolean breakCall(CleanupMachine m,boolean path,long reason,long payload,boolean terminal,int effect,long replacement) throws Exception {
        throw new IllegalStateException("Break recovery requires CompareResourceBreak");
    }
    int cleanupCases,terminalCleanupCases,connectedCloses,connectedDestructors,cleanupSteps,serviceCloses,releaseCalls;
    @Override boolean originalCode(long pc) {
        for(int i=0;i<CLEAN.length;i++) if(within(pc,4,CLEAN[i],CLEAN_END[i])) return true;
        return super.originalCode(pc);
    }
    @Override IoMachine makeMachine(byte[] mapped,byte[] binary) { return new CleanupMachine(mapped,binary); }
    class CleanupMachine extends OpenMachine {
        boolean releasedObject,breakActive;
        int breakReads,breakWrites;
        long cleanupPayload=0x12340002L;
        @Override long releasePayload() { return recoverBreak ? new long[]{0,1,0x80000000L,MASK}[(cases/4)%4] : super.releasePayload(); }
        @Override long precloseTarget(boolean path) { return recoverBreak && path ? breakEntries[0] : DIAGNOSTIC; }
        @Override long executePreclose(boolean path,int effect) throws Exception {
            if(!recoverBreak) return super.executePreclose(path,effect);
            require(register("r2")==releasePayload(),"Worker release r2 reaches break");
            breakCall(this,path,0,releasePayload(),false,effect==2 ? 1 : 0,precloseReplacement());
            return register("r0");
        }
        CleanupMachine(byte[] mapped,byte[] binary) { super(mapped,binary); }
        @Override long closeTarget(boolean path) { return path ? cleanEntries[3] : CLEAN[3]; }
        @Override long precloseReplacement() { return CLOSE_OBJECT+65; }
        @Override public void beforeLoad(PcodeThread<byte[]> t,PcodeOp op,AddressSpace space,byte[] offset,int size) {
            long a=Utils.bytesToLong(offset,offset.length,false);
            if(breakActive && a==0x44e450 && size==4) breakReads++;
            require(!releasedObject || !within(a,size,OBJ,OBJ+24),"Object read after release");
            if(within(a,size,CLOSE_OBJECT-16,CLOSE_OBJECT+512)) return;
            super.beforeLoad(t,op,space,offset,size);
        }
        void cleanupFixtures() {
            byte[] data=new byte[528]; new Random(CLEAN[0]).nextBytes(data); memory(CLOSE_OBJECT-16,data);
            for(int i=0;i<3;i++) writeWord(CLOSE_OBJECT+32*i,CLOSE_VT);
            writeWord(CLOSE_VT+0x2c,CLOSE_SERVICE);
        }
        @Override void setupAllocation(byte[] initial,long length,long allocation) {
            super.setupAllocation(initial,length,allocation); cleanupFixtures();
        }
        @Override void call(boolean path,byte[] initial,long open,long read,long handle,
                long length,long allocation,int profile,int effect) throws Exception {
            releasedObject=false;
            // Valid synthetic backend objects replace opaque old-mode handle words.
            long valid=handle<2 ? handle : handle==0x4560 ? CLOSE_OBJECT : handle==0x4561 ? CLOSE_OBJECT+1 :
                handle==0x80000000L ? CLOSE_OBJECT+32 : CLOSE_OBJECT+33;
            super.call(path,initial,open,read,valid,length,allocation,profile,effect);
        }
        boolean executeCleanup(boolean path,int kind,long argument,long initialHandle,long replacement,
                int effect,boolean terminal) throws Exception {
            releasedObject=false;
            long returnPc=register("lr"),sp=register("sp"),payload=register("r2");
            long[] saved=new long[8]; for(int r=4;r<=11;r++) saved[r-4]=register("r"+r);
            byte[] objectBefore=memory(OBJ,24),backendBefore=memory(CLOSE_OBJECT-16,528);
            boolean objectKind=kind<=2,closes=objectKind && (initialHandle&~1L)!=0;
            boolean diagnostic=closes && (initialHandle&1)!=0;
            long closeArgument=objectKind ? (diagnostic && effect==1 ? replacement : initialHandle)&~1L : argument;
            int diags=0,closeCalls=0,releases=0,steps=0;
            while(thread.getCounter().getOffset()!=returnPc) {
                long pc=thread.getCounter().getOffset();
                if(pc==precloseTarget(path)) {
                    require(diagnostic && ++diags==1 && register("r0")==initialHandle,"Cleanup diagnostic predicate/argument");
                    require((register("sp")&7)==0 && closeCalls==0 && releases==0,"Cleanup diagnostic order/alignment");
                    require(Arrays.equals(objectBefore,memory(OBJ,24)),"Object changed before diagnostic");
                    trace.add("cleanup-diagnostic:"+initialHandle); dependencyCalls++;
                    if(recoverBreak) {
                        boolean returned=breakCall(this,path,0,payload,terminal,effect,replacement);
                        if(!returned) { terminalCleanupCases++; return false; }
                        continue;
                    }
                    if(terminal) { terminalCleanupCases++; return false; }
                    if(effect==1) writeWord(OBJ+4,replacement);
                    externalReturn(0x87654321L); continue;
                }
                if(pc==CLOSE_SERVICE) {
                    require((kind==3 && argument!=0 || closes && closeArgument!=0) && ++closeCalls==1,
                        "Cleanup close predicate/count");
                    require(register("r0")==closeArgument && (register("sp")&7)==0,"Close vtable slot/receiver/alignment");
                    require(releases==0 && diags==(diagnostic ? 1 : 0),"Close before release/after diagnostic");
                    if(objectKind) require(get(OBJ+4)==(diagnostic && effect==1 ? replacement : initialHandle),"Handle cleared before close");
                    trace.add("backend-close:"+closeArgument+":"+get(OBJ+4)); serviceCloses++; dependencyCalls++;
                    // A backend may change the caller-visible word; cleanup still clears after return.
                    if(objectKind && effect==2) writeWord(OBJ+4,0x12345679L);
                    externalReturn(0x87654321L); continue;
                }
                if(pc==RELEASE) {
                    require((kind==2 || kind==4 && argument!=0) && ++releases==1 && register("r0")==argument,"Object release predicate/receiver");
                    require((register("sp")&7)==0,"Release alignment");
                    if(kind==2) require(get(OBJ+4)==(closes ? 0 : initialHandle) && closeCalls==(closes && closeArgument!=0 ? 1 : 0),"Release after cleanup");
                    trace.add("object-release:"+argument+":"+get(OBJ+4)); releaseCalls++; dependencyCalls++;
                    if(argument==OBJ) releasedObject=true;
                    externalReturn(0x76543210L); continue;
                }
                require(path ? within(pc,4,BUILD,BUILD+codeSize) :
                    (within(pc,4,CLEAN[0],CLEAN_END[1]) || within(pc,4,CLEAN[2],CLEAN_END[2]) ||
                     within(pc,4,CLEAN[3],CLEAN_END[3]) || within(pc,4,CLEAN[4],CLEAN_END[4])),"Cleanup PC "+Long.toHexString(pc));
                if(!path) visited.add(pc);
                require(++steps<256,"Cleanup instruction budget"); monitor.checkCancelled(); thread.stepInstruction();
            }
            require(diags==(diagnostic ? 1 : 0),"Cleanup diagnostic count");
            require(closeCalls==((kind==3 && argument!=0 || closes && closeArgument!=0) ? 1 : 0),"Cleanup backend count");
            require(releases==((kind==2 || kind==4 && argument!=0) ? 1 : 0),"Cleanup release count");
            if(kind<=1) require(register("r0")==argument,"Cleanup object return");
            byte[] expected=objectBefore.clone(); if(closes) put(expected,4,0);
            require(Arrays.equals(expected,memory(OBJ,24)),"Cleanup exact object bytes");
            require(Arrays.equals(backendBefore,memory(CLOSE_OBJECT-16,528)),"Backend/vtable guards");
            require(register("sp")==sp,"Cleanup stack restoration");
            for(int r=4;r<=11;r++) require(register("r"+r)==saved[r-4],"Cleanup saved register");
            cleanupSteps=Math.max(cleanupSteps,steps); return true;
        }
        @Override void executeClose(boolean path,long handle) throws Exception {
            long caller=register("lr");
            executeCleanup(path,3,handle,get(OBJ+4),0,0,false);
            register("lr",caller); connectedCloses++;
        }
        @Override void executeDestroy(boolean path) throws Exception {
            long caller=register("lr");
            thread.overrideCounter(toAddr(path ? cleanEntries[2] : CLEAN[2]));
            executeCleanup(path,2,OBJ,get(OBJ+4),0,0,false);
            register("lr",caller); connectedDestructors++;
        }
        void direct(boolean path,int kind,long handle,long argument,long replacement,int effect,boolean terminal) throws Exception {
            releasedObject=false;
            initialize(path,0,new byte[0x144]); destroyed=false; active=false; trace.clear(); cleanupFixtures();
            byte[] guard=new byte[64]; new Random(kind+effect).nextBytes(guard); memory(OBJ-16,guard);
            writeWord(OBJ+4,handle); byte[] before=memory(OBJ-16,64);
            register("r0",argument); register("r1",0xfedcba98L); register("r2",cleanupPayload);
            thread.overrideCounter(toAddr(path ? cleanEntries[kind] : CLEAN[kind])); executing=true;
            boolean returned=executeCleanup(path,kind,argument,handle,replacement,effect,terminal);
            if(returned && kind<=2 && (handle&~1L)!=0) put(before,20,0);
            require(Arrays.equals(before,memory(OBJ-16,64)),"Direct object guards");
            for(byte b:memory(STACK-0x1000,0xf00)) require(b==(byte)0x96,"Cleanup stack guard");
        }
        void diagnosticBoundary(boolean callback) throws Exception {
            initialize(false,0,new byte[0x144]); trace.clear(); destroyed=false;
            writeWord(0x44e450,callback ? 0x750004 : 0); register("r0",CLOSE_OBJECT+1); register("r2",0x12345678);
            thread.overrideCounter(toAddr(DIAGNOSTIC)); executing=true; int steps=0,calls=0;
            while(thread.getCounter().getOffset()!=0x1526b4) {
                long pc=thread.getCounter().getOffset();
                if(pc==0x750004) {
                    require(callback && ++calls==1 && get(0x44e450)==0,"Diagnostic callback clear/order");
                    require(register("r0")==0 && register("r1")==0 && register("r2")==0 && register("r3")==0 &&
                        get(register("sp"))==0 && get(register("sp")+4)==0x12345678,"Diagnostic callback arguments");
                    externalReturn(0xabcdef01L); continue;
                }
                require(within(pc,4,DIAGNOSTIC,DIAGNOSTIC+8) || within(pc,4,0x2ad90c,0x2ad958),"Diagnostic boundary PC");
                require(++steps<32,"Diagnostic boundary budget"); thread.stepInstruction();
            }
            require(calls==(callback ? 1 : 0) && register("r0")==0 && register("r1")==0 && register("r2")==0 && register("sp")==STACK,
                "SVC boundary arguments/stack");
        }
        @Override public void beforeStore(PcodeThread<byte[]> t,PcodeOp op,AddressSpace space,byte[] offset,int size,byte[] value) {
            long a=Utils.bytesToLong(offset,offset.length,false);
            require(!releasedObject || !within(a,size,OBJ,OBJ+24),"Object write after release");
            if(a==0x44e450 && size==4) {
                if(breakActive) { require(Utils.bytesToLong(value,4,false)==0,"Break only clears callback slot"); breakWrites++; }
                return;
            }
            super.beforeStore(t,op,space,offset,size,value);
        }
    }
    void compare(CleanupMachine a,CleanupMachine b,int kind,long handle,long argument,long replacement,int effect,boolean terminal,PrintWriter log) throws Exception {
        try {
            a.direct(false,kind,handle,argument,replacement,effect,terminal);
            b.direct(true,kind,handle,argument,replacement,effect,terminal);
            require(a.trace.equals(b.trace),"Cleanup original/rebuilt trace");
        } catch(Exception e) { throw new IllegalStateException("Worker I/O case cleanup="+cleanupCases+" kind="+kind+" handle="+handle+" effect="+effect,e); }
        log.printf("%d\t%d\t%d\t%d\t%d\t%d\t%s%n",++cleanupCases,kind,handle,argument,replacement,effect,terminal);
    }
    @Override String extraChecks(byte[] mapped,byte[] binary,Path out) throws Exception {
        String inherited=super.extraChecks(mapped,binary,out);
        CleanupMachine a=new CleanupMachine(mapped,binary),b=new CleanupMachine(mapped,binary);
        try(PrintWriter log=new PrintWriter(Files.newBufferedWriter(out.resolve("cleanup-results.tsv")))) {
            log.println("case\tkind\thandle\targument\treplacement\teffect\tterminal");
            for(int kind=0;kind<3;kind++) for(long handle:new long[]{0,1,CLOSE_OBJECT,CLOSE_OBJECT+1,CLOSE_OBJECT+32,CLOSE_OBJECT+33}) {
                compare(a,b,kind,handle,OBJ,0,0,false,log);
                if((handle&~1L)!=0) compare(a,b,kind,handle,OBJ,0,2,false,log);
                if(handle>1 && (handle&1)!=0) {
                    compare(a,b,kind,handle,OBJ,0,0,true,log);
                    for(long replacement:new long[]{0,1,CLOSE_OBJECT+32,CLOSE_OBJECT+65})
                        compare(a,b,kind,handle,OBJ,replacement,1,false,log);
                }
            }
            for(long argument:new long[]{0,CLOSE_OBJECT,CLOSE_OBJECT+32,CLOSE_OBJECT+64}) compare(a,b,3,1,argument,0,0,false,log);
            for(long argument:new long[]{0,OBJ,0x80000000L,MASK}) compare(a,b,4,1,argument,0,0,false,log);
        }
        a.diagnosticBoundary(false); a.diagnosticBoundary(true);
        require(currentProgram.getMemory().getInt(toAddr(0x1526b4))==0xef00003c,"Diagnostic SVC encoding");
        require(currentProgram.getMemory().getInt(toAddr(0x4208b4))==CLEAN[2],"Original deleting destructor vtable");
        require(currentProgram.getMemory().getInt(toAddr(CLEAN[0]))==0xe3a01000 &&
                currentProgram.getMemory().getInt(toAddr(CLEAN[0]+4))==0xe1a00000,"Unsaved base entry prefix bytes");
        StringBuilder listing=new StringBuilder(); int count=0;
        for(int i=0;i<CLEAN.length;i++) {
            if(i!=0) { var f=getFunctionAt(toAddr(CLEAN[i])); require(f!=null && f.getBody().getMaxAddress().getOffset()==CLEAN_END[i]-1,"Cleanup saved extent"); }
            for(long pc=CLEAN[i];pc<CLEAN_END[i];pc+=4) {
                require(visited.contains(pc),"Unvisited cleanup instruction "+Long.toHexString(pc)); count++;
                listing.append(String.format("%08x %08x %s visited=true%n",pc,currentProgram.getMemory().getInt(toAddr(pc)),currentProgram.getListing().getInstructionAt(toAddr(pc))));
            }
        }
        listing.append("Original diagnostic chain: callback absent/present reaches 001526b4 SVC 0x3C with r0/r1/r2=0; execution stops before SVC.\n");
        Files.writeString(out.resolve("original-cleanup-ghidra.txt"),listing);
        return inherited+String.format(Locale.ROOT,",\"direct_cleanup_cases\":%d,\"terminal_cleanup_paths_both\":%d,\"connected_close_calls_both\":%d,\"connected_destructor_calls_both\":%d,\"backend_close_calls_both\":%d,\"object_release_calls_both\":%d,\"cleanup_max_steps\":%d,\"new_cleanup_instruction_addresses\":%d,\"cleanup_destructor_close_recovered\":true,\"backend_close_resource_release_modeled\":true,\"returning_diagnostic_model_explicit\":true,\"original_diagnostic_svc_boundary_cases\":2",
            cleanupCases,terminalCleanupCases,connectedCloses,connectedDestructors,serviceCloses,releaseCalls,cleanupSteps,count);
    }
    @Override public void run() throws Exception {
        var lines=Files.readAllLines(Path.of(getScriptArgs()[0]).resolve("entries.txt"));
        for(int i=0;i<5;i++) cleanEntries[i]=Long.parseLong(lines.get(14+i));
        super.run();
    }
}
