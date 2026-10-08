// Executed vtable adapters inside allocation/I/O, with explicit file/diagnostic models.
// @category SMT4
import java.nio.file.*;
import java.util.*;
import java.io.*;

public class CompareResourceWorkerFileMethods extends CompareResourceWorkerAllocation {
    static final long[] METHODS={0x3dfc54,0x354f70,0x354f9c};
    static final long[] METHOD_END={0x3dfc80,0x354f9c,0x354fa4};
    static final long[] LOWER={0x2bb8ec,0x2aca78,0x2bb864};
    long[] methodEntries=new long[3];
    int adapterCalls, directMethodCases, terminalSizeCases, diagnostics, methodSteps;
    long lowerTarget(boolean path,int kind) { return LOWER[kind]; }
    @Override boolean originalCode(long pc) {
        for(int k=0;k<3;k++) if(within(pc,4,METHODS[k],METHOD_END[k])) return true;
        return super.originalCode(pc);
    }
    @Override IoMachine makeMachine(byte[] mapped,byte[] binary) { return new MethodMachine(mapped,binary); }
    class MethodMachine extends AllocationMachine {
        boolean rebuilt;
        long readResult;
        MethodMachine(byte[] mapped,byte[] binary) { super(mapped,binary); }
        @Override void call(boolean path,byte[] initial,long open,long read,long handle,
                long length,long allocation,int profile,int effect) throws Exception {
            rebuilt=path; readResult=read;
            super.call(path,initial,open,read,handle,length,allocation,profile,effect);
        }
        @Override void setupAllocation(byte[] initial,long length,long allocation) {
            super.setupAllocation(initial,length,allocation);
            for(long v:new long[]{VT,VT+0x80}) {
                writeWord(v+36,rebuilt ? methodEntries[0] : METHODS[0]);
                writeWord(v+12,rebuilt ? methodEntries[1] : METHODS[1]);
                writeWord(v+40,rebuilt ? methodEntries[2] : METHODS[2]);
            }
        }
        // Lower models preserve the object in this package. Distinct word patterns
        // make width/sign mistakes visible; real lower state effects remain open.
        boolean executeMethod(boolean path,int kind,long result,long lo,long hi,
                long origin,long count,long data,long size,boolean terminalFailure) throws Exception {
            long savedSp=register("sp"),returnPc=register("lr");
            long[] saved=new long[8]; for(int r=4;r<=11;r++) saved[r-4]=register("r"+r);
            byte[] objectBefore=memory(OBJ,24);
            int lowerCalls=0,diagnosticCalls=0,steps=0;
            while(thread.getCounter().getOffset()!=returnPc) {
                long pc=thread.getCounter().getOffset();
                if(pc==lowerTarget(path,kind)) {
                    require(++lowerCalls==1 && register("r0")==OBJ+4,"Method lower receiver/count");
                    require((register("sp")&7)==0,"Method lower stack alignment");
                    if(kind==0) {
                        long out=register("r1");
                        require((out&7)==0 && within(out,8,register("sp"),savedSp),"Size output layout");
                        if((result&0x80000000L)==0) { writeWord(out,lo); writeWord(out+4,hi); }
                    } else if(kind==1) {
                        require(register("r1")==origin && register("r2")==lo && register("r3")==hi &&
                            get(register("sp"))==origin,"Seek full-width forwarding");
                    } else {
                        require(register("r1")==count && register("r2")==data && register("r3")==size,"Read forwarding");
                        writeWord(count,size^MASK);
                        if(!terminalFailure) writeWord(LOCK,0x81234567L);
                    }
                    trace.add("file-lower:"+kind+":"+result+":"+lo+":"+hi+":"+origin+":"+data+":"+size);
                    dependencyCalls++; externalReturn(result); continue;
                }
                if(pc==0x2bbd70) {
                    require(kind!=2 && lowerCalls==1 && ++diagnosticCalls==1 && (result&0x80000000L)!=0,
                        "Diagnostic branch predicate");
                    require(register("r0")==result && register("r1")== (kind==0 ? 0x3dfc70 : 0x354f8c),"Diagnostic result/site");
                    require((register("sp")&7)==0,"Diagnostic alignment");
                    trace.add("diagnostic:"+result+":"+register("r1")); diagnostics++; dependencyCalls++;
                    if(kind==0 && terminalFailure) {
                        require(Arrays.equals(objectBefore,memory(OBJ,24)),"Terminal size object preservation");
                        terminalSizeCases++; return false;
                    }
                    externalReturn(0x87654321L); continue;
                }
                require(path ? within(pc,4,BUILD,BUILD+codeSize) : within(pc,4,METHODS[kind],METHOD_END[kind]),
                    "Method PC "+Long.toHexString(pc));
                if(!path) visited.add(pc);
                require(++steps<64,"Method budget"); monitor.checkCancelled(); thread.stepInstruction();
            }
            require(lowerCalls==1 && diagnosticCalls==((kind!=2 && (result&0x80000000L)!=0) ? 1 : 0),"Method call order/count");
            require(register("sp")==savedSp,"Method stack restored");
            for(int r=4;r<=11;r++) require(register("r"+r)==saved[r-4],"Method callee-saved register");
            require(Arrays.equals(objectBefore,memory(OBJ,24)),"Method object preservation");
            if(kind==0) require(register("r0")==lo && register("r1")==hi,"Full 64-bit size return");
            if(kind==2) require(register("r0")==result && get(count)==(size^MASK),"Read return/count");
            adapterCalls++; methodSteps=Math.max(methodSteps,steps); return true;
        }
        @Override boolean allocationStep(long pc,boolean path) throws Exception {
            for(int kind=0;kind<3;kind++) if(pc==(path ? methodEntries[kind] : METHODS[kind])) {
                require(register("r0")==OBJ,"Virtual receiver");
                long count=0,data=0,size=0;
                if(kind==1) require(register("r2")==0 && register("r3")==0 && get(register("sp"))==0,"Virtual seek args");
                if(kind==2) {
                    count=register("r1"); data=register("r2"); size=register("r3");
                    require(data==DATA && size==length && get(GLOBAL+4)==1,"Virtual read args/busy");
                    require(within(count,4,register("sp"),STACK-16),"Virtual read count layout");
                }
                long result=kind==0 ? new long[]{0,1,0x7fffffffL}[cases%3] : kind==1 ? new long[]{0,0x7fffffffL,0x80000000L,MASK}[cases%4] : readResult;
                executeMethod(path,kind,result,kind==0 ? length : 0,kind==0 ? (0x81234567L+cases)&MASK : 0,0,count,data,size,false);
                event(kind==0 ? 0x730008 : kind==1 ? 0x730004 : 0x73000c);
                return true;
            }
            return super.allocationStep(pc,path);
        }
        void direct(boolean path,int kind,long result,long lo,long hi,long origin,long data,long size) throws Exception {
            initialize(path,0,new byte[0x144]); destroyed=false; trace.clear();
            byte[] obj=new byte[24]; new Random(0x354f70).nextBytes(obj); memory(OBJ,obj);
            // Reserve caller stack arguments above the adapter's own frame.
            register("sp",STACK-16); writeWord(STACK-16,origin);
            register("r0",OBJ); register("r1",kind==2 ? SIZE : 0xdead1234L);
            register("r2",kind==2 ? data : lo); register("r3",kind==2 ? size : hi);
            writeWord(SIZE,0xabcdef01L);
            thread.overrideCounter(toAddr(path ? methodEntries[kind] : METHODS[kind])); executing=true;
            boolean returned=executeMethod(path,kind,result,lo,hi,origin,SIZE,data,size,true);
            require(returned==!(kind==0 && (result&0x80000000L)!=0),"Direct termination boundary");
            if(returned) {
                require(register("sp")==STACK-16,"Direct stack restoration");
                for(int r=4;r<=11;r++) require(register("r"+r)==0x12340000L+r,"Direct saved register");
            }
            for(byte value:memory(STACK-0x1000,0xf80)) require(value==(byte)0x96,"Method stack guard");
            require(get(STACK-16)==origin,"Caller fifth word preserved");
        }
    }
    @Override String extraChecks(byte[] mapped,byte[] binary,Path out) throws Exception {
        String inherited=super.extraChecks(mapped,binary,out);
        MethodMachine a=new MethodMachine(mapped,binary),b=new MethodMachine(mapped,binary);
        try(PrintWriter log=new PrintWriter(Files.newBufferedWriter(out.resolve("method-results.tsv")))) {
            log.println("kind\tresult\tlow\thigh\torigin\tdata\tsize");
            long[] words={0,1,0x7fffffffL,0x80000000L,MASK,0x12345678};
            for(int kind=0;kind<3;kind++) for(long result:new long[]{0,1,0x7fffffffL,0x80000000L,MASK})
                for(int i=0;i<words.length;i++) for(long origin:kind==1 ? new long[]{0,1,2,0x80000000L,MASK} : new long[]{0}) {
                    long lo=words[i],hi=words[(i+2)%words.length],data=words[(i+3)%words.length],size=words[(i+4)%words.length];
                    try { a.direct(false,kind,result,lo,hi,origin,data,size); b.direct(true,kind,result,lo,hi,origin,data,size);
                        require(a.trace.equals(b.trace),"Direct lower/diagnostic traces");
                    } catch(Exception e) {throw new IllegalStateException("Worker I/O case method="+kind+" result="+result+" i="+i+" origin="+origin,e);}
                    directMethodCases++; log.printf("%d\t%d\t%d\t%d\t%d\t%d\t%d%n",kind,result,lo,hi,origin,data,size);
                }
        }
        StringBuilder listing=new StringBuilder();
        for(int k=0;k<3;k++) {
            var f=getFunctionAt(toAddr(METHODS[k]));
            require(f!=null && f.getBody().getMaxAddress().getOffset()==METHOD_END[k]-1,"Method Ghidra extent");
            for(long pc=METHODS[k];pc<METHOD_END[k];pc+=4) {
                require(visited.contains(pc),"Unvisited method instruction");
                listing.append(String.format("%08x %s%n",pc,currentProgram.getListing().getInstructionAt(toAddr(pc))));
            }
        }
        var mem=currentProgram.getMemory();
        require(mem.getInt(toAddr(TABLE))==0x4208b0 && mem.getInt(toAddr(TABLE+12))==0x4208b0 &&
            mem.getInt(toAddr(0x4208b0-48))==0,"Pinned construction table");
        for(int k=0;k<3;k++) require(mem.getInt(toAddr(0x4208b0+new int[]{36,12,40}[k]))==METHODS[k],"Pinned virtual slot");
        Files.writeString(out.resolve("original-methods-ghidra.txt"),listing);
        return inherited+String.format(Locale.ROOT,",\"direct_method_cases\":%d,\"method_returns_both_paths\":%d,\"terminal_size_failures_both_paths\":%d,\"diagnostic_calls_both_paths\":%d,\"method_max_steps\":%d,\"size_seek_read_adapters_recovered\":true,\"lower_file_diagnostic_modeled\":true",
            directMethodCases,adapterCalls,terminalSizeCases,diagnostics,methodSteps);
    }
    @Override public void run() throws Exception {
        var lines=Files.readAllLines(Path.of(getScriptArgs()[0]).resolve("entries.txt"));
        for(int k=0;k<3;k++) methodEntries[k]=Long.parseLong(lines.get(4+k));
        super.run();
    }
}
