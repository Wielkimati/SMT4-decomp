// Break dispatcher with callback and SVC outcome models; integrated prefix/cleanup.
// @category SMT4
import java.nio.file.*;
import java.util.*;
import java.io.*;

public class CompareResourceBreak extends CompareResourceWorkerPrefix {
    static final long SLOT=0x44e450, CALLBACK=0x790000, OTHER_CALLBACK=0x790005;
    static final long DISPATCH=0x2ad90c, SVC=0x1526b4;
    int breakPairs,breakCallbacks,breakServices,breakTerminals,breakConnected;
    int payloadCleanupPairs,payloadPrefixPairs,persistentBreakSequences;
    final Set<Long> breakVisited=new TreeSet<>();

    @Override boolean breakCall(CleanupMachine m,boolean path,long reason,long payload,
            boolean terminal,int effect,long replacement) throws Exception {
        byte[] guard=new byte[36]; Arrays.fill(guard,(byte)0x67); m.memory(SLOT-16,guard);
        m.writeWord(SLOT,CALLBACK);
        breakConnected++;
        return executeBreak(m,path,0,reason,payload,0,0,terminal,effect,replacement,OTHER_CALLBACK,0x87654321L);
    }

    boolean executeBreak(CleanupMachine m,boolean path,int kind,long reason,long payload,
            long svc1,long svc2,boolean terminal,int effect,long replacement,long mutation,long result) throws Exception {
        long caller=m.register("lr"),sp=m.register("sp"),initialSlot=m.get(SLOT);
        long[] saved=new long[8]; for(int r=4;r<=11;r++) saved[r-4]=m.register("r"+r);
        byte[] slotGuard=m.memory(SLOT-16,36);
        long expectedReason=kind==0 ? 0 : reason;
        int callbacks=0,services=0,steps=0;
        m.breakActive=true; m.breakReads=0; m.breakWrites=0;
        try {
            while(m.thread.getCounter().getOffset()!=caller) {
                long pc=m.thread.getCounter().getOffset();
                if(pc==CALLBACK || pc==(OTHER_CALLBACK&~1L)) {
                    require(kind!=2 && pc==(initialSlot&~1L) && ++callbacks==1,"Captured callback target/count");
                    require(m.thread.getContext().getRegisterValue(currentProgram.getRegister("TMode")).getUnsignedValue().longValue()==(initialSlot&1),"Callback ARM/Thumb decoding mode");
                    require(m.get(SLOT)==0 && m.breakReads==1 && m.breakWrites==1,"Capture and clear before callback");
                    require(m.register("r0")==expectedReason && m.register("r1")==0 && m.register("r2")==0 &&
                        m.register("r3")==0 && m.get(m.register("sp"))==0 && m.get(m.register("sp")+4)==payload,
                        "Break six callback words: payload="+Long.toHexString(payload)+" actual="+Long.toHexString(m.get(m.register("sp")+4)));
                    require((m.register("sp")&7)==0,"Break callback stack alignment");
                    m.trace.add("break-callback:"+pc+":"+expectedReason+":"+payload);
                    m.writeWord(SLOT,mutation);
                    if(effect==1) m.writeWord(OBJ+4,replacement);
                    breakCallbacks++; m.externalReturn(0xabcdef01L); continue;
                }
                boolean original=within(pc,4,DIAGNOSTIC,DIAGNOSTIC+8) || within(pc,4,DISPATCH,0x2ad958) || within(pc,4,SVC,SVC+8);
                require(path ? within(pc,4,BUILD,BUILD+codeSize) : original,"Break instruction PC "+Long.toHexString(pc));
                if(!path) { visited.add(pc); breakVisited.add(pc); }
                if(m.get(pc)==0xef00003cL) {
                    require(++services==1,"One SVC break boundary");
                    require(m.register("r0")==expectedReason && m.register("r1")==svc1 && m.register("r2")==svc2,"Break SVC argument words");
                    require(callbacks==(kind!=2 && initialSlot!=0 ? 1 : 0),"Callback precedes service");
                    m.trace.add("break-svc:"+expectedReason+":"+svc1+":"+svc2+":"+m.get(SLOT));
                    breakServices++;
                    if(terminal) { breakTerminals++; break; }
                    // SVC effects are the only intercepted instructions. BX LR executes.
                    for(String r:new String[]{"r1","r2","r3","r12"}) m.register(r,0xdeadbeefL);
                    m.register("r0",result); m.register("cpsr",0xa0000010L);
                    m.thread.overrideCounter(toAddr(pc+4)); continue;
                }
                require(++steps<80,"Break instruction budget"); monitor.checkCancelled(); m.thread.stepInstruction();
            }
        } finally { m.breakActive=false; }
        boolean callback=kind!=2 && initialSlot!=0;
        require(services==1 && callbacks==(callback ? 1 : 0),"Break service/callback counts");
        require(m.breakReads==(kind==2 ? 0 : 1) && m.breakWrites==(callback ? 1 : 0),"Break slot access footprint");
        put(slotGuard,16,callback ? mutation : initialSlot);
        require(Arrays.equals(slotGuard,m.memory(SLOT-16,36)),"Break callback slot/guards/mutation preservation");
        if(!terminal) {
            require(m.register("r0")==result,"Break returns service r0");
            require(m.register("sp")==sp,"Break restores stack");
            for(int r=4;r<=11;r++) require(m.register("r"+r)==saved[r-4],"Break preserves callee register");
            m.register("lr",caller);
        }
        return !terminal;
    }

    void probe(CleanupMachine a,CleanupMachine b,int kind,long reason,long payload,
            long callback,long mutation,boolean terminal,long result,PrintWriter log) throws Exception {
        for(boolean path:new boolean[]{false,true}) {
            CleanupMachine m=path ? b : a;
            m.initialize(path,0,new byte[0x144]); m.destroyed=false; m.releasedObject=false; m.trace.clear();
            byte[] guard=new byte[36]; Arrays.fill(guard,(byte)0x67); m.memory(SLOT-16,guard); m.writeWord(SLOT,callback);
            m.register("r0",reason); m.register("r1",0x81234567L); m.register("r2",payload);
            m.thread.overrideCounter(toAddr(path ? breakEntries[kind] : new long[]{DIAGNOSTIC,DISPATCH,SVC}[kind])); m.executing=true;
            executeBreak(m,path,kind,reason,payload,kind==2 ? 0x81234567L : 0,kind==2 ? payload : 0,
                terminal,0,0,mutation,result);
            for(byte v:m.memory(STACK-0x1000,0xf00)) require(v==(byte)0x96,"Break stack guard");
        }
        require(a.trace.equals(b.trace),"Break original/rebuilt ordered events");
        log.printf("%d\t%d\t%x\t%x\t%x\t%x\t%s\t%x%n",++breakPairs,kind,reason,payload,callback,mutation,terminal,result);
    }

    @Override void preChecks(byte[] mapped,byte[] binary,Path out) throws Exception {
        try {
        CleanupMachine a=new CleanupMachine(mapped,binary),b=new CleanupMachine(mapped,binary);
        try(PrintWriter log=new PrintWriter(Files.newBufferedWriter(out.resolve("break-results.tsv")))) {
            log.println("case\tkind\treason\tpayload\tcallback\tmutation\tterminal\tresult");
            for(int kind=0;kind<3;kind++) for(long value:new long[]{0,1,0x80000000L,MASK})
                for(long callback:new long[]{0,CALLBACK,OTHER_CALLBACK}) {
                    long payload=value^0x81234567L;
                    probe(a,b,kind,value,payload,callback,callback==CALLBACK ? OTHER_CALLBACK : 0,false,value,log);
                    probe(a,b,kind,value,payload,callback,callback==CALLBACK ? CALLBACK : 0,true,value,log);
                }
        }
        // Caller-level payload boundaries, independent of the dispatcher input matrix.
        try(PrintWriter log=new PrintWriter(Files.newBufferedWriter(out.resolve("break-caller-results.tsv")))) {
            for(int kind=0;kind<3;kind++) for(long payload:new long[]{0,0x80000000L,MASK}) {
                a.cleanupPayload=payload; b.cleanupPayload=payload;
                a.direct(false,kind,CLOSE_OBJECT+1,OBJ,CLOSE_OBJECT+33,1,false);
                b.direct(true,kind,CLOSE_OBJECT+1,OBJ,CLOSE_OBJECT+33,1,false);
                require(a.trace.equals(b.trace),"Cleanup payload and mutation trace");
                log.printf("cleanup\t%d\t%x%n",kind,payload); payloadCleanupPairs++;
            }
            RegistryMachine x=new RegistryMachine(mapped,binary),y=new RegistryMachine(mapped,binary);
            for(int kind=0;kind<2;kind++) for(int last:new int[]{0x7f,0x80,0xff}) for(boolean terminal:new boolean[]{false,true}) {
                byte[] name=name(1,2,3,4,5,6,7,last,0);
                x.resetRegistry(false,occupied(),BACKEND); y.resetRegistry(true,occupied(),BACKEND);
                long p=x.mutate(false,kind,name,0,BACKEND,0,1,terminal,0),q=y.mutate(true,kind,name,0,BACKEND,0,1,terminal,0);
                require(p==q && x.trace.equals(y.trace),"Prefix signed-eighth-byte payload trace");
                log.printf("prefix\t%d\t%x\t%s%n",kind,last,terminal); payloadPrefixPairs++;
            }
        }
        // No fixture resets between calls: a callback's replacement is used exactly
        // once by the next dispatch, and its clearing survives a third call.
        for(boolean path:new boolean[]{false,true}) {
            CleanupMachine m=path ? b : a; m.initialize(path,0,new byte[0x144]); m.destroyed=false; m.releasedObject=false;
            byte[] guard=new byte[36]; Arrays.fill(guard,(byte)0x67); m.memory(SLOT-16,guard); m.writeWord(SLOT,CALLBACK); m.trace.clear();
            for(int i=0;i<3;i++) {
                m.register("r0",0x80000001L); m.register("r1",0x1234); m.register("r2",i); m.register("lr",RETURN);
                m.thread.overrideCounter(toAddr(path ? breakEntries[1] : DISPATCH)); m.executing=true;
                executeBreak(m,path,1,0x80000001L,i,0,0,false,0,0,i==0 ? OTHER_CALLBACK : 0,i);
            }
            persistentBreakSequences++;
        }
        require(a.trace.equals(b.trace),"Persistent callback replacement/clearing sequence");
        super.preChecks(mapped,binary,out);
        } catch(Exception e) { throw new IllegalStateException("Worker I/O case break/caller probes",e); }
    }

    @Override String extraChecks(byte[] mapped,byte[] binary,Path out) throws Exception {
        String inherited=super.extraChecks(mapped,binary,out);
        StringBuilder listing=new StringBuilder(); int count=0;
        for(long[] range:new long[][]{{DIAGNOSTIC,DIAGNOSTIC+8},{DISPATCH,0x2ad958},{SVC,SVC+8}}) {
            var f=getFunctionAt(toAddr(range[0]));
            if(range[0]!=SVC) require(f!=null && f.getBody().getMaxAddress().getOffset()==range[1]-1,"Break saved membership");
            listing.append(String.format("entry=%08x saved=%s%n",range[0],f==null ? "none" : f.getBody()));
            for(long pc=range[0];pc<range[1];pc+=4) {
                require(breakVisited.contains(pc),"Unvisited break instruction "+Long.toHexString(pc)); count++;
                listing.append(String.format("%08x %08x %s visited=true%n",pc,currentProgram.getMemory().getInt(toAddr(pc)),currentProgram.getListing().getInstructionAt(toAddr(pc))));
            }
        }
        require(currentProgram.getMemory().getInt(toAddr(SVC))==0xef00003c && currentProgram.getMemory().getInt(toAddr(SVC+4))==0xe12fff1e,"Unsaved SVC body exact encoding");
        Files.writeString(out.resolve("original-break-ghidra.txt"),listing);
        StringBuilder next=new StringBuilder();
        for(long address:new long[]{0x3f3568,0x2c5fac,0x3561f0}) {
            var f=getFunctionAt(toAddr(address));
            next.append(String.format("%08x saved=%s%n",address,f==null ? "none" : f.getBody()));
        }
        next.append(String.format("startup literal 003f36f0=%08x 003f36f4=%08x%n",
            currentProgram.getMemory().getInt(toAddr(0x3f36f0)),currentProgram.getMemory().getInt(toAddr(0x3f36f4))));
        Files.writeString(out.resolve("next-registry-membership.txt"),next);
        Files.writeString(out.resolve("break-caller-summary.json"),String.format(Locale.ROOT,
            "{\"cleanup_payload_pairs\":%d,\"prefix_payload_pairs\":%d,\"persistent_sequences_both\":%d}\n",payloadCleanupPairs,payloadPrefixPairs,persistentBreakSequences));
        return inherited+String.format(Locale.ROOT,",\"direct_break_pairs\":%d,\"new_break_instruction_sites\":%d,\"break_callback_calls_both\":%d,\"break_svc_boundaries_both\":%d,\"break_terminal_paths_both\":%d,\"break_integrated_calls_both\":%d,\"break_dispatch_recovered\":true,\"break_callback_kernel_modeled\":true",breakPairs,count,breakCallbacks,breakServices,breakTerminals,breakConnected);
    }
    @Override public void run() throws Exception {
        var lines=Files.readAllLines(Path.of(getScriptArgs()[0]).resolve("break-entries.txt"));
        for(int i=0;i<3;i++) breakEntries[i]=Long.parseLong(lines.get(i));
        recoverBreak=true; super.run();
    }
}
