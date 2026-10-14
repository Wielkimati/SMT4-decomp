// Connected teardown scratch-register contract; real break dispatcher, modeled callback/SVC.
// @category SMT4
import ghidra.pcode.emu.PcodeThread;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.pcode.utils.Utils;
import java.nio.file.*;
import java.security.MessageDigest;
import java.util.*;
import java.io.*;

public class CompareResourcePoolTeardownBreak extends CompareResourcePoolObjectTeardown {
    static final long SLOT=0x44e450, CALLBACK=0x790000, THUMB_CALLBACK=0x790005;
    long breakEntry,expectedR2; int plannedDiagnostics,pairs,callbacks,services,terminals;
    boolean stopped; PrintWriter transport;
    class BreakScenario extends LifeScenario {
        long payload,callback,serviceR2,closeR2=0x93456789L,handleR2=0xa4567890L; int mutation,terminalIndex;
        BreakScenario(){super(false);}
    }
    class BreakBoundary extends CleanupBoundary {
        long payload,returnedR2,callback,replacement; boolean terminal;
        BreakBoundary(OwnerPlan p,long pool){super(DIAG2,p,pool);}
    }
    class Terminal extends RuntimeException {}
    void diagnostic(OwnerPlan p,long pool){
        BreakScenario c=(BreakScenario)p.c;BreakBoundary e=new BreakBoundary(p,pool);
        e.payload=expectedR2;e.returnedR2=(c.serviceR2+0x1010101L*plannedDiagnostics)&MASK;
        e.terminal=++plannedDiagnostics==c.terminalIndex;e.callback=p.s.get(SLOT);
        if(e.callback!=0){
            p.w(SLOT,0);e.replacement=e.callback==CALLBACK?THUMB_CALLBACK:0;
            e.effect(p,SLOT,e.replacement);
            if(c.mutation==1)e.effect(p,pool+16,0);
            if(c.mutation==2)e.effect(p,pool+16,LINKS+0x60);
        }
        expectedR2=e.returnedR2;stopped=e.terminal;
    }
    @Override void planBase(OwnerPlan p,long pool){
        p.w(pool,0x420bc0);
        if(p.s.get(pool+12)!=0){diagnostic(p,pool);if(stopped)return;}
        if(p.s.get(pool+16)!=0){diagnostic(p,pool);if(stopped)return;}
        long node=p.s.get(pool+16);int budget=0;
        if(node!=0){
            while(node!=0){require(++budget<=8,"Acyclic list domain");expectedR2=node;long next=p.s.get(node+4);p.w(node+4,0);p.w(node,0);node=next;}
            p.w(pool+16,0);
        }
    }
    @Override void planTeardown(OwnerPlan p,long node){
        event(TEARDOWN,p,node);p.w(node+8,0);p.w(node,0x420948);
        for(int i=0;i<5;i++){
            long file=p.s.get(node+12+4*i);if(file==0)continue;
            BreakScenario c=(BreakScenario)p.c;
            if(p.s.get(file+4)!=0)expectedR2=c.clearHandle?c.closeR2:c.handleR2;
            // Original nested wrappers preserve incoming r2. A fresh lock is
            // acquired with base=-1, then 0x138FCC returns its negation, one.
            boolean nested=p.s.get(SECOND+52)==LOCK_TLS&&p.s.get(SECOND+56)!=0;
            super.planFileDispose(p,file);if(!nested)expectedR2=1;
        }
        for(int off:new int[]{0xf4,0xb8}){
            long pool=node+off;p.w(pool,0x420b00);if(p.s.get(pool+36)!=0)p.w(pool+36,0);planBase(p,pool);if(stopped)return;
        }
    }
    @Override void planObjectDispose(OwnerPlan p,long node){
        event(OBJECT_DISPOSE,p,node);planTeardown(p,node);if(!stopped)returnNode(p,p.s.get(STATE+4),node);
    }
    @Override long normalizePc(long pc){return pc==breakEntry?DIAG2:super.normalizePc(pc);}
    @Override boolean handleAdditional(OwnerMachine machine,long pc,Boundary boundary,OwnerPlan p)throws Exception{
        if(!(boundary instanceof BreakBoundary)){
            boolean handled=super.handleAdditional(machine,pc,boundary,p);
            if(boundary.pc==0x23)machine.register("r2",((BreakScenario)p.c).handleR2);
            return handled;
        }
        BreakMachine m=(BreakMachine)machine;BreakBoundary e=(BreakBoundary)boundary;
        require(m.register("r2")==e.payload,"Diagnostic entry r2 expected="+Long.toHexString(e.payload)+" actual="+Long.toHexString(m.register("r2"))+" rebuilt="+m.rebuiltPath);
        transport.printf("%d\t%s\t%x\t%x\t%x\t%x\t%b%n",pairs,m.rebuiltPath?"rebuilt":"original",e.node,e.payload,e.returnedR2,e.callback,e.terminal);transport.flush();
        long caller=m.register("lr"),sp=m.register("sp");long[] saved=new long[8];for(int i=4;i<12;i++)saved[i-4]=m.register("r"+i);
        int callbackCount=0,serviceCount=0,steps=0;m.inBreak=true;m.slotReads=m.slotWrites=0;
        try{
            while(m.thread.getCounter().getOffset()!=caller){
                long at=m.thread.getCounter().getOffset();
                if(at==CALLBACK||at==(THUMB_CALLBACK&~1L)){
                    require(++callbackCount==1&&at==(e.callback&~1L),"Captured callback target");
                    require(m.thread.getContext().getRegisterValue(currentProgram.getRegister("TMode")).getUnsignedValue().longValue()==(e.callback&1),"Callback instruction mode");
                    require(m.slotReads==1&&m.slotWrites==1&&m.get(SLOT)==0,"Capture and clear before callback");
                    require(m.register("r0")==0&&m.register("r1")==0&&m.register("r2")==0&&m.register("r3")==0&&m.get(m.register("sp"))==0&&m.get(m.register("sp")+4)==e.payload,"Six callback words");
                    require((m.register("sp")&7)==0,"Callback stack alignment");
                    for(Write effect:e.effects)m.writeWord(effect.at(),effect.value());
                    m.externalReturn(0x87654321L);callbacks++;continue;
                }
                boolean original=within(at,4,DIAG2,DIAG2+8)||within(at,4,0x2ad90c,0x2ad958)||within(at,4,0x1526b4,0x1526bc);
                require(m.rebuiltPath?within(at,4,BUILD,BUILD+codeSize):original,"Break PC extent");
                if(!m.rebuiltPath)visited.add(at);
                if(m.get(at)==0xef00003cL){
                    require(++serviceCount==1&&m.register("r0")==0&&m.register("r1")==0&&m.register("r2")==0,"SVC reason/words");
                    require(callbackCount==(e.callback==0?0:1),"Callback before SVC");
                    require(m.slotReads==1&&m.slotWrites==(e.callback==0?0:1),"Slot access footprint");services++;
                    if(e.terminal){terminals++;throw new Terminal();}
                    for(String r:new String[]{"r1","r3","r12"})m.register(r,0xdeadbeefL);
                    m.register("r0",0xa1234567L);m.register("r2",e.returnedR2);m.register("cpsr",0xa0000010L);m.thread.overrideCounter(toAddr(at+4));continue;
                }
                require(++steps<80,"Break budget");monitor.checkCancelled();m.thread.stepInstruction();
            }
            require(serviceCount==1&&m.register("r0")==0xa1234567L&&m.register("r2")==e.returnedR2,"Break service returns r0/r2");
            require(m.register("sp")==sp,"Break stack restored");for(int i=4;i<12;i++)require(m.register("r"+i)==saved[i-4],"Break callee saved");
            m.register("lr",caller);return true;
        }finally{m.inBreak=false;}
    }
    class BreakMachine extends TeardownMachine {
        boolean inBreak;int slotReads,slotWrites;long inputPayload;
        @Override void machineStep(boolean rebuilt,int steps)throws Exception{
            boolean send=inClose&&get(thread.getCounter().getOffset())==0xef000032L;
            super.machineStep(rebuilt,steps);
            if(send)register("r2",((BreakScenario)scenario).closeR2);
        }
        BreakMachine(byte[] map,byte[] binary){super(map,binary);}
        @Override void setup(boolean rebuilt,long original,long build){super.setup(rebuilt,original,build);register("r2",inputPayload);}
        @Override public void beforeLoad(PcodeThread<byte[]> t,PcodeOp op,AddressSpace sp,byte[] offset,int size){
            long at=Utils.bytesToLong(offset,offset.length,false);if(inBreak&&at==SLOT){require(size==4,"Slot read width");slotReads++;}super.beforeLoad(t,op,sp,offset,size);
        }
        @Override public void beforeStore(PcodeThread<byte[]> t,PcodeOp op,AddressSpace sp,byte[] offset,int size,byte[] value){
            long at=Utils.bytesToLong(offset,offset.length,false);if(inBreak&&at==SLOT){require(size==4,"Slot write width");slotWrites++;}super.beforeStore(t,op,sp,offset,size,value);
        }
    }
    void probe(BreakMachine a,BreakMachine b,State s,BreakScenario c,long node,int kind)throws Exception{
        expectedR2=c.payload;plannedDiagnostics=0;stopped=false;OwnerPlan p=blankPlan(s,c,node);
        if(kind==0)planObjectDispose(p,node);else if(kind==1)planTeardown(p,node);else planBase(p,node);
        try{
            for(boolean rebuilt:new boolean[]{false,true}){
                BreakMachine m=rebuilt?b:a;m.inputPayload=c.payload;m.seed(s);boolean terminal=false;
                try{m.cleanup(rebuilt,p,kind);}catch(Terminal stop){terminal=true;m.executing=false;}
                require(terminal==stopped,"Terminal outcome");require(m.observed.equals(p.writes),"Connected ordered writes");m.matches(p.s);m.matches(m.tls);
                for(byte v:m.memory(STACK-0x1000,0xc00))require(v==(byte)0x96,"Connected stack guard");
                if(!terminal&&kind!=0)require(m.register("r2")==expectedR2,"Teardown returned r2");
            }
            results.printf("%d\t%d\t%x\t%x\t%x\t%d\t%d\t%d%n",++pairs,kind,c.payload,c.serviceR2,c.callback,c.mutation,c.terminalIndex,plannedDiagnostics);results.flush();
        }catch(Exception e){throw new IllegalStateException("Pool owner case connected teardown "+pairs,e);}
    }
    State fixture(BreakScenario c,long node,int kind,int count,boolean active,boolean files){
        State s=lifeFixture(1,0,false);s.add(SLOT-16,36,0x67);s.set(SLOT,c.callback);
        if(node!=B)s.add(node-16,0x150,0xb7);
        construct(s,new ArrayList<>(),node,true);s.set(STATE+4,P);s.set(P+36,B+0x130);
        if(files){s.set(node+12,FILES);s.set(FILES,0x420998);s.set(FILES+4,0x12345678);s.set(SECOND+36,FILES+0x200);}
        for(int i=0;i<(kind==2?1:2);i++){
            long pool=node+(kind==2?0:i==0?0xf4:0xb8),link=LINKS+i*32;
            s.set(pool+12,active?1:0);s.set(pool+16,count==0?0:link);s.set(pool+36,count==0?0:STORAGE);
            for(int n=0;n<count;n++){s.set(link+16*n,0xabc01234L+n);s.set(link+16*n+4,n==count-1?0:link+16*(n+1));}
        }
        s.set(LINKS+0x60,0x87654321L);s.set(LINKS+0x64,LINKS+0x70);s.set(LINKS+0x70,0x12345678);s.set(LINKS+0x74,0);return s;
    }
    @Override public void run()throws Exception{
        Path out=Path.of(getScriptArgs()[0]);byte[] map=new byte[0x377000];require(currentProgram.getMemory().getBytes(toAddr(0x100000),map)==map.length,"Map");
        require(HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(map)).equals("834938d18d2b7c688311c46c27bed813d0d7a9f8e3cbb61da8a6a3f23d360ebd"),"Hash");
        require(word(map,0x420a3c-0x100000+48)==OBJECT_DISPOSE&&word(map,0x420a3c-0x100000+52)==TEARDOWN,"Object vtable");
        require(word(map,0x420998-0x100000+44)==FILE_DISPOSE&&word(map,0x420998-0x100000+48)==FILE_TEARDOWN,"File vtable");
        byte[] binary=Files.readAllBytes(out.resolve("resource-worker-backend.bin"));codeSize=binary.length;
        var entries=Files.readAllLines(out.resolve("teardown-entries.txt"));for(int i=0;i<6;i++)cleanupEntries[i]=Long.parseLong(entries.get(i));
        breakEntry=Long.parseLong(Files.readString(out.resolve("break-entry.txt")));recoverRequest=true;
        BreakMachine a=new BreakMachine(map,binary),b=new BreakMachine(map,binary);
        try(PrintWriter log=new PrintWriter(Files.newBufferedWriter(out.resolve("connected-results.tsv")));PrintWriter payloads=new PrintWriter(Files.newBufferedWriter(out.resolve("diagnostic-transport.tsv")))){
            transport=payloads;transport.println("pair\tpath\tpool\tpayload\tservice_r2\tcallback\tterminal");
            results=log;log.println("pair\tkind\tentry_r2\tsvc_r2\tcallback\tmutation\tterminal_index\tdiagnostics");
            for(int kind=0;kind<3;kind++)for(int count=0;count<=2;count++)for(boolean active:new boolean[]{false,true})for(long callback:new long[]{0,CALLBACK,THUMB_CALLBACK}){
                BreakScenario c=new BreakScenario();c.callback=callback;c.payload=new long[]{0,0x81234567L,MASK}[count];c.serviceR2=new long[]{MASK,0,0x76543210L}[count];
                long node=active?0xf0000000L:B;probe(a,b,fixture(c,node,kind,count,active,false),c,node,kind);
            }
            for(int kind=0;kind<3;kind++)for(int mutation=1;mutation<=2;mutation++){
                BreakScenario c=new BreakScenario();c.callback=CALLBACK;c.payload=0xa9876543L;c.serviceR2=0x12345678;c.mutation=mutation;
                probe(a,b,fixture(c,B,kind,2,true,false),c,B,kind);
            }
            for(int kind=0;kind<3;kind++)for(int terminal=1;terminal<=(kind==2?2:4);terminal++)for(long callback:new long[]{0,CALLBACK,THUMB_CALLBACK}){
                BreakScenario c=new BreakScenario();c.callback=callback;c.payload=0x87654321L;c.serviceR2=0x81234567L;c.terminalIndex=terminal;
                probe(a,b,fixture(c,B,kind,2,true,false),c,B,kind);
            }
            // Entry and post-service words vary independently, not just by list shape.
            for(long input:new long[]{0,0x80000000L,MASK})for(long output:new long[]{0,0x76543210L,MASK}){
                BreakScenario c=new BreakScenario();c.callback=CALLBACK;c.payload=input;c.serviceR2=output;
                probe(a,b,fixture(c,B,2,2,true,false),c,B,2);
            }
            // Empty first embedded pool must carry entry r2 into the live second.
            BreakScenario skip=new BreakScenario();skip.callback=CALLBACK;skip.payload=0x1234abcd;skip.serviceR2=MASK;
            State skipState=fixture(skip,B,1,2,true,false);skipState.set(B+0xf4+12,0);skipState.set(B+0xf4+16,0);
            probe(a,b,skipState,skip,B,1);
            // Full-width detached node address becomes the next pool's payload.
            BreakScenario high=new BreakScenario();high.callback=CALLBACK;high.payload=MASK;high.serviceR2=0;
            State highState=fixture(high,B,1,0,true,false);highState.add(0xf0010000L-16,48,0xb1);highState.set(0xf0010000L,0x12345678);highState.set(0xf0010004L,0);
            highState.set(B+0xf4+16,0xf0010000L);probe(a,b,highState,high,B,1);
            for(int mask:new int[]{1,16,17,31})for(boolean nested:new boolean[]{false,true})for(int handleMode=0;handleMode<3;handleMode++){
                BreakScenario c=new BreakScenario();c.callback=CALLBACK;c.payload=0x87654321L;c.serviceR2=0x81234567L;
                c.clearHandle=handleMode==2;c.closeKernel=handleMode==1?0x80000000L:1;c.closeStatus=MASK;
                State s=fixture(c,B,0,2,true,false);
                if(nested){s.set(SECOND+48,MASK);s.set(SECOND+52,LOCK_TLS);s.set(SECOND+56,3);}
                for(int i=0;i<5;i++)if((mask&(1<<i))!=0){long file=FILES+32*i;s.set(B+12+4*i,file);s.set(file,0x420998);s.set(file+4,handleMode==0?0:0x12345678);}
                s.set(SECOND+36,FILES+0x200);probe(a,b,s,c,B,0);
            }
            for(boolean nested:new boolean[]{false,true}){
                BreakScenario c=new BreakScenario();c.callback=CALLBACK;c.payload=MASK;c.serviceR2=0;c.terminalIndex=1;
                State s=fixture(c,B,0,2,true,true);if(nested){s.set(SECOND+48,MASK);s.set(SECOND+52,LOCK_TLS);s.set(SECOND+56,3);}
                probe(a,b,s,c,B,0);
            }
            // A close callback can change the later owned slot and the global
            // destination pool. Keep the ordered-write and node-return oracle.
            for(int effect=0;effect<2;effect++){
                BreakScenario c=new BreakScenario();c.callback=THUMB_CALLBACK;c.payload=MASK;c.serviceR2=0;c.changeSlot=effect==0;c.movePool=effect==1;
                State s=fixture(c,B,0,2,true,true);s.set(FILES+0xa0,0x420998);s.set(FILES+0xa4,0x23456789);
                probe(a,b,s,c,B,0);
            }
        }
        int sites=0;for(long[] range:new long[][]{{OBJECT_DISPOSE,0x356840},{TEARDOWN,0x3568c0},{BASE_TEARDOWN,0x2a45e8},{DIAG2,DIAG2+8},{0x2ad90c,0x2ad958},{0x1526b4,0x1526bc}})
            for(long pc=range[0];pc<range[1];pc+=4){require(visited.contains(pc),"Connected instruction site "+Long.toHexString(pc));sites++;}
        require(sites==97,"Teardown and reused break extents");
        Files.writeString(out.resolve("visited.txt"),String.join("\n",visited.stream().map(v->String.format("%08x",v)).toList()));
        Files.writeString(out.resolve("comparison.json"),String.format(Locale.ROOT,"{\"connected_pairs\":%d,\"callback_calls_both\":%d,\"svc_calls_both\":%d,\"terminal_outcomes_both\":%d,\"break_dispatch_executed\":true,\"concrete_file_disposal_and_nested_locks\":true,\"entry_and_return_r2_checked\":true,\"teardown_and_reused_break_sites\":97,\"callback_and_kernel_modeled\":true,\"live_verified\":false}\n",pairs,callbacks,services,terminals));
        println("SMT4_POOL_TEARDOWN_BREAK_COMPARE_OK");
    }
}
