// Concrete resource lifetime, file disposal and close IPC; scheduled kernel/diagnostics.
// @category SMT4
import ghidra.pcode.emu.PcodeThread;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.pcode.utils.Utils;
import java.nio.file.*;
import java.security.MessageDigest;
import java.util.*;
import java.io.*;

public class CompareResourcePoolObjectTeardown extends CompareResourcePoolObjectInitialize {
    static final long TEARDOWN=0x356844,BASE_TEARDOWN=0x2a458c,FILE_TEARDOWN=0x356578,CLOSE=0x356d5c;
    static final long DIAG2=0x2bce9c,P2=0x950000,LINKS=0x951000,ALT_TEARDOWN=0x780020;
    long[] cleanupEntries=new long[6];
    final long[] cleanupOriginal={OBJECT_DISPOSE,TEARDOWN,BASE_TEARDOWN,FILE_DISPOSE,FILE_TEARDOWN,CLOSE};
    int cleanupPairs,basePairs,sequences,closeCalls,handleCloses,baseDiagnostics;
    class LifeScenario extends InitScenario {
        long closeKernel,closeStatus; boolean movePool,changeSlot,clearHandle,clearList,alternateTeardown;
        LifeScenario(boolean load){super(load);}
    }
    class CleanupBoundary extends Boundary {
        long node,handle;
        CleanupBoundary(long pc,OwnerPlan p,long node){super(pc,p);this.node=node;p.boundaries.add(this);}
    }
    CleanupBoundary event(long pc,OwnerPlan p,long node){return new CleanupBoundary(pc,p,node);}
    void returnNode(OwnerPlan p,long pool,long node){
        p.acquire(pool+48);p.w(node,p.s.get(pool+36));p.w(pool+36,node);p.w(pool+44,p.s.get(pool+44)-1);p.release(pool+48);
    }
    @Override void planFileDispose(OwnerPlan p,long file){
        LifeScenario c=(LifeScenario)p.c;event(FILE_DISPOSE,p,file);
        if(p.s.get(file+4)!=0){
            CleanupBoundary close=event(CLOSE,p,file);close.handle=p.s.get(file+4);
            if(c.movePool)close.effect(p,STATE+4,P2);
            if(c.clearHandle)close.effect(p,file+4,0);
            if(c.changeSlot&&file==FILES)close.effect(p,p.object+0x1c,FILES+0xa0);
        }
        event(FILE_TEARDOWN,p,file);
        if(p.s.get(file+4)!=0){CleanupBoundary svc=event(0x23,p,file);svc.handle=p.s.get(file+4);p.w(file+4,0);}
        returnNode(p,SECOND,file);
    }
    void planBase(OwnerPlan p,long pool){
        LifeScenario c=(LifeScenario)p.c;p.w(pool,0x420bc0);
        if(p.s.get(pool+12)!=0){CleanupBoundary e=event(DIAG2,p,pool);if(c.clearList)e.effect(p,pool+16,0);}
        if(p.s.get(pool+16)!=0){CleanupBoundary e=event(DIAG2,p,pool);if(c.clearList)e.effect(p,pool+16,0);}
        long node=p.s.get(pool+16);
        if(node!=0){int budget=0;while(node!=0){require(++budget<=8,"List domain");long next=p.s.get(node+4);p.w(node+4,0);p.w(node,0);node=next;}p.w(pool+16,0);}
    }
    void planTeardown(OwnerPlan p,long node){
        event(TEARDOWN,p,node);p.w(node+8,0);p.w(node,0x420948);
        for(int i=0;i<5;i++){long file=p.s.get(node+12+4*i);if(file!=0)planFileDispose(p,file);}
        for(int off:new int[]{0xf4,0xb8}){long pool=node+off;p.w(pool,0x420b00);if(p.s.get(pool+36)!=0)p.w(pool+36,0);planBase(p,pool);}
    }
    @Override void planObjectDispose(OwnerPlan p,long node){
        event(OBJECT_DISPOSE,p,node);
        if(((LifeScenario)p.c).alternateTeardown){CleanupBoundary e=event(ALT_TEARDOWN,p,node);e.effect(p,STATE+4,P2);e.effect(p,node+8,0x12345678);}
        else planTeardown(p,node);
        returnNode(p,p.s.get(STATE+4),node);
    }
    @Override long normalizePc(long pc){for(int i=0;i<6;i++)if(pc==cleanupEntries[i])return cleanupOriginal[i];return super.normalizePc(pc);}
    @Override boolean additionalExternal(long pc){return pc==TEARDOWN||pc==FILE_TEARDOWN||pc==CLOSE||pc==DIAG2||pc==ALT_TEARDOWN||super.additionalExternal(pc);}
    @Override boolean handleAdditional(OwnerMachine machine,long pc,Boundary boundary,OwnerPlan p)throws Exception{
        if(!(boundary instanceof CleanupBoundary))return super.handleAdditional(machine,pc,boundary,p);
        TeardownMachine m=(TeardownMachine)machine;CleanupBoundary e=(CleanupBoundary)boundary;
        if(pc==DIAG2||pc==ALT_TEARDOWN){
            if(pc==ALT_TEARDOWN)require(m.register("r0")==e.node,"Alternate teardown receiver");
            for(Write effect:e.effects)m.writeWord(effect.at(),effect.value());m.externalReturn(0xdeadbeefL);if(pc==DIAG2)baseDiagnostics++;return true;
        }
        if(e.pc==0x23){
            require(m.get(m.thread.getCounter().getOffset())==0xef000023L&&m.register("r0")==e.handle,"Close-handle argument");
            long site=m.thread.getCounter().getOffset();if(!m.rebuiltPath)visited.add(site);
            for(String r:new String[]{"r0","r1","r2","r3","r12"})m.register(r,0xdeadbeefL);
            m.register("cpsr",0xa0000010L);m.thread.overrideCounter(toAddr(site+4));handleCloses++;return true;
        }
        if(pc==CLOSE){require(m.get(m.register("r0"))==e.handle,"Captured close handle");m.startClose(e);}
        else require(m.register("r0")==e.node,"Cleanup receiver");
        m.machineStep(m.rebuiltPath,1);return true;
    }
    class TeardownMachine extends InitMachine {
        boolean inClose;long closeReturn,closeInput,closeHandle;int closeTlsReads;boolean closeSent;
        CleanupBoundary closeBoundary;List<Write> closeWrites=new ArrayList<>();
        TeardownMachine(byte[] map,byte[] binary){super(map,binary);}
        @Override boolean lock(long at){return at==P2+48||super.lock(at);}
        @Override boolean permitted(long pc){return within(pc,4,OBJECT_DISPOSE,0x356840)||within(pc,4,TEARDOWN,0x3568c0)||within(pc,4,BASE_TEARDOWN,0x2a45e8)||within(pc,4,FILE_DISPOSE,0x3564a4)||within(pc,4,FILE_TEARDOWN,0x3565a0)||within(pc,4,0x239cd0,0x239cf4)||within(pc,4,CLOSE,0x356d84)||super.permitted(pc);}
        @Override void setup(boolean rebuilt,long original,long build){
            super.setup(rebuilt,original,build);inClose=false;
            writeWord(0x420a3c+48,rebuilt?cleanupEntries[0]:OBJECT_DISPOSE);writeWord(0x420a3c+52,rebuilt?cleanupEntries[1]:TEARDOWN);
            writeWord(0x420998+44,rebuilt?cleanupEntries[3]:FILE_DISPOSE);writeWord(0x420998+48,rebuilt?cleanupEntries[4]:FILE_TEARDOWN);
        }
        void startClose(CleanupBoundary e){
            require(!inClose,"No nested close");inClose=true;closeReturn=register("lr")&~1L;closeInput=register("r0");closeHandle=get(closeInput);
            closeTlsReads=0;closeSent=false;closeWrites.clear();closeBoundary=e;tls.set(CMD,0x08080000);
        }
        @Override public void beforeStore(PcodeThread<byte[]> t,PcodeOp op,AddressSpace sp,byte[] offset,int size,byte[] value){
            long at=Utils.bytesToLong(offset,offset.length,false);
            if(inClose&&within(at,size,LOCK_TLS-16,LOCK_TLS+0x130)){require(size==4,"Close TLS width");closeWrites.add(new Write(at,word(value,0)));return;}
            super.beforeStore(t,op,sp,offset,size,value);
        }
        @Override void machineStep(boolean rebuilt,int steps)throws Exception{
            long pc=thread.getCounter().getOffset();LifeScenario c=(LifeScenario)scenario;
            if(inClose&&pc==closeReturn){
                require(closeSent&&closeTlsReads==1,"One close TLS/SVC");require(get(closeInput)==closeHandle,"Close input preserved");
                require(register("r0")==((c.closeKernel>>31)!=0?c.closeKernel:c.closeStatus),"Close result selection");matches(tls);inClose=false;closeCalls++;
            }
            long bits=get(pc);
            if(inClose&&(bits&0xffff0fffL)==0xee1d0f70L)closeTlsReads++;
            if(inClose&&bits==0xef000032L){
                require(!closeSent&&closeWrites.equals(List.of(new Write(CMD,0x08080000))),"Close command order/count");matches(tls);
                require(register("r0")==closeHandle,"Close kernel handle");tls.set(CMD+4,c.closeStatus);writeWord(CMD+4,c.closeStatus);
                for(Write effect:closeBoundary.effects)writeWord(effect.at(),effect.value());
                for(String r:new String[]{"r1","r2","r3","r12"})register(r,0xdeadbeefL);
                register("r0",c.closeKernel);register("cpsr",0xa0000010L);thread.overrideCounter(toAddr(pc+4));closeSent=true;if(!rebuilt)visited.add(pc);return;
            }
            super.machineStep(rebuilt,steps);
        }
        void cleanup(boolean rebuilt,OwnerPlan p,int kind)throws Exception{
            scenario=(LifeScenario)p.c;object=p.object;active=false;inQuery=false;setup(rebuilt,cleanupOriginal[kind],cleanupEntries[kind]);
            register("r0",p.object);executing=true;int steps=0,events=0;
            while(thread.getCounter().getOffset()!=RETURN){
                long pc=normalizePc(thread.getCounter().getOffset());boolean external=additionalExternal(pc)||pc==OBJECT_DISPOSE||pc==FILE_DISPOSE;
                boolean svc=!external&&get(pc)==0xef000023L;external|=svc;
                if(external){
                    require(events<p.boundaries.size(),"Cleanup extra boundary");Boundary e=p.boundaries.get(events++);
                    require(e.pc==(svc?0x23:pc),"Cleanup boundary order "+Long.toHexString(pc));require(observed.equals(p.writes.subList(0,e.writeCount)),"Cleanup boundary ordered writes");matches(e.before);
                    require((register("sp")&(svc?3:7))==0,"Cleanup boundary alignment");require(handleAdditional(this,pc,e,p),"Cleanup handler");continue;
                }
                machineStep(rebuilt,++steps);
            }
            require(events==p.boundaries.size()&&!inClose,"Cleanup complete");require(observed.equals(p.writes),"Cleanup final ordered writes");matches(p.s);matches(tls);
            if(kind!=0)require(register("r0")==p.object,"Teardown receiver return");finishChecks(steps);
        }
    }
    State lifeFixture(long guard,int nested,boolean empty){
        State s=ownerFixture(guard,nested,empty,ownerCases%4);s.add(STORAGE-16,0x800,0xa6);s.add(P2-16,0x60,0xa7);s.add(LINKS-16,0x100,0xa8);
        s.set(0x44e644,0xabc01234L);s.set(P2+36,0);s.set(P2+44,0);s.set(P2+48,1);s.set(P2+52,0);s.set(P2+56,0);
        s.set(AVT+52,ALT_TEARDOWN);return s;
    }
    OwnerPlan blankPlan(State s,LifeScenario c,long node){
        State empty=new State(s);empty.set(P+36,0);OwnerPlan p=new OwnerPlan(empty,c);p.s=new State(s);p.writes.clear();p.boundaries.clear();p.object=node;p.file=FILES;return p;
    }
    State cleanupPair(TeardownMachine a,TeardownMachine b,State s,LifeScenario c,long node,int kind,boolean seed)throws Exception{
        OwnerPlan p=blankPlan(s,c,node);if(kind==0)planObjectDispose(p,node);else if(kind==1)planTeardown(p,node);else planBase(p,node);
        try{if(seed){a.seed(s);b.seed(s);}a.cleanup(false,p,kind);b.cleanup(true,p,kind);cleanupPairs++;if(kind==2)basePairs++;
            results.printf("cleanup\t%d\t%d\t%x\t%d%n",cleanupPairs,kind,node,p.boundaries.size());return p.s;
        }catch(Exception e){throw new IllegalStateException("Pool owner case cleanup "+cleanupPairs,e);}
    }
    State ownerPair(TeardownMachine a,TeardownMachine b,State s,LifeScenario c,boolean seed)throws Exception{
        if(seed){a.seed(s);b.seed(s);}OwnerPlan p=new OwnerPlan(s,c);compare(a,b,p);return p.s;
    }
    @Override public void run()throws Exception{
        Path out=Path.of(getScriptArgs()[0]);byte[] map=new byte[0x377000];require(currentProgram.getMemory().getBytes(toAddr(0x100000),map)==map.length,"Map");
        require(HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(map)).equals("834938d18d2b7c688311c46c27bed813d0d7a9f8e3cbb61da8a6a3f23d360ebd"),"Hash");
        require(word(map,0x420a3c-0x100000+48)==OBJECT_DISPOSE&&word(map,0x420a3c-0x100000+52)==TEARDOWN,"Main vtable");
        require(word(map,0x420998-0x100000+44)==FILE_DISPOSE&&word(map,0x420998-0x100000+48)==FILE_TEARDOWN,"File vtable");
        StringBuilder staticText=new StringBuilder();
        for(long[] range:new long[][]{{OBJECT_DISPOSE,0x356840},{TEARDOWN,0x3568c0},{BASE_TEARDOWN,0x2a45e8}}){
            var f=getFunctionAt(toAddr(range[0]));staticText.append(String.format("%08x saved=%s%n",range[0],f==null?"none":f.getBody()));
            for(long pc=range[0];pc<range[1];pc+=4)staticText.append(String.format("%08x %s%n",pc,getInstructionAt(toAddr(pc))));
        }
        Files.writeString(out.resolve("static-ghidra.txt"),staticText);
        byte[] binary=Files.readAllBytes(out.resolve("resource-worker-backend.bin"));codeSize=binary.length;
        var entries=Files.readAllLines(out.resolve("owner-entries.txt"));ownerEntry=Long.parseLong(entries.get(0));constructEntry=Long.parseLong(entries.get(1));
        entries=Files.readAllLines(out.resolve("object-init-entries.txt"));initEntry=Long.parseLong(entries.get(0));queryEntry=Long.parseLong(entries.get(1));serviceEntry=Long.parseLong(entries.get(2));ipcEntry=Long.parseLong(entries.get(3));
        entries=Files.readAllLines(out.resolve("teardown-entries.txt"));for(int i=0;i<6;i++)cleanupEntries[i]=Long.parseLong(entries.get(i));
        recoverRequest=true;requestEntry=Long.parseLong(Files.readString(out.resolve("request-entry.txt")));
        TeardownMachine a=new TeardownMachine(map,binary),b=new TeardownMachine(map,binary);
        try(PrintWriter log=new PrintWriter(Files.newBufferedWriter(out.resolve("results.tsv")))){
            results=log;
            // Persistent create/fail/dispose/recreate: no reseeding between operations.
            for(boolean load:new boolean[]{false,true})for(int nested:new int[]{0,3}){
                State s=lifeFixture(0,nested,false);a.seed(s);b.seed(s);sequences++;
                for(int i=0;i<10;i++){
                    LifeScenario c=new LifeScenario(load);c.queryValue=new long[]{0xfffffff7L,0xfffffff8L,0,8,9}[i%5];
                    if(i==1)c.request=c.responseStatus=0xc8a01234L;
                    if(i==2)c.kernel=c.request=0x80000001L;
                    if(i==3)c.counts[0]=39;
                    if(i==4)c.parameters[3]=0;
                    if(i==5&&load)c.statuses[4]=MASK;
                    c.closeKernel=i%3==0?0x80000000L:i%3==1?1:0;c.closeStatus=i%2==0?MASK:0;
                    s=ownerPair(a,b,s,c,false);
                    if(c.request>>31==0&&c.init>>31==0){long node=s.get(OUTPUT);s=cleanupPair(a,b,s,c,node,0,false);require(s.get(P+36)==node,"Main node reusable");}
                    require(s.get(P+44)==0&&s.get(SECOND+44)==5,"Lifetime counts restored");
                }
            }
            // Header and every loaded read failure; return both concrete nodes.
            for(int index=0;index<6;index++){
                LifeScenario c=new LifeScenario(true);c.statuses[index]=0x80001234L;State s=lifeFixture(1,0,false);
                s=ownerPair(a,b,s,c,true);require(s.get(P+36)==B&&s.get(SECOND+36)==FILES,"Failure returns heads");
            }
            LifeScenario exhausted=new LifeScenario(false);ownerPair(a,b,lifeFixture(1,0,true),exhausted,true);
            // All ownership masks, zero/nonzero handles, two pool-head states and unsigned count edges.
            for(int mask=0;mask<32;mask++){
                LifeScenario c=new LifeScenario(false);State s=lifeFixture(1,mask%2==0?0:3,false);List<Write> ignored=new ArrayList<>();construct(s,ignored,B,true);s.set(STATE+4,P);
                s.set(P+44,new long[]{0,1,MASK,0x80000000L}[mask%4]);s.set(P+36,B+0x130);s.set(SECOND+44,0);
                for(int i=0;i<5;i++)if((mask&(1<<i))!=0){long f=FILES+32*i;s.set(B+12+4*i,f);s.set(f,0x420998);s.set(f+4,i%2==0?0:0x12340000+i);}
                s.set(SECOND+36,FILES+0x200);s.set(B+0xf4+36,mask%2==0?0:STORAGE);s.set(B+0xb8+36,mask%3==0?0:STORAGE+64);
                cleanupPair(a,b,s,c,B,mask%2,true);
            }
            // Service effects prove global-pool and later-slot reload; alternate virtual teardown is explicit.
            for(int mode=0;mode<4;mode++){
                LifeScenario c=new LifeScenario(false);c.movePool=mode==0;c.changeSlot=mode==1;c.clearHandle=mode==2;c.alternateTeardown=mode==3;
                State s=lifeFixture(1,0,false);construct(s,new ArrayList<>(),B,true);s.set(STATE+4,P);s.set(P+36,B+0x130);
                s.set(B+12,FILES);s.set(FILES,0x420998);s.set(FILES+4,0x12345678);s.set(FILES+0xa0,0x420998);s.set(FILES+0xa4,0x87654321L);
                if(c.alternateTeardown)s.set(B,AVT);cleanupPair(a,b,s,c,B,0,true);
            }
            // High objects and live embedded lists, with recursive pool locks.
            for(boolean high:new boolean[]{false,true})for(boolean clear:new boolean[]{false,true}){
                LifeScenario c=new LifeScenario(false);c.clearList=clear;State s=lifeFixture(1,0,false);long node=high?0xf0000000L:B;
                if(high)s.add(node-16,0x150,0xb7);construct(s,new ArrayList<>(),node,true);s.set(STATE+4,P);s.set(P+36,B+0x130);
                s.set(node+12,FILES);s.set(FILES,0x420998);s.set(FILES+4,MASK);s.set(SECOND+36,FILES+0x200);
                for(long lock:new long[]{P+48,SECOND+48}){s.set(lock,MASK);s.set(lock+4,LOCK_TLS);s.set(lock+8,3);}
                for(int i=0;i<2;i++){
                    long pool=node+(i==0?0xf4:0xb8),link=LINKS+32*i;s.set(pool+12,i==0?1:0);s.set(pool+16,link);s.set(pool+36,STORAGE+32*i);
                    s.set(link,0x87654321L);s.set(link+4,link+16);s.set(link+16,0xabcdef01L);s.set(link+20,0);
                }
                cleanupPair(a,b,s,c,node,0,true);
            }
            // Direct helper lists: diagnostic continuation, two-word detach, high pointers and untouched fields.
            for(int count=0;count<=3;count++)for(boolean active:new boolean[]{false,true})for(boolean clear:new boolean[]{false,true}){
                LifeScenario c=new LifeScenario(false);c.clearList=clear;State s=lifeFixture(1,0,false);long pool=count%2==0?B:0xf0000000L;
                if(pool!=B)s.add(pool-16,0x80,0xb6);s.set(pool+12,active?0x80000000L:0);s.set(pool+16,count==0?0:LINKS);
                for(int i=0;i<count;i++){s.set(LINKS+16*i,0xabc00000L+i);s.set(LINKS+16*i+4,i+1==count?0:LINKS+16*(i+1));}
                cleanupPair(a,b,s,c,pool,2,true);
            }
        }
        int sites=0;for(long[] range:new long[][]{{OBJECT_DISPOSE,0x356840},{TEARDOWN,0x3568c0},{BASE_TEARDOWN,0x2a45e8}})for(long pc=range[0];pc<range[1];pc+=4){require(visited.contains(pc),"Teardown site "+Long.toHexString(pc));sites++;}
        Files.writeString(out.resolve("visited.txt"),String.join("\n",visited.stream().map(v->String.format("%08x",v)).toList()));
        Files.writeString(out.resolve("comparison.json"),String.format(Locale.ROOT,"{\"owner_pairs\":%d,\"cleanup_pairs\":%d,\"direct_base_pairs\":%d,\"persistent_sequences\":%d,\"new_instruction_sites\":%d,\"file_close_ipc_calls_both\":%d,\"file_handle_close_calls_both\":%d,\"base_diagnostics_both\":%d,\"cleanup_models_removed\":true,\"file_disposal_teardown_close_ipc_executed\":true,\"pool_counts_return_and_reuse_checked\":true,\"ordered_writes_full_fixtures_checked\":true,\"reads_diagnostics_and_alternate_teardown_modeled\":true,\"tls_svc_exclusives_scheduled\":true,\"live_verified\":false}\n",ownerCases,cleanupPairs,basePairs,sequences,sites,closeCalls,handleCloses,baseDiagnostics));
        println("SMT4_POOL_OWNER_COMPARE_OK");
    }
}
