// Alternate creation and concrete virtual handle wrapping through the lifetime chain.
// @category SMT4
import ghidra.pcode.emu.PcodeThread;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.pcode.utils.Utils;
import java.nio.file.*;
import java.security.MessageDigest;
import java.util.*;
import java.io.*;

public class CompareResourcePoolAlternate extends CompareResourcePoolObjectTeardown {
    static final long ALTERNATE=0x1270c4,WRAP=0x3567a4;
    long wrapEntry; int factoryPairs,factoryCalls; boolean directFactory;
    PrintWriter transport;
    int originalFirstByte=-1;
    class AlternateMachine extends TeardownMachine {
        boolean wrapping;long wrapOutput,wrapReturn,wrapInitial,wrapExpected,wrapHandle,wrapSp;
        List<Write> publications=new ArrayList<>();
        AlternateMachine(byte[] map,byte[] binary){super(map,binary);}
        @Override long originalOwner(){return ALTERNATE;}
        @Override long[] ownerStack(OwnerPlan p){return new long[]{p.c.parameters[3],p.c.parameters[4],INPUT};}
        @Override void ownerRegisters(OwnerPlan p){register("r0",OUTPUT);register("r1",p.c.parameters[0]);register("r2",p.c.parameters[1]);register("r3",p.c.parameters[2]);}
        @Override void setup(boolean rebuilt,long original,long build){
            super.setup(rebuilt,original,build);wrapping=false;
            writeWord(0x420a3c+60,rebuilt?wrapEntry:WRAP);
        }
        @Override boolean permitted(long pc){return within(pc,4,ALTERNATE,0x127218)||within(pc,4,WRAP,0x3567e4)||super.permitted(pc);}
        @Override void checkRequest(OwnerPlan p,Boundary b){
            require(get(register("r0"))==b.before.get(STATE+16),"Alternate service captured");
            require(get(register("r1"))==0,"Alternate initial handle");
            require(register("r2")==0&&register("r3")==3,"Alternate request registers");long sp=register("sp");
            require(get(sp)==1&&get(sp+8)==1&&get(sp+12)==2&&get(sp+20)==12&&get(sp+24)==1&&get(sp+28)==0,"Alternate request scalar layout");
            long one=get(sp+4),two=get(sp+16);require(within(one,4,sp,STACK)&&get(one)==one,"Alternate self-referential byte buffer storage");
            require(two==INPUT,"Alternate descriptor passed by address");
            // The pinned build currently places this local at the original
            // stack offset. Also compare the actual exposed byte; a later
            // compiler/frame change must not silently broaden this evidence.
            if(!rebuiltPath)originalFirstByte=(int)get(one)&255;
            else require(((int)get(one)&255)==originalFirstByte,"Alternate exposed byte equals original");
            transport.printf("%s\t%x\t%x\t%x\t%x\t%x\t%x%n",rebuiltPath?"rebuilt":"original",one,get(one),get(one)&255,get(two),get(two+4),get(two+8));
            probe=new RequestProbe(p.c);probe.data1=memory(one,4);probe.data2=memory(two,12);probe.effects=b.effects;
        }
        @Override public void beforeStore(PcodeThread<byte[]> t,PcodeOp op,AddressSpace sp,byte[] offset,int size,byte[] value){
            long at=Utils.bytesToLong(offset,offset.length,false);
            if(wrapping&&at==wrapOutput){require(size==4,"Factory publication width");publications.add(new Write(at,word(value,0)));}
            super.beforeStore(t,op,sp,offset,size,value);
        }
        void finishWrap(){
            require(register("sp")==wrapSp,"Factory stack restored");
            require(register("r0")== (wrapExpected==0?EMPTY:0),"Factory result");
            require(get(wrapOutput)==(wrapExpected==0?wrapInitial:wrapExpected),"Factory output preservation/publication");
            require(publications.equals(wrapExpected==0?List.of():List.of(new Write(wrapOutput,wrapExpected))),"Factory output write count");
            if(wrapExpected!=0)require(get(wrapExpected)==0x420998&&get(wrapExpected+4)==wrapHandle,"Factory node layout");
            wrapping=false;factoryCalls++;
        }
        @Override void machineStep(boolean rebuilt,int steps)throws Exception{
            long pc=thread.getCounter().getOffset();
            if(wrapping&&pc==wrapReturn)finishWrap();
            if(pc==(rebuilt?wrapEntry:WRAP)){
                require(!wrapping&&(register("sp")&7)==0,"Factory call alignment/context");
                if(!directFactory)require(register("r0")==object,"Factory receiver");
                wrapping=true;wrapOutput=register("r1");wrapReturn=register("lr")&~1L;wrapSp=register("sp");
                wrapInitial=get(wrapOutput);wrapExpected=get(SECOND+36);wrapHandle=register("r2");publications.clear();
                if(!directFactory)require(wrapInitial==0&&wrapHandle==scenario.handle,"Caller factory arguments");
            }
            super.machineStep(rebuilt,steps);
        }
        @Override void owner(boolean rebuilt,OwnerPlan p)throws Exception{super.owner(rebuilt,p);require(!wrapping,"Factory returned");}
        void factory(boolean rebuilt,OwnerPlan p,long receiver,long handle)throws Exception{
            scenario=(LifeScenario)p.c;active=false;inQuery=false;setup(rebuilt,WRAP,wrapEntry);
            register("r0",receiver);register("r1",OUTPUT);register("r2",handle);executing=true;int steps=0,closes=0;
            while(thread.getCounter().getOffset()!=RETURN){
                long pc=thread.getCounter().getOffset();
                if(get(pc)==0xef000023L){
                    require((register("sp")&3)==0&&register("r0")==handle,"Exhausted factory closes captured handle");
                    require(observed.equals(p.writes),"No exhausted factory output store");require(get(OUTPUT)==p.s.get(OUTPUT),"Exhausted output untouched before close");
                    if(!rebuilt)visited.add(pc);for(String r:new String[]{"r1","r2","r3","r12"})register(r,0xdeadbeefL);
                    register("r0",((LifeScenario)scenario).closeKernel);register("cpsr",0xa0000010L);thread.overrideCounter(toAddr(pc+4));closes++;continue;
                }
                machineStep(rebuilt,++steps);
            }
            require(wrapping,"Direct factory entered");finishWrap();
            require(closes==(p.file==0?1:0),"Factory close count");require(observed.equals(p.writes),"Factory ordered writes rebuilt="+rebuilt+" expected="+p.writes+" actual="+observed);matches(p.s);matches(tls);finishChecks(steps);
        }
    }
    void factoryPair(AlternateMachine a,AlternateMachine b,State s,long receiver,long handle,LifeScenario c)throws Exception{
        OwnerPlan p=blankPlan(s,c,B);p.acquire(SECOND+48);p.file=p.s.get(SECOND+36);
        if(p.file!=0){p.w(SECOND+36,p.s.get(p.file));p.w(SECOND+44,p.s.get(SECOND+44)+1);}p.release(SECOND+48);
        if(p.file!=0){p.w(p.file,0x420998);p.w(p.file+4,handle);p.w(OUTPUT,p.file);}
        try{directFactory=true;a.seed(s);b.seed(s);a.factory(false,p,receiver,handle);b.factory(true,p,receiver,handle);factoryPairs++;
            results.printf("factory\t%d\t%x\t%x\t%x%n",factoryPairs,receiver,handle,p.file);
        }catch(Exception e){throw new IllegalStateException("Pool owner case factory "+factoryPairs,e);}finally{directFactory=false;}
    }
    State pair(AlternateMachine a,AlternateMachine b,State s,LifeScenario c,boolean seed)throws Exception{
        return ownerPair(a,b,s,c,seed);
    }
    @Override public void run()throws Exception{
        Path out=Path.of(getScriptArgs()[0]);byte[] map=new byte[0x377000];require(currentProgram.getMemory().getBytes(toAddr(0x100000),map)==map.length,"Map");
        require(HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(map)).equals("834938d18d2b7c688311c46c27bed813d0d7a9f8e3cbb61da8a6a3f23d360ebd"),"Hash");
        require(word(map,0x420a3c-0x100000+60)==WRAP,"Factory vtable");
        require(word(map,0x420a3c-0x100000+48)==OBJECT_DISPOSE&&word(map,0x420a3c-0x100000+52)==TEARDOWN,"Object vtable");
        require(word(map,0x420998-0x100000)==READ&&word(map,0x420998-0x100000+44)==FILE_DISPOSE&&word(map,0x420998-0x100000+48)==FILE_TEARDOWN,"File vtable");
        StringBuilder staticText=new StringBuilder();
        for(long[] range:new long[][]{{ALTERNATE,0x127218},{WRAP,0x3567e4}}){
            var f=getFunctionAt(toAddr(range[0]));staticText.append(String.format("%08x saved=%s%n",range[0],f==null?"none":f.getBody()));
            for(long pc=range[0];pc<range[1];pc+=4)staticText.append(String.format("%08x %s%n",pc,getInstructionAt(toAddr(pc))));
        }
        Files.writeString(out.resolve("static-ghidra.txt"),staticText);
        byte[] binary=Files.readAllBytes(out.resolve("resource-worker-backend.bin"));codeSize=binary.length;
        var entries=Files.readAllLines(out.resolve("alternate-entries.txt"));ownerEntry=Long.parseLong(entries.get(0));wrapEntry=Long.parseLong(entries.get(1));
        entries=Files.readAllLines(out.resolve("object-init-entries.txt"));initEntry=Long.parseLong(entries.get(0));queryEntry=Long.parseLong(entries.get(1));serviceEntry=Long.parseLong(entries.get(2));ipcEntry=Long.parseLong(entries.get(3));
        entries=Files.readAllLines(out.resolve("teardown-entries.txt"));for(int i=0;i<6;i++)cleanupEntries[i]=Long.parseLong(entries.get(i));
        recoverRequest=true;requestEntry=Long.parseLong(Files.readString(out.resolve("request-entry.txt")));
        AlternateMachine a=new AlternateMachine(map,binary),b=new AlternateMachine(map,binary);
        try(PrintWriter log=new PrintWriter(Files.newBufferedWriter(out.resolve("results.tsv")));
            PrintWriter requests=new PrintWriter(Files.newBufferedWriter(out.resolve("request-layouts.tsv")))){
            results=log;transport=requests;
            transport.println("machine\tbuffer_address\tself_word\texposed_byte\tdescriptor_0\tdescriptor_1\tdescriptor_2");
            // Independent factory contract: ignored/unmapped receivers, handle bits,
            // exhaustion output sentinels, count wrap and recursive pool locks.
            for(boolean empty:new boolean[]{false,true})for(long handle:new long[]{0,1,0x80000000L,MASK})for(int nested:new int[]{0,3}){
                LifeScenario c=new LifeScenario(false);c.closeKernel=handle;State s=lifeFixture(1,0,empty);
                s.set(OUTPUT,handle^0x87654321L);s.set(SECOND+44,handle);
                s.set(SECOND+48,nested==0?1:MASK);s.set(SECOND+52,nested==0?0:LOCK_TLS);s.set(SECOND+56,nested);
                factoryPair(a,b,s,handle,handle,c);
            }
            // Original alternate owner, persistent failure/dispose/reuse with real pools.
            for(boolean load:new boolean[]{false,true})for(int nested:new int[]{0,3}){
                State s=lifeFixture(0,nested,false);a.seed(s);b.seed(s);sequences++;
                for(int i=0;i<10;i++){
                    LifeScenario c=new LifeScenario(load);c.queryValue=new long[]{0xfffffff7L,0xfffffff8L,0,8,9}[i%5];
                    c.effects=true;c.handle=i%2==0?0:0x80000000L+i;
                    if(i==1)c.request=c.responseStatus=0xc8a01234L;
                    if(i==2)c.kernel=c.request=0x80000001L;
                    if(i==3)c.counts[0]=39;
                    if(i==4)c.parameters[3]=0;
                    if(i==5&&load)c.statuses[4]=MASK;
                    c.closeKernel=i%3==0?0x80000000L:1;c.closeStatus=i%2==0?MASK:0;
                    s=pair(a,b,s,c,false);
                    if(c.request>>31==0&&c.init>>31==0)s=cleanupPair(a,b,s,c,s.get(OUTPUT),0,false);
                    require(s.get(P+44)==0&&s.get(SECOND+44)==5,"Alternate lifetime counts restored");
                }
            }
            // Signed kernel/service boundaries and no response: IPC command word 1
            // becomes success and word 3 (type 1) becomes the wrapped handle.
            for(long kernel:new long[]{0,1,0x7fffffffL,0x80000000L,MASK})for(long service:new long[]{0,1,0x7fffffffL,0x80000000L,MASK}){
                LifeScenario c=new LifeScenario(false);c.kernel=kernel;c.request=service;c.concrete();
                pair(a,b,lifeFixture(1,0,false),c,true);
            }
            LifeScenario unanswered=new LifeScenario(false);unanswered.response=false;unanswered.request=unanswered.responseStatus=0;unanswered.handle=1;
            pair(a,b,lifeFixture(1,0,false),unanswered,true);
            // Empty main/file pools, header/read failures, descriptor edge words,
            // high mapped nodes and argument transport into initialized layouts.
            for(int mode=0;mode<12;mode++){
                LifeScenario c=new LifeScenario(true);State s=lifeFixture(1,mode%2==0?0:3,mode==1||mode==2);
                if(mode==0)s.set(P+36,0);
                if(mode==1)c.handle=0;
                if(mode>=3&&mode<=8)c.statuses[mode-3]=0x80001234L;
                if(mode==9){long n=0xf0000000L;s.add(n-16,0x150,0xb7);s.set(P+36,n);s.set(n,0);}
                if(mode==10){c.parameters[0]=1;c.parameters[1]=4;c.parameters[3]=176;}
                if(mode==11){c.parameters[0]=0x08000002;c.parameters[1]=0x20000003;c.parameters[3]=184;}
                s.set(INPUT,new long[]{0,1,0x80000000L,MASK}[mode%4]);s.set(INPUT+4,0x76543210);s.set(INPUT+8,0xfedcba98L);
                pair(a,b,s,c,true);
            }
        }
        int sites=0;for(long[] range:new long[][]{{ALTERNATE,0x127218},{WRAP,0x3567e4}})for(long pc=range[0];pc<range[1];pc+=4){require(visited.contains(pc),"Alternate site "+Long.toHexString(pc));sites++;}
        Files.writeString(out.resolve("visited.txt"),String.join("\n",visited.stream().map(v->String.format("%08x",v)).toList()));
        Files.writeString(out.resolve("comparison.json"),String.format(Locale.ROOT,"{\"alternate_owner_pairs\":%d,\"direct_factory_pairs\":%d,\"factory_calls_both\":%d,\"cleanup_pairs\":%d,\"persistent_sequences\":%d,\"new_instruction_sites\":%d,\"request_calls_both\":%d,\"file_close_ipc_calls_both\":%d,\"ordered_writes_full_fixtures_checked\":true,\"request_initializer_and_lifetime_chain_executed\":true,\"factory_exhaustion_preserves_output\":true,\"first_buffer_self_pointer_normalized\":true,\"raw_first_buffer_byte_equality_claimed\":true,\"reads_and_diagnostics_modeled\":true,\"tls_svc_exclusives_scheduled\":true,\"live_verified\":false}\n",ownerCases,factoryPairs,factoryCalls,cleanupPairs,sequences,sites,requestCalls,closeCalls));
        println("SMT4_POOL_OWNER_COMPARE_OK");
    }
}
