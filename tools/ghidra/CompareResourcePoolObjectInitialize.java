// Initializer and query-helper recovery through the concrete owner; lower reads/query are scheduled.
// @category SMT4
import ghidra.pcode.emu.PcodeThread;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.pcode.utils.Utils;
import java.nio.file.*;
import java.security.MessageDigest;
import java.util.*;
import java.io.*;

public class CompareResourcePoolObjectInitialize extends CompareResourcePoolOwner {
    static final long STORAGE=0x940000, READ=0x3564a8, SERVICE=0x2bbd3c, QUERY=0x14f42c;
    long initEntry,queryEntry,serviceEntry,ipcEntry; int directCases,readCalls,queryCalls,diagnostics;
    class InitScenario extends Scenario {
        long[] header={0x12345678,0x101,12,0x202,7,0x303,20,0x404,9,0xabcdef01L};
        long[] sizing=header.clone(),statuses=new long[6],counts={40,40,12,7,20,9};
        long queryStatus,queryKernel,queryValue,diagnosticValue,serviceHandle=0xabc01234L,serviceAfterDiagnostic=0xabc05678L; boolean diagnosticEffect;
        InitScenario(boolean load){super(0,0);parameters=new long[]{2,3,STORAGE,load?184:136,load?1:0};concrete();}
    }
    class InitBoundary extends Boundary {
        long offset,buffer,length,status,site=0x14622c; byte[] data; int readIndex=-1;
        InitBoundary(long pc,OwnerPlan p){super(pc,p);p.boundaries.add(this);}
    }
    void bytes(State s,long at,byte[] data){var e=s.blocks.floorEntry(at);System.arraycopy(data,0,e.getValue(),(int)(at-e.getKey()),data.length);}
    byte[] words(long[] values){byte[] data=new byte[values.length*4];for(int i=0;i<values.length;i++)put(data,4*i,values[i]);return data;}
    long scheduleRead(OwnerPlan p,int index,long offset,long buffer,long size){
        InitScenario c=(InitScenario)p.c;InitBoundary e=new InitBoundary(READ,p);e.readIndex=index;e.offset=offset&MASK;e.buffer=buffer;e.length=size;e.status=c.statuses[index];
        if(index<2)e.data=words(index==0?c.header:c.sizing);
        else {e.data=new byte[(int)size];for(int i=0;i<e.data.length;i++)e.data[i]=(byte)(0x30+index*13+i);bytes(p.s,buffer,e.data);}
        return e.status;
    }
    void pool(OwnerPlan p,long at,long base,long stride,long bytes){
        long aligned=(base+3)&~3L,available=((base+bytes-aligned)&MASK)/stride*stride;
        p.w(at+20,0);p.w(at+24,stride);p.w(at+28,aligned);p.w(at+32,available);p.w(at+44,0);p.w(at+40,4);
        long head=0,node=(aligned+available-stride)&MASK;
        int budget=0;while(aligned<=node){require(++budget<40,"Oracle pool domain");p.w(node,head);head=node;node=(node-stride)&MASK;}
        p.w(at+36,head);p.w(at+48,1);p.w(at+52,0);p.w(at+56,0);
    }
    @Override long planInitializer(OwnerPlan p){
        InitScenario c=(InitScenario)p.c;long n=p.object;long[] h=c.header,v=c.parameters;
        p.boundary(INIT);
        long status=scheduleRead(p,0,0,0,40);if((status>>31)!=0)return c.init=status;
        if(c.counts[0]!=40)return c.init=0xc8a04554L;
        long first=(v[0]*32)&MASK,second=(v[1]*24)&MASK,needed=(first+second)&MASK;
        if(v[4]!=0){
            status=scheduleRead(p,1,0,0,40);long sum=(c.sizing[2]+c.sizing[4]+c.sizing[6]+c.sizing[8])&MASK;
            needed=(status>>31)!=0||c.counts[1]!=40||(sum>>31)!=0?MASK:(needed+sum)&MASK;
        }
        if(needed>v[3])return c.init=EMPTY;
        long base=v[2];long[] starts=new long[4];
        if(v[4]!=0){
            long offset=40;
            for(int i=0;i<4;i++){
                starts[i]=base;status=scheduleRead(p,i+2,offset,base,h[2+2*i]);
                if((status>>31)!=0)return c.init=status;
                base=(base+h[2+2*i])&MASK;offset=(offset+c.counts[i+2])&MASK;
            }
            p.w(n+0x78,0);p.w(n+0x70,starts[0]);p.w(n+0x74,h[2]);p.w(n+0x7c,n);
            for(int i=1;i<4;i++){long at=n+0x70+16*i;p.w(at+8,0);p.w(at+4,h[2+2*i]);p.w(at,starts[i]);p.w(at+12,n);}
        }else for(int i=0;i<4;i++){long at=n+0x70+16*i;p.w(at+12,h[1+2*i]);p.w(at,0);p.w(at+4,h[2+2*i]);p.w(at+8,n);}
        long[][] fields={{0x2c,n+0x70},{0x20,0},{0x28,h[2]>>>2},{0x24,0},{0x3c,n+0x80},{0x38,h[4]},{0x30,0},{0x34,0},{0x48,0},{0x54,n+0x90},{0x64,n+0xa0},{0x4c,0},{0x50,h[6]>>>2},{0x58,0},{0x5c,0},{0x60,h[8]}};
        for(long[] f:fields)p.w(n+f[0],f[1]);
        pool(p,n+0xb8,base,32,first);pool(p,n+0xf4,(base+first)&MASK,24,second);p.w(n+0xb0,h[9]);
        if(p.s.get(0x44e644)==0){InitBoundary diagnostic=new InitBoundary(DIAG,p);diagnostic.status=0xe0a046dbL;diagnostic.site=0x2bbd58;diagnostic.effect(p,0x44e644,c.serviceAfterDiagnostic);}
        long queryResult=(c.queryKernel>>31)!=0?c.queryKernel:c.queryStatus;
        if((c.queryKernel>>31)==0)p.w(n+4,c.queryValue);
        if((queryResult>>31)!=0){InitBoundary diagnostic=new InitBoundary(DIAG,p);diagnostic.status=queryResult;if(c.diagnosticEffect)diagnostic.effect(p,n+4,c.diagnosticValue);}
        int value=(int)p.s.get(n+4),slot=value< -8?0:value<0?1:value==0?2:value<=8?3:4;
        p.w(n+12+4*slot,p.file);p.w(n+8,p.file);return c.init=0;
    }
    @Override long normalizePc(long pc){return pc==initEntry?INIT:super.normalizePc(pc);}
    @Override boolean concreteInitializer(){return true;}
    @Override boolean additionalExternal(long pc){return pc==READ||pc==DIAG;}
    @Override boolean handleAdditional(OwnerMachine m,long pc,Boundary boundary,OwnerPlan p)throws Exception{
        if(!(boundary instanceof InitBoundary))return false;
        InitBoundary e=(InitBoundary)boundary;InitScenario c=(InitScenario)p.c;
        if(pc==READ){
            require(m.register("r0")==p.file,"Read object");long out=m.register("r1"),sp=m.register("sp"),buffer=m.get(sp);
            require(m.register("r2")==e.offset&&m.register("r3")==((e.offset&0x80000000L)==0?0:MASK),"Read signed offset");
            require(m.get(sp+4)==e.length,"Read length");require(within(out,4,STACK-0x400,STACK),"Read count location");
            if(e.readIndex<2)require(within(buffer,40,STACK-0x400,STACK)&&!(out>=buffer&&out<buffer+40),"Header extent");else require(buffer==e.buffer,"Payload placement");
            m.memory(buffer,e.data);m.writeWord(out,c.counts[e.readIndex]);m.externalReturn(e.status);readCalls++;
        }else if(pc==DIAG){require(m.register("r0")==e.status&&m.register("r1")==e.site,"Diagnostic arguments");
            for(Write effect:e.effects)m.writeWord(effect.at(),effect.value());m.externalReturn(0xdeadbeefL);diagnostics++;
        }else return false;
        return true;
    }
    class InitMachine extends OwnerMachine {
        long object;boolean active;InitScenario scenario;
        long ipcReturn,ipcOutput,ipcInitial,ipcService;boolean inQuery,querySent;int queryTlsReads;
        List<Write> queryWrites=new ArrayList<>();
        @Override public void beforeStore(PcodeThread<byte[]> t,PcodeOp op,AddressSpace sp,byte[] offset,int size,byte[] value){
            long at=Utils.bytesToLong(offset,offset.length,false);
            if(inQuery&&within(at,size,LOCK_TLS-16,LOCK_TLS+0x130)){require(size==4,"Query TLS width");queryWrites.add(new Write(at,word(value,0)));return;}
            super.beforeStore(t,op,sp,offset,size,value);
        }
        void finishQuery(){
            require(querySent&&queryTlsReads==1,"One query TLS/kernel operation");require(queryWrites.equals(List.of(new Write(CMD,0x08630000))),"Query TLS command stores");
            require(register("r0")==((scenario.queryKernel>>31)!=0?scenario.queryKernel:scenario.queryStatus),"Query status");
            require(get(ipcOutput)==((scenario.queryKernel>>31)!=0?ipcInitial:scenario.queryValue),"Query publication");matches(tls);inQuery=false;queryCalls++;
        }
        InitMachine(byte[] map,byte[] binary){super(map,binary);}
        @Override boolean lock(long at){return super.lock(at)||(active&&(at==object+0xe8||at==object+0x124));}
        @Override boolean permitted(long pc){return within(pc,4,0x145e7c,0x14627c)||within(pc,4,SERVICE,0x2bbd64)||within(pc,4,QUERY,0x14f460)||super.permitted(pc);}
        @Override void machineStep(boolean rebuilt,int steps)throws Exception{
            long pc=thread.getCounter().getOffset();if(pc==(rebuilt?initEntry:INIT))active=true;
            if(inQuery&&pc==ipcReturn)finishQuery();
            if(pc==(rebuilt?ipcEntry:QUERY)){
                require(!inQuery,"Nested query");inQuery=true;querySent=false;queryTlsReads=0;queryWrites.clear();
                ipcReturn=register("lr")&~1L;ipcOutput=register("r1");ipcInitial=get(ipcOutput);ipcService=get(register("r0"));
                require(ipcOutput==object+4&&ipcService==get(0x44e644),"Concrete helper arguments");tls.set(CMD,0x08630000);
            }
            long bits=get(pc);
            if(inQuery&&(bits&0xffff0fffL)==0xee1d0f70L)queryTlsReads++;
            if(inQuery&&bits==0xef000032L){
                require(!querySent&&queryWrites.equals(List.of(new Write(CMD,0x08630000))),"Query command before send");matches(tls);
                require(register("r0")==ipcService&&get(ipcOutput)==ipcInitial,"Query kernel arguments/no early publication");
                tls.set(CMD+4,scenario.queryStatus);tls.set(CMD+8,scenario.queryValue);writeWord(CMD+4,scenario.queryStatus);writeWord(CMD+8,scenario.queryValue);
                for(String r:new String[]{"r1","r2","r3","r12"})register(r,0xdeadbeefL);
                register("r0",scenario.queryKernel);register("cpsr",0xa0000010L);thread.overrideCounter(toAddr(pc+4));querySent=true;if(!rebuilt)visited.add(pc);return;
            }
            super.machineStep(rebuilt,steps);
        }
        @Override void owner(boolean rebuilt,OwnerPlan p)throws Exception{object=p.object;active=false;inQuery=false;scenario=(InitScenario)p.c;super.owner(rebuilt,p);require(!inQuery,"Query returned");}
        void directInit(boolean rebuilt,OwnerPlan p)throws Exception{
            scenario=(InitScenario)p.c;inQuery=false;seed(p.boundaries.get(0).before);setup(rebuilt,INIT,initEntry);object=p.object;active=true;
            register("r0",p.object);register("r1",p.file);register("r2",p.c.parameters[0]);register("r3",p.c.parameters[1]);
            for(int i=0;i<3;i++)writeWord(STACK+4*i,p.c.parameters[i+2]);writeWord(STACK+12,0x96a55a96L);
            executing=true;int steps=0,events=1;
            while(thread.getCounter().getOffset()!=RETURN){
                long pc=thread.getCounter().getOffset();
                if(additionalExternal(pc)){
                    require(events<p.boundaries.size(),"Direct extra dependency");Boundary e=p.boundaries.get(events++);
                    require(e.pc==pc,"Direct dependency order");require(observed.equals(p.writes.subList(0,e.writeCount)),"Direct boundary writes");matches(e.before);
                    require((register("sp")&7)==0,"Direct boundary alignment");require(handleAdditional(this,pc,e,p),"Direct boundary");continue;
                }
                machineStep(rebuilt,++steps);
            }
            require(events==p.boundaries.size(),"Direct missing boundary");require(observed.equals(p.writes),"Direct final writes");matches(p.s);
            require(register("r0")==p.result,"Direct result");for(int i=0;i<3;i++)require(get(STACK+4*i)==p.c.parameters[i+2],"Direct preserved arguments");
            require(get(STACK+12)==0x96a55a96L,"Direct upper stack guard");finishChecks(steps);
        }
    }
    void casePair(InitMachine a,InitMachine b,InitScenario c,boolean direct,PrintWriter log)throws Exception{
        State s=ownerFixture(1,3,false,ownerCases%4);s.set(0x44e644,c.serviceHandle);s.add(STORAGE-16,0x800,0xa6);
        try{
            if(direct){
                s.set(P+36,0);OwnerPlan p=new OwnerPlan(s,c);p.s=new State(s);p.writes.clear();p.boundaries.clear();p.object=directCases%2==0?B:0xf0000000L;p.file=FILES;
                if(p.object!=B)p.s.add(p.object-16,0x150,0xa7);
                p.s.set(FILES,0x420998);p.s.set(FILES+4,0x12345678);p.s.set(p.object+4,0x81234567L);
                p.result=planInitializer(p);a.directInit(false,p);b.directInit(true,p);directCases++;
            }else{OwnerPlan p=new OwnerPlan(s,c);a.seed(s);b.seed(s);compare(a,b,p);}
            log.printf("%s\t%d\t%d\t%s\t%s\t%x%n",direct?"direct":"owner",ownerCases,directCases,Arrays.toString(c.parameters),Arrays.toString(c.counts),c.init);
        }catch(Exception e){throw new IllegalStateException("Pool owner case initializer "+ownerCases+" direct "+directCases,e);}
    }
    @Override public void run()throws Exception{
        Path out=Path.of(getScriptArgs()[0]);byte[] map=new byte[0x377000];require(currentProgram.getMemory().getBytes(toAddr(0x100000),map)==map.length,"Map");
        require(HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(map)).equals("834938d18d2b7c688311c46c27bed813d0d7a9f8e3cbb61da8a6a3f23d360ebd"),"Hash");
        require(word(map,0x420998-0x100000)==READ,"Concrete virtual read target");
        byte[] binary=Files.readAllBytes(out.resolve("resource-worker-backend.bin"));codeSize=binary.length;
        var entries=Files.readAllLines(out.resolve("owner-entries.txt"));ownerEntry=Long.parseLong(entries.get(0));constructEntry=Long.parseLong(entries.get(1));
        entries=Files.readAllLines(out.resolve("object-init-entries.txt"));initEntry=Long.parseLong(entries.get(0));queryEntry=Long.parseLong(entries.get(1));serviceEntry=Long.parseLong(entries.get(2));ipcEntry=Long.parseLong(entries.get(3));
        recoverRequest=true;requestEntry=Long.parseLong(Files.readString(out.resolve("request-entry.txt")));
        InitMachine a=new InitMachine(map,binary),b=new InitMachine(map,binary);
        try(PrintWriter log=new PrintWriter(Files.newBufferedWriter(out.resolve("results.tsv")))){
            results=log;
            for(boolean direct:new boolean[]{false,true}){
                for(boolean load:new boolean[]{false,true}){
                    for(long value:new long[]{0x80000000L,0xfffffff7L,0xfffffff8L,MASK,0,1,8,9,0x7fffffffL}){
                        InitScenario c=new InitScenario(load);c.queryValue=value;casePair(a,b,c,direct,log);
                    }
                    for(int delta:new int[]{-1,0,1}){InitScenario c=new InitScenario(load);c.parameters[3]+=delta;casePair(a,b,c,direct,log);}
                    for(long count:new long[]{0,39,41,MASK}){InitScenario c=new InitScenario(load);c.counts[0]=count;casePair(a,b,c,direct,log);}
                    for(long status:new long[]{1,0x7fffffffL,0x80000000L,0xc8a01234L,MASK}){InitScenario c=new InitScenario(load);c.statuses[0]=status;casePair(a,b,c,direct,log);}
                    for(long status:new long[]{1,0x80000000L,MASK})for(boolean publish:new boolean[]{false,true}){
                        InitScenario c=new InitScenario(load);c.queryStatus=status;c.queryKernel=publish?0:0x80001234L;c.queryValue=9;c.diagnosticEffect=status==MASK;c.diagnosticValue=0xfffffff8L;casePair(a,b,c,direct,log);
                    }
                    for(int offset:new int[]{0,1,3}){InitScenario c=new InitScenario(load);c.parameters[2]+=offset;c.parameters[0]=0;c.parameters[1]=0;c.parameters[3]=MASK;casePair(a,b,c,direct,log);}
                }
                for(long mode:new long[]{1,0x80000000L,MASK}){
                    InitScenario c=new InitScenario(true);c.parameters[4]=mode;c.parameters[2]+=mode==1?1:3;
                    c.header[2]=c.header[4]=c.header[6]=c.header[8]=0;c.sizing=c.header.clone();c.counts[2]=c.counts[3]=c.counts[4]=c.counts[5]=0;
                    c.parameters[3]=136;casePair(a,b,c,direct,log);
                }
                for(long kernel:new long[]{1,0x7fffffffL,MASK}){InitScenario c=new InitScenario(true);c.queryKernel=kernel;c.queryValue=8;casePair(a,b,c,direct,log);}
                for(long handle:new long[]{0,0x12345678,0x80000000L,MASK}){InitScenario c=new InitScenario(false);c.serviceHandle=0;c.serviceAfterDiagnostic=handle;casePair(a,b,c,direct,log);}
                for(int index=1;index<6;index++){
                    for(long status:new long[]{0x80000000L,0xc8a01234L}){InitScenario c=new InitScenario(true);c.statuses[index]=status;casePair(a,b,c,direct,log);}
                    for(long count:new long[]{0,1,0x7fffffffL,0xfffffff0L}){InitScenario c=new InitScenario(true);c.counts[index]=count;casePair(a,b,c,direct,log);}
                }
                for(int mode=0;mode<5;mode++){
                    InitScenario c=new InitScenario(true);c.parameters[3]=MASK;
                    if(mode==0)c.statuses[1]=MASK;
                    if(mode==1)c.counts[1]=39;
                    if(mode==2)c.sizing[2]=0x80000000L;
                    if(mode==3)c.sizing[2]=0xfffffff0L;
                    if(mode==4){c.parameters[0]=0x08000002;c.parameters[1]=0x20000003;c.parameters[3]=184;}
                    casePair(a,b,c,direct,log);
                }
                InitScenario c=new InitScenario(false);c.header[2]=MASK;c.header[4]=0x80000000L;c.header[6]=3;c.header[8]=0;casePair(a,b,c,direct,log);
            }
        }
        int sites=0;for(long pc=0x145e7c;pc<0x14627c;pc+=4){require(visited.contains(pc),"Initializer site "+Long.toHexString(pc));sites++;}
        int querySites=0;for(long[] range:new long[][]{{SERVICE,0x2bbd64},{QUERY,0x14f460}})for(long pc=range[0];pc<range[1];pc+=4){require(visited.contains(pc),"Query chain site "+Long.toHexString(pc));querySites++;}
        Files.writeString(out.resolve("visited.txt"),String.join("\n",visited.stream().map(v->String.format("%08x",v)).toList()));
        Files.writeString(out.resolve("comparison.json"),String.format(Locale.ROOT,"{\"owner_pairs\":%d,\"direct_initializer_pairs\":%d,\"initializer_and_helper_instruction_sites\":%d,\"read_calls_both\":%d,\"query_calls_both\":%d,\"returning_diagnostics_both\":%d,\"initializer_model_removed\":true,\"request_executed\":true,\"pool_lock_initializers_executed\":true,\"ordered_writes_full_fixtures_checked\":true,\"read_diagnostic_cleanup_models\":true,\"query_service_and_ipc_models_removed\":true,\"query_chain_instruction_sites\":%d,\"tls_svc_exclusives_scheduled\":true,\"live_verified\":false}\n",ownerCases,directCases,sites,readCalls,queryCalls,diagnostics,querySites));
        println("SMT4_POOL_OWNER_COMPARE_OK");
    }
}
