// Concrete pool ownership; optional request IPC recovery, explicit kernel/initializer/cleanup models.
// @category SMT4
import ghidra.pcode.emu.PcodeThread;
import ghidra.pcode.exec.*;
import ghidra.pcode.utils.Utils;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.pcode.PcodeOp;
import java.nio.file.*;
import java.security.MessageDigest;
import java.util.*;
import java.io.*;

public class CompareResourcePoolOwner extends CompareResourceLazyPool {
    static final long SECOND=0x4d4358, FILES=0x920000, INPUT=0x922000, OUTPUT=0x923000;
    static final long AVT=0x924000, FVT=0x924100, OBJECT_DISPOSE=0x3567f0, FILE_DISPOSE=0x356438;
    static final long ALT_OBJECT=0x780010, ALT_FILE=0x780014, REQUEST=0x2b5dd0, INIT=0x145e9c;
    static final long[] PARAM={0x81234567L,0xfedcba98L,0x11223344,0x80000000L,0xffffffffL};
    boolean recoverRequest; long requestEntry; int requestCases,requestCalls;
    static final long CMD=LOCK_TLS+0x80;
    long ownerEntry,constructEntry; int ownerCases,constructorCases; PrintWriter results;
    class Scenario {
        long[] parameters=PARAM;
        long kernel,responseStatus; boolean response=true,concreteScenario;
        long request,init,handle=0xaabbccddL; boolean publish=true,secondEmpty,alternate,effects;
        Scenario(long r,long i){request=r;init=i;}
        void concrete(){concreteScenario=true;responseStatus=request;publish=(kernel&0x80000000L)==0;if(!response){request=0;handle=2;}if(!publish)request=kernel;}
    }
    void write(State s,List<Write> writes,long at,long value){s.set(at,value);writes.add(new Write(at,value&MASK));}
    void construct(State s,List<Write> writes,long n,boolean clear){
        if(clear)for(int i=0;i<0x130;i+=4)write(s,writes,n+i,0);
        write(s,writes,n+4,0);write(s,writes,n+8,0);
        for(int i=0x20;i<=0x6c;i+=4)write(s,writes,n+i,0);
        for(int i=0xbc;i<=0xcc;i+=4)write(s,writes,n+i,0);
        for(int i:new int[]{0xdc,0xe8,0xec})write(s,writes,n+i,0);
        write(s,writes,n+0xf0,MASK);write(s,writes,n+0xf8,0);write(s,writes,n+0xb8,0x420b9c);
        for(int i=0xfc;i<=0x108;i+=4)write(s,writes,n+i,0);
        for(int i:new int[]{0x118,0x124,0x128})write(s,writes,n+i,0);
        write(s,writes,n+0x12c,MASK);write(s,writes,n+12,0);write(s,writes,n+0xf4,0x420b9c);
        for(int i:new int[]{0x10,0x14,0x18})write(s,writes,n+i,0);
        write(s,writes,n,0x420a3c);write(s,writes,n+0x1c,0);
    }
    class Boundary {
        long pc;State before;int writeCount;List<Write> effects=new ArrayList<>();
        Boundary(long address,OwnerPlan p){pc=address;before=new State(p.s);writeCount=p.writes.size();}
        void effect(OwnerPlan p,long at,long value){effects.add(new Write(at,value&MASK));p.s.set(at,value);}
    }
    class OwnerPlan {
        State s;List<Write> writes;List<Boundary> boundaries=new ArrayList<>();long object,file,result;int reads;Scenario c;
        Boundary boundary(long pc){Boundary b=new Boundary(pc,this);boundaries.add(b);return b;}
        void w(long at,long value){write(s,writes,at,value);}
        void acquire(long at){if(s.get(at+4)!=LOCK_TLS){w(at,MASK);w(at+4,LOCK_TLS);}w(at+8,s.get(at+8)+1);}
        void release(long at){long count=(s.get(at+8)-1)&MASK;w(at+8,count);if(count==0){w(at+4,0);w(at,1);}}
        OwnerPlan(State initial,Scenario config){
            c=config;Plan p=new Plan(initial);s=p.s;writes=p.writes;object=p.result;reads=p.reads;
            if(object==0){result=EMPTY;return;}
            construct(s,writes,object,true);
            Boundary request=boundary(REQUEST);
            if(c.effects)request.effect(this,STATE+16,0x778899aa);
            result=c.request;
            if((result&0x80000000L)==0){
                acquire(SECOND+48);file=s.get(SECOND+36);
                if(file!=0){w(SECOND+36,s.get(file));w(SECOND+44,s.get(SECOND+44)+1);}
                release(SECOND+48);
                if(file==0){Boundary close=boundary(0x23);if(c.effects)close.effect(this,STATE+16,0xa0b0c0d0L);result=EMPTY;}
                else{
                    w(file,0x420998);w(file+4,c.publish?c.handle:0);
                    result=planInitializer(this);
                    if((result&0x80000000L)!=0)planFileDispose(this,file);
                    else result=0;
                }
            }
            if((result&0x80000000L)!=0)planObjectDispose(this,object);
            else {w(OUTPUT,object);result=0;}
        }
    }
    void planFileDispose(OwnerPlan p,long file){Boundary release=p.boundary(p.c.alternate?ALT_FILE:FILE_DISPOSE);release.effect(p,file+4,0);}
    void planObjectDispose(OwnerPlan p,long object){Boundary release=p.boundary(p.c.alternate&&p.file!=0?ALT_OBJECT:OBJECT_DISPOSE);release.effect(p,object+0x1c,0xabcdef01L);}
    long planInitializer(OwnerPlan p) {
        Boundary init=p.boundary(INIT);init.effect(p,p.object+4,p.file);init.effect(p,p.object+8,0x13579bdf);
        if(p.c.alternate){init.effect(p,p.file,FVT);init.effect(p,p.object,AVT);}return p.c.init;
    }
    long normalizePc(long pc){return recoverRequest&&pc==requestEntry?REQUEST:pc;}
    boolean concreteInitializer(){return false;}
    boolean additionalExternal(long pc){return false;}
    boolean handleAdditional(OwnerMachine m,long pc,Boundary b,OwnerPlan p)throws Exception{return false;}
    class OwnerMachine extends LazyMachine {
        State tls; RequestProbe probe; boolean rebuiltPath;
        class RequestProbe {
            long output,ret,sp,initialOutput,service; long[] args=new long[10];
            List<Write> expected=new ArrayList<>(),actual=new ArrayList<>(),publications=new ArrayList<>();
            boolean sent; int tlsReads; Scenario c; byte[] data1,data2; List<Write> effects=List.of();
            RequestProbe(Scenario config){
                c=config;output=register("r1");ret=register("lr")&~1L;sp=register("sp");initialOutput=get(output);service=get(register("r0"));
                args[0]=register("r2");args[1]=register("r3");for(int i=0;i<8;i++)args[i+2]=get(sp+4*i);
                long[] words={0x08030204,args[0],args[1],args[2],args[4],args[5],args[7],args[8],args[9],((args[4]<<14)|0x802)&MASK,args[3],((args[7]<<14)|2)&MASK,args[6]};
                for(int index:new int[]{0,3,4,7,1,2,5,6,8,9,10,11,12}){expected.add(new Write(CMD+index*4,words[index]));tls.set(CMD+index*4,words[index]);}
            }
            void send(boolean rebuilt)throws Exception{
                require(!sent&&tlsReads==1,"One TLS read and kernel call");require(actual.equals(expected),"IPC ordered command writes");matches(tls);
                require(register("r0")==service,"Kernel service handle");require(get(output)==initialOutput,"No early handle publication");
                if(data1!=null){require(Arrays.equals(data1,memory(args[3],data1.length))&&Arrays.equals(data2,memory(args[6],data2.length)),"Kernel request buffers preserved");}
                if(c.response){long status=c.concreteScenario?c.responseStatus:c.request;tls.set(CMD+4,status);tls.set(CMD+12,c.handle);writeWord(CMD+4,status);writeWord(CMD+12,c.handle);}
                for(Write effect:effects)writeWord(effect.at(),effect.value());
                long pc=thread.getCounter().getOffset();if(!rebuilt)visited.add(pc);
                for(String r:new String[]{"r1","r2","r3","r12"})register(r,0xdeadbeefL);
                register("r0",c.kernel);register("cpsr",0xa0000010L);thread.overrideCounter(toAddr(pc+4));sent=true;
            }
            void finishProbe(){
                require(sent&&actual.equals(expected),"Kernel call or final TLS write order");long result=(c.kernel&0x80000000L)!=0?c.kernel:tls.get(CMD+4);
                long handle=(c.kernel&0x80000000L)!=0?initialOutput:tls.get(CMD+12);
                require(register("r0")==result,"IPC result");require(get(output)==handle,"IPC handle publication");
                require(publications.equals((c.kernel&0x80000000L)!=0?List.of():List.of(new Write(output,handle))),"IPC publication count/order");
                require(register("sp")==sp,"IPC stack restoration");for(int i=0;i<8;i++)require(get(sp+4*i)==args[i+2],"IPC input arguments preserved");matches(tls);if(data1!=null)require(Arrays.equals(data1,memory(args[3],data1.length))&&Arrays.equals(data2,memory(args[6],data2.length)),"Returned request buffers preserved");requestCalls++;
            }
        }
        OwnerMachine(byte[] map,byte[] binary){super(map,binary);}
        boolean lock(long at){return at==O||at==P+48||at==SECOND+48;}
        @Override public void beforeLoad(PcodeThread<byte[]> t,PcodeOp op,AddressSpace sp,byte[] offset,int size){
            long at=Utils.bytesToLong(offset,offset.length,false);
            if(at==G){require(size==4,"Guard width");reads++;}
            if(xload){require(size==4&&lock(at)&&!reserved,"Exclusive load");exclusive=at;reserved=true;}
            boolean ok=(recoverRequest&&within(at,size,LOCK_TLS-16,LOCK_TLS+0x130))||within(at,size,0x100000,0x477000)||within(at,size,BUILD,BUILD+codeSize)||within(at,size,STACK-0x1000,STACK+16);
            for(var e:layout.blocks.entrySet())ok|=within(at,size,e.getKey(),e.getKey()+e.getValue().length);
            require(ok,"Read extent "+Long.toHexString(at));
        }
        @Override public void beforeStore(PcodeThread<byte[]> t,PcodeOp op,AddressSpace sp,byte[] offset,int size,byte[] value){
            long at=Utils.bytesToLong(offset,offset.length,false);
            if(recoverRequest&&within(at,size,LOCK_TLS-16,LOCK_TLS+0x130)){
                require(probe!=null&&size==4,"IPC write width/context");probe.actual.add(new Write(at,word(value,0)));return;
            }
            if(probe!=null&&at==probe.output){require(size==4,"Handle width");probe.publications.add(new Write(at,word(value,0)));return;}
            if(within(at,size,STACK-0x1000,STACK))return;
            require(size==4,"Store width");
            if(lock(at)){
                if(at==P+48&&word(value,0)==0&&!allowed){}
                else {require(allowed&&at==exclusive,"Exclusive store");allowed=false;}
            }
            observed.add(new Write(at,word(value,0)));
        }
        void matches(State s){for(var e:s.blocks.entrySet())require(Arrays.equals(e.getValue(),memory(e.getKey(),e.getValue().length)),"Full fixture "+Long.toHexString(e.getKey()));}
        void setup(boolean rebuilt,long original,long build){
            rebuiltPath=rebuilt;
            initialize(rebuilt,0,new byte[0x144]);observed.clear();reads=0;reserved=pending=allowed=xload=false;
            if(recoverRequest){tls=new State();tls.blocks.clear();tls.add(LOCK_TLS-16,0x140,0);
                for(int i=0;i<0x140;i+=4)tls.set(LOCK_TLS-16+i,0xa5010000L+0x101*i);memory(LOCK_TLS-16,tls.blocks.get(LOCK_TLS-16));probe=null;}
            thread.overrideCounter(toAddr(rebuilt?build:original));
        }
        boolean permitted(long pc){
            return (recoverRequest&&within(pc,4,REQUEST,0x2b5e6c))||within(pc,4,0x2adcd8,0x2ade84)||within(pc,4,0x14636c,0x146448)||within(pc,4,0x2c4b84,0x2c4bd8)||
                within(pc,4,0x146284,0x146350)||within(pc,2,0x2c0128,0x2c013a)||
                within(pc,4,0x2a4eb4,0x2a4f54)||within(pc,4,0x2c3b54,0x2c3b70)||within(pc,4,0x138f44,0x138f5c)||
                within(pc,4,0x2c6c64,0x2c6c94)||within(pc,4,0x2c61e4,0x2c62d4)||
                within(pc,4,0x2c3afc,0x2c3b34)||within(pc,4,0x2c3a78,0x2c3a98)||
                within(pc,4,0x1464f8,0x1465d4)||within(pc,4,0x138fc0,0x139010)||within(pc,4,0x2b5d6c,0x2b5dd0);
        }
        void machineStep(boolean rebuilt,int steps)throws Exception{
            long pc=thread.getCounter().getOffset();require(rebuilt?within(pc,4,BUILD,BUILD+codeSize):permitted(pc),"Owner PC "+Long.toHexString(pc));
            require(steps<8192,"Budget");if(!rebuilt)visited.add(pc);
            long bits=get(pc);
            if(recoverRequest&&bits==0xef000032L){require(probe!=null,"Request context");probe.send(rebuilt);return;}
            if((bits&0xffff0fffL)==0xee1d0f70L){if(probe!=null)probe.tlsReads++;register("r"+((bits>>>12)&15),LOCK_TLS);thread.overrideCounter(toAddr(pc+4));return;}
            monitor.checkCancelled();thread.stepInstruction();
        }
        void finishChecks(int steps){finish(steps);require(!reserved&&!pending&&!allowed,"Exclusive completion");for(byte v:memory(STACK-0x1000,0xc00))require(v==(byte)0x96,"Stack guard");executing=false;}
        void direct(boolean rebuilt,State initial,long node)throws Exception{
            seed(initial);setup(rebuilt,0x14636c,constructEntry);register("r0",node);executing=true;
            State expected=new State(initial);List<Write> writes=new ArrayList<>();construct(expected,writes,node,false);int steps=0;
            while(thread.getCounter().getOffset()!=RETURN)machineStep(rebuilt,++steps);
            require(register("r0")==node,"Constructor result");require(observed.equals(writes),"Constructor ordered writes");matches(expected);finishChecks(steps);
        }
        void directRequest(boolean rebuilt,State initial,long[] args,Scenario c)throws Exception{
            seed(initial);setup(rebuilt,REQUEST,requestEntry);register("sp",STACK-32);register("r0",INPUT);register("r1",OUTPUT);
            register("r2",args[0]);register("r3",args[1]);for(int i=0;i<8;i++)writeWord(STACK-32+4*i,args[i+2]);
            probe=new RequestProbe(c);executing=true;int steps=0;
            while(thread.getCounter().getOffset()!=RETURN)machineStep(rebuilt,++steps);
            probe.finishProbe();State expected=new State(initial);if((c.kernel&0x80000000L)==0)expected.set(OUTPUT,tls.get(CMD+12));
            matches(expected);require(observed.isEmpty(),"No other direct writes");probe=null;register("sp",STACK);finishChecks(steps);
        }
        long originalOwner(){return 0x2adcd8;}
        long[] ownerStack(OwnerPlan p){return new long[]{p.c.parameters[2],p.c.parameters[3],p.c.parameters[4]};}
        void ownerRegisters(OwnerPlan p){register("r0",OUTPUT);register("r1",INPUT);register("r2",p.c.parameters[0]);register("r3",p.c.parameters[1]);}
        void checkRequest(OwnerPlan p,Boundary b){
            require(get(register("r0"))==b.before.get(STATE+16),"Service captured");require(get(register("r1"))==0,"Initial output handle");
            require(register("r2")==0&&register("r3")==0x2345678a,"Request registers");long sp=register("sp");
            require(get(sp)==2&&get(sp+8)==16&&get(sp+12)==2&&get(sp+20)==20&&get(sp+24)==1&&get(sp+28)==0,"Request scalar arguments");
            long one=get(sp+4),two=get(sp+16);require(within(one,16,sp,STACK)&&within(two,20,sp,STACK),"Request buffer extent");
            require(get(one)==b.before.get(INPUT)&&get(one+4)==b.before.get(INPUT+4)&&get(one+8)==(0xffffff00L|(b.before.get(INPUT+8)&255))&&get(one+12)==p.c.parameters[0],"Request first buffer and padding");
            require(get(two)==0&&get(two+4)==b.before.get(INPUT+12)&&get(two+8)==0&&get(two+12)==0&&get(two+16)==0,"Request second buffer");
            if(recoverRequest){probe=new RequestProbe(p.c);probe.data1=memory(one,16);probe.data2=memory(two,20);probe.effects=b.effects;}
        }
        void owner(boolean rebuilt,OwnerPlan p)throws Exception{
            setup(rebuilt,originalOwner(),ownerEntry);ownerRegisters(p);
            for(int i=0;i<3;i++)writeWord(STACK+4*i,ownerStack(p)[i]);writeWord(STACK+12,0x96a55a96L);
            executing=true;int steps=0,events=0;
            while(thread.getCounter().getOffset()!=RETURN){
                long pc=thread.getCounter().getOffset();
                if(probe!=null&&pc==probe.ret){probe.finishProbe();probe=null;}
                pc=normalizePc(pc);
                boolean external=additionalExternal(pc)||pc==REQUEST||pc==INIT||pc==OBJECT_DISPOSE||pc==FILE_DISPOSE||pc==ALT_OBJECT||pc==ALT_FILE;
                boolean svc=!external&&get(pc)==0xef000023L;external|=svc;
                if(external){
                    require(events<p.boundaries.size(),"Extra dependency");Boundary b=p.boundaries.get(events++);
                    require(b.pc==(svc?0x23:pc),"Dependency order "+Long.toHexString(pc));
                    require(observed.equals(p.writes.subList(0,b.writeCount)),"Boundary ordered writes");matches(b.before);
                    // SVC is not a public ABI call; a compiled leaf may use a
                    // word-aligned stack there. All function entries retain 8.
                    require((register("sp")&(svc?3:7))==0,"Boundary alignment");long value=0xdeadbeefL;
                    if(pc==REQUEST){
                        checkRequest(p,b);
                        if(recoverRequest){machineStep(rebuilt,++steps);continue;}
                        if(p.c.publish)writeWord(register("r1"),p.c.handle);value=p.c.request;
                    }else if(pc==INIT){
                        require(register("r0")==p.object&&register("r1")==p.file&&register("r2")==p.c.parameters[0]&&register("r3")==p.c.parameters[1],"Initializer registers");
                        for(int i=0;i<3;i++)require(get(register("sp")+4*i)==p.c.parameters[i+2],"Initializer stack arguments");value=p.c.init;
                        if(concreteInitializer()){machineStep(rebuilt,++steps);continue;}
                    }else if(handleAdditional(this,pc,b,p)){continue;}else if(svc){require(register("r0")== (p.c.publish?p.c.handle:0),"Close handle");}
                    else require(register("r0")==((pc==FILE_DISPOSE||pc==ALT_FILE)?p.file:p.object),"Dispose object");
                    for(Write effect:b.effects)writeWord(effect.at(),effect.value());
                    if(svc){if(!rebuilt)visited.add(pc);for(String r:new String[]{"r0","r1","r2","r3","r12"})register(r,0xdeadbeefL);register("cpsr",0xa0000010L);thread.overrideCounter(toAddr(pc+4));}
                    else externalReturn(value);
                    continue;
                }
                machineStep(rebuilt,++steps);
            }
            require(probe==null,"Request returned");if(recoverRequest)matches(tls);
            require(events==p.boundaries.size(),"Missing dependency");require(observed.equals(p.writes),"Final ordered writes");matches(p.s);
            require(register("r0")==p.result,"Owner result");require(reads==p.reads,"Guard reads");
            for(int i=0;i<3;i++)require(get(STACK+4*i)==ownerStack(p)[i],"Incoming arguments unchanged");require(get(STACK+12)==0x96a55a96L,"Upper stack guard");finishChecks(steps);
        }
    }
    State ownerFixture(long guard,int nested,boolean secondEmpty,int variant){
        State s=fixture(guard,nested);s.add(SECOND-16,0x60,0x87);s.add(FILES-16,0x2a0,0x88);s.add(INPUT-16,0x30,0x89);s.add(OUTPUT-16,0x24,0x8a);s.add(AVT,0x140,0x8b);
        s.set(SECOND+20,0);s.set(SECOND+24,0x20);s.set(SECOND+36,secondEmpty?0:FILES);s.set(SECOND+44,5);
        s.set(SECOND+48,1);s.set(SECOND+52,0);s.set(SECOND+56,0);
        for(int i=0;i<20;i++)s.set(FILES+32*i,i==19?0:FILES+32*(i+1));
        s.set(INPUT,variant==0?0:0x87654321L);s.set(INPUT+4,0xffffffffL);s.set(INPUT+8,new long[]{0,1,0x12345680,0xffffffffL}[variant%4]);s.set(INPUT+12,0xabcdef01L);
        s.set(STATE+16,0x12345678);s.set(OUTPUT,0xeeeeeeeeL);s.set(AVT+48,ALT_OBJECT);s.set(FVT+44,ALT_FILE);return s;
    }
    void compare(OwnerMachine a,OwnerMachine b,OwnerPlan p)throws Exception{
        try{a.owner(false,p);b.owner(true,p);results.printf("%d\t%x\t%x\t%x\t%x\t%d%n",ownerCases++,p.object,p.file,p.c.request,p.result,p.boundaries.size());}
        catch(Exception e){throw new IllegalStateException("Pool owner case "+ownerCases,e);}
    }
    void directPair(OwnerMachine a,OwnerMachine b,long[] args,Scenario c,PrintWriter log)throws Exception{
        State s=new State();s.blocks.clear();s.add(INPUT-16,0x30,0x83);s.add(OUTPUT-16,0x30,0x84);s.set(INPUT,args[1]);s.set(OUTPUT,args[0]);
        try{a.directRequest(false,s,args,c);b.directRequest(true,s,args,c);log.printf("direct-request\t%d\t%x\t%x\t%s%n",requestCases++,c.kernel,c.request,Arrays.toString(args));}
        catch(Exception e){throw new IllegalStateException("Pool owner case direct request "+requestCases,e);}
    }
    @Override public void run()throws Exception{
        Path out=Path.of(getScriptArgs()[0]);byte[] map=new byte[0x377000];require(currentProgram.getMemory().getBytes(toAddr(0x100000),map)==map.length,"Map");
        require(HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(map)).equals("834938d18d2b7c688311c46c27bed813d0d7a9f8e3cbb61da8a6a3f23d360ebd"),"Hash");
        byte[] binary=Files.readAllBytes(out.resolve("resource-worker-backend.bin"));codeSize=binary.length;var entries=Files.readAllLines(out.resolve("owner-entries.txt"));ownerEntry=Long.parseLong(entries.get(0));constructEntry=Long.parseLong(entries.get(1));
        recoverRequest=Files.exists(out.resolve("request-entry.txt"));if(recoverRequest)requestEntry=Long.parseLong(Files.readString(out.resolve("request-entry.txt")));
        OwnerMachine a=new OwnerMachine(map,binary),b=new OwnerMachine(map,binary);
        for(int fill:new int[]{0,0x55,0x96,0xff})for(long node:new long[]{0x930000,0x930004,0xf0000000L}){
            State s=new State();s.blocks.clear();s.add(node-16,0x150,fill);
            try{a.direct(false,s,node);b.direct(true,s,node);constructorCases++;}catch(Exception e){throw new IllegalStateException("Pool owner case constructor "+constructorCases,e);}
        }
        try(PrintWriter log=new PrintWriter(Files.newBufferedWriter(out.resolve("results.tsv")))){
            results=log;int variant=0;
            if(!recoverRequest)for(long status:new long[]{0,1,0x7fffffffL,0x80000000L,0xd8604659L,0xffffffffL})for(boolean publish:new boolean[]{false,true}){
                Scenario c=new Scenario(status,0);c.publish=publish;c.effects=true;State s=ownerFixture(0,0,false,variant++);a.seed(s);b.seed(s);compare(a,b,new OwnerPlan(s,c));
            }
            if(recoverRequest){
                for(long kernel:new long[]{0,1,0x7fffffffL,0x80000000L,0xffffffffL})
                for(long service:new long[]{0,1,0x7fffffffL,0x80000000L,0xd8604659L,0xffffffffL})
                for(boolean response:new boolean[]{false,true}){
                    Scenario c=new Scenario(service,0);c.kernel=kernel;c.response=response;c.effects=true;c.concrete();
                    State s=ownerFixture(0,0,false,variant++);a.seed(s);b.seed(s);compare(a,b,new OwnerPlan(s,c));
                }
                for(long size:new long[]{0,1,16,20,0x3ffff,0x40000,0x40001,0x7fffffffL,0x80000000L,MASK})
                for(boolean swapped:new boolean[]{false,true}){
                    long[] args={0x89abcdefL,0x12345678,0xfedcba98L,swapped?MASK:0,size,0x87654321L,swapped?0:MASK,(~size)&MASK,0xaabbccddL,0x11223344};
                    directPair(a,b,args,new Scenario(1,0),log);
                }
                for(long kernel:new long[]{0,1,0x7fffffffL,0x80000000L,MASK})for(long service:new long[]{0,1,0x7fffffffL,0x80000000L,MASK})for(boolean response:new boolean[]{false,true}){
                    Scenario c=new Scenario(service,0);c.kernel=kernel;c.response=response;
                    directPair(a,b,new long[]{0xfedcba98L,0x12345678,0x87654321L,0,16,2,MASK,20,1,0},c,log);
                }
            }
            for(long status:new long[]{0,1,0x7fffffffL,0x80000000L,0xffffffffL})for(boolean alternate:new boolean[]{false,true}){
                Scenario c=new Scenario(1,status);c.alternate=alternate;c.effects=true;if(recoverRequest)c.concrete();State s=ownerFixture(1,3,false,variant++);a.seed(s);b.seed(s);compare(a,b,new OwnerPlan(s,c));
            }
            for(boolean publish:new boolean[]{false,true}){
                Scenario c=new Scenario(0,0);c.publish=publish;if(recoverRequest){c.handle=publish?0xaabbccddL:0;c.concrete();}c.secondEmpty=true;c.effects=true;State s=ownerFixture(0,3,true,variant++);a.seed(s);b.seed(s);compare(a,b,new OwnerPlan(s,c));
            }
            for(long guard:new long[]{0,1,2,0x80000000L})for(int nested:new int[]{0,3}){
                State s=ownerFixture(guard,nested,false,variant++);a.seed(s);b.seed(s);
                for(int i=0;i<(guard==0?18:4);i++){Scenario c=new Scenario(i%2,i%3);if(recoverRequest)c.concrete();OwnerPlan p=new OwnerPlan(s,c);compare(a,b,p);s=p.s;}
            }
        }
        int ownerSites=0,constructorSites=0;for(long pc=0x2adcd8;pc<0x2ade84;pc+=4){require(visited.contains(pc),"Owner site "+Long.toHexString(pc));ownerSites++;}
        for(long pc=0x14636c;pc<0x146448;pc+=4){require(visited.contains(pc),"Constructor site");constructorSites++;}
        Files.writeString(out.resolve("visited.txt"),String.join("\n",visited.stream().map(v->String.format("%08x",v)).toList()));
        Files.writeString(out.resolve("comparison.json"),String.format(Locale.ROOT,"{\"owner_calls\":%d,\"direct_constructor_calls\":%d,\"persistent_sequences\":8,\"owner_instruction_sites\":%d,\"constructor_instruction_sites\":%d,\"ordered_writes_and_full_fixtures_checked\":true,\"lazy_clear_constructor_and_both_pool_takes_executed\":true,\"request_initializer_virtual_cleanup_and_close_modeled\":true,\"tls_and_successful_exclusives_modeled\":true,\"storage_and_initial_locks_synthetic\":true,\"live_verified\":false}\n",ownerCases,constructorCases,ownerSites,constructorSites));
        if(recoverRequest){
            int sites=0;for(long pc=REQUEST;pc<0x2b5e6c;pc+=4){require(visited.contains(pc),"Request instruction site");sites++;}
            String comparison=Files.readString(out.resolve("comparison.json")).replace("\"request_initializer_virtual_cleanup_and_close_modeled\":true", "\"request_initializer_virtual_cleanup_and_close_modeled\":false,\"initializer_virtual_cleanup_and_close_modeled\":true");
            comparison=comparison.trim();comparison=comparison.substring(0,comparison.length()-1)+String.format(Locale.ROOT,",\"request_model_removed\":true,\"direct_request_pairs\":%d,\"request_calls_both\":%d,\"request_instruction_sites\":%d,\"tls_command_order_buffers_and_publication_checked\":true,\"kernel_responses_modeled\":true}\n",requestCases,requestCalls,sites);
            Files.writeString(out.resolve("comparison.json"),comparison);
        }
        println("SMT4_POOL_OWNER_COMPARE_OK");
    }
}
