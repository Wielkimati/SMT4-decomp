// Pool/lock construction, exact ordered field effects, then persistent consumers.
// @category SMT4
import ghidra.pcode.emu.PcodeThread;
import ghidra.pcode.exec.*;
import ghidra.pcode.exec.PcodeExecutorStatePiece.Reason;
import ghidra.pcode.utils.Utils;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.pcode.PcodeOp;
import java.nio.file.*;
import java.security.MessageDigest;
import java.util.*;
import java.io.*;

public class CompareResourcePoolInitialize extends CompareResourceWorkerBackend {
    static final long[] INIT={0x2a4eb4,0x2c3b54,0x138f44}, END_INIT={0x2a4f54,0x2c3b70,0x138f5c};
    long[] initEntry=new long[3];
    int initCases,pendingCases,poolCases,lockCases,initAttempts,initializedSequences;
    record Access(String kind,long at,long value) {}
    class InitPlan {
        State s; List<Access> events=new ArrayList<>(); int mutate;
        void write(long at,long value) { value&=MASK;events.add(new Access("w",at,value));s.set(at,value); }
        InitPlan(State initial,long element,long storage,long bytes,long alignment,long flags,int mutation) {
            s=new State(initial);mutate=mutation;
            long stride=(((element+alignment-1)&MASK)/alignment*alignment)&MASK;
            long start=(((storage+alignment-1)&MASK)/alignment*alignment)&MASK;
            require(alignment!=0 && stride!=0,"Nonzero quotient domain");
            long usable=(((storage+bytes-start)&MASK)/stride*stride)&MASK;
            write(POOL+0x14,flags);write(POOL+0x18,stride);write(POOL+0x1c,start);
            write(POOL+0x20,usable);write(POOL+0x2c,0);write(POOL+0x28,alignment);
            long node=(start+usable-stride)&MASK,head=0;int n=0;
            while(node>=start) {
                require(++n<=64 && within(node,4,NODE-16,NODE+0xf0),"Bounded mapped list");
                write(node,head);
                if(n==1 && mutation!=0) {
                    if(mutation==1)s.set(POOL+0x18,stride*2);
                    else s.set(POOL+0x1c,node);
                }
                events.add(new Access("r",POOL+0x18,s.get(POOL+0x18)));
                events.add(new Access("r",POOL+0x1c,s.get(POOL+0x1c)));
                head=node;node=(node-s.get(POOL+0x18))&MASK;start=s.get(POOL+0x1c);
            }
            write(POOL+0x24,head);
        }
        InitPlan(State initial,int kind,int failures,boolean pending) {
            s=new State(initial);
            for(int i=0;i<failures+(pending?0:1);i++) {
                events.add(new Access("xload",POOL+0x30,s.get(POOL+0x30)));
                events.add(new Access("attempt",POOL+0x30,1));
                if(i==failures)write(POOL+0x30,1);
            }
            if(!pending && kind==1) {write(POOL+0x34,0);write(POOL+0x38,0);}
        }
    }
    class InitMachine extends BackendMachine {
        boolean initializing;InitPlan plan;int cursor,failures,attempt,mutation;boolean xload,reserved,attempted,allowed;
        InitMachine(byte[] map,byte[] binary) {super(map,binary);}
        void observe(String kind,long at,long value) {
            require(cursor<plan.events.size(),"Extra init event "+kind+" "+Long.toHexString(at));
            Access e=plan.events.get(cursor++);
            require(e.equals(new Access(kind,at,value)),"Init expected "+e+" got "+new Access(kind,at,value));
        }
        @Override public void beforeExecuteInstruction(PcodeThread<byte[]> t,Instruction ins,PcodeProgram program) {
            if(!initializing) {super.beforeExecuteInstruction(t,ins,program);return;}
            String name=ins.getMnemonicString().toLowerCase(Locale.ROOT);xload=name.equals("ldrex");
            if(name.equals("strex")) {
                require(reserved&&!attempted,"Init exclusive reservation");
                long bits=get(ins.getAddress().getOffset());
                observe("attempt",POOL+0x30,register("r"+(bits&15)));attempted=true;
            }
        }
        @Override public boolean handleMissingUserop(PcodeThread<byte[]> t,PcodeOp op,PcodeFrame frame,String name,PcodeUseropLibrary<byte[]> library) {
            if(!initializing)return super.handleMissingUserop(t,op,frame,name,library);
            require(name.equals("hasExclusiveAccess")&&reserved&&attempted,"Init exclusive userop");
            byte[] arg=t.getState().getVar(op.getInput(1),Reason.INSPECT);
            require(Utils.bytesToLong(arg,arg.length,false)==POOL+0x30,"Init exclusive address");
            allowed=attempt++>=failures;reserved=attempted=false;initAttempts++;
            t.getState().setVar(op.getOutput(),machine.getArithmetic().fromConst(allowed?1:0,op.getOutput().getSize()));return true;
        }
        @Override public void beforeLoad(PcodeThread<byte[]> t,PcodeOp op,AddressSpace sp,byte[] offset,int size) {
            if(!initializing) {super.beforeLoad(t,op,sp,offset,size);return;}
            long at=Utils.bytesToLong(offset,offset.length,false);
            if(at==POOL+0x30) {
                require(size==4&&xload&&!reserved,"Init LDREX");observe("xload",at,get(at));reserved=true;return;
            }
            if(at>=POOL && at<POOL+0x40) {
                require(size==4 || size==8,"Init read width");
                for(int i=0;i<size;i+=4)observe("r",at+i,get(at+i));return;
            }
            require(within(at,size,STACK-0x1000,STACK)||within(at,size,BUILD,BUILD+codeSize)||within(at,size,0x100000,0x477000),"Init read extent");
        }
        @Override public void beforeStore(PcodeThread<byte[]> t,PcodeOp op,AddressSpace sp,byte[] offset,int size,byte[] value) {
            if(!initializing) {super.beforeStore(t,op,sp,offset,size,value);return;}
            long at=Utils.bytesToLong(offset,offset.length,false);
            if(within(at,size,STACK-0x1000,STACK))return;
            require(size==4,"Init write width");
            if(at==POOL+0x30){require(allowed,"Init nonexclusive store");allowed=false;}
            observe("w",at,word(value,0));
            if(within(at,4,NODE-16,NODE+0xf0)&&mutation!=0) {
                if(mutation==1)writeWord(POOL+0x18,get(POOL+0x18)*2);
                else writeWord(POOL+0x1c,at);
                mutation=0;
            }
        }
        void init(int kind,InitPlan p,long element,long storage,long bytes,long alignment,long flags,int failed,boolean pending) throws Exception {
            initialize(isRebuilt,0,new byte[0x144]);
            plan=p;cursor=attempt=0;failures=failed;mutation=p.mutate;
            xload=reserved=attempted=allowed=false;initializing=true;
            // Six-argument entry: reserve stack argument words below the inherited top.
            long initialSp=STACK-8;register("sp",initialSp);
            writeWord(initialSp,alignment);writeWord(initialSp+4,flags);
            register("r0",kind==0?POOL:POOL+0x30);register("r1",element);register("r2",storage);register("r3",bytes);
            thread.overrideCounter(toAddr(isRebuilt?initEntry[kind]:INIT[kind]));executing=true;
            int steps=0;
            while(thread.getCounter().getOffset()!=RETURN) {
                long pc=thread.getCounter().getOffset();long bits=get(pc);
                if(pending && cursor==plan.events.size() && (bits&0x0ff00fffL)==0x01900f9fL)break;
                boolean valid=isRebuilt?within(pc,4,BUILD,BUILD+codeSize):
                    within(pc,4,INIT[0],END_INIT[0])||within(pc,4,INIT[1],END_INIT[1])||within(pc,4,INIT[2],END_INIT[2])||
                    within(pc,4,0x2c6c64,0x2c6c94)||within(pc,4,0x2c61e4,0x2c62d4);
                require(valid,"Init PC "+Long.toHexString(pc));require(++steps<4096,"Init budget");
                if(!isRebuilt)visited.add(pc);monitor.checkCancelled();thread.stepInstruction();
            }
            require(cursor==plan.events.size(),"Missing init events");require(!reserved&&!attempted&&!allowed,"Init exclusive completion");
            check(plan.s,"Initialized full guarded state");
            if(!pending) {
                require(register("sp")==initialSp,"Init SP");
                for(int r=4;r<=11;r++)require(register("r"+r)==0x12340000L+r,"Init callee saved");
            } else require(thread.getCounter().getOffset()!=RETURN,"Pending initializer returned");
            for(byte v:memory(STACK-0x1000,0xe00))require(v==(byte)0x96,"Init stack guard");
            require(get(initialSp)==alignment && get(initialSp+4)==flags,"Stack arguments preserved");
            maxSteps=Math.max(maxSteps,steps);initializing=executing=false;
        }
    }
    State initializePair(InitMachine a,InitMachine b,State s,int kind,long element,long storage,long bytes,long alignment,long flags,int mutation,int failures,boolean pending,boolean seed,PrintWriter log) throws Exception {
        try {
            InitPlan p=kind==0?new InitPlan(s,element,storage,bytes,alignment,flags,mutation):new InitPlan(s,kind,failures,pending);
            if(seed){a.seed(s,false);b.seed(s,true);}
            a.init(kind,p,element,storage,bytes,alignment,flags,failures,pending);
            b.init(kind,p,element,storage,bytes,alignment,flags,failures,pending);
            log.printf("%d\t%d\t%x\t%x\t%x\t%x\t%x\t%d\t%d\t%b\t%s%n",initCases++,kind,element,storage,bytes,alignment,flags,mutation,failures,pending,p.events);
            if(kind==0)poolCases++;else lockCases++;if(pending)pendingCases++;
            return p.s;
        } catch(Exception e) {throw new IllegalStateException("Pool initialization case "+initCases+" kind="+kind,e);}
    }
    @Override public void run() throws Exception {
        Path out=Path.of(getScriptArgs()[0]);loadClear(out);loadLocks(out);
        require(recoverClear&&recoverLocks,"Recovered consumers required");
        byte[] map=new byte[0x377000];require(currentProgram.getMemory().getBytes(toAddr(0x100000),map)==map.length,"Map");
        require(HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(map)).equals("834938d18d2b7c688311c46c27bed813d0d7a9f8e3cbb61da8a6a3f23d360ebd"),"Hash");
        byte[] binary=Files.readAllBytes(out.resolve("resource-worker-backend.bin"));codeSize=binary.length;
        var entries=Files.readAllLines(out.resolve("entries.txt"));for(int i=0;i<11;i++)entry[i]=Long.parseLong(entries.get(i));
        entries=Files.readAllLines(out.resolve("init-entries.txt"));for(int i=0;i<3;i++)initEntry[i]=Long.parseLong(entries.get(i));
        InitMachine a=new InitMachine(map,binary),b=new InitMachine(map,binary);
        try(PrintWriter log=new PrintWriter(Files.newBufferedWriter(out.resolve("results.tsv")));PrintWriter life=new PrintWriter(Files.newBufferedWriter(out.resolve("lifetimes.tsv")))) {
            log.println("case\tkind\telement\tstorage\tbytes\talignment\tflags\tmutation\tfailures\tpending\tordered_events");
            // Non-power-of-two alignment, short storage, exact/trailing capacity and starting offsets.
            for(long alignment:new long[]{4,8,12,16,20})for(long element:new long[]{1,4,15,16,17,31})for(int offset:new int[]{0,1,3})for(int capacity:new int[]{0,1,3}) {
                long storage=NODE+offset,start=(storage+alignment-1)/alignment*alignment;
                long stride=(element+alignment-1)/alignment*alignment;
                long bytes=start-storage+stride*capacity+(capacity==3?stride-1:0);
                initializePair(a,b,new State(),0,element,storage,bytes,alignment,capacity==1?MASK:capacity,0,0,false,true,log);
            }
            for(int mutation:new int[]{1,2})initializePair(a,b,new State(),0,16,NODE,64,4,1,mutation,0,false,true,log);
            // Wrapped storage end / usable-byte subtraction produce no nodes, not a rejected request.
            for(long bytes:new long[]{0,1,2,0xfffffff0L,0xffffffffL})
                initializePair(a,b,new State(),0,16,NODE+1,bytes,4,0x80000000L,0,0,false,true,log);
            for(int kind:new int[]{1,2})for(long base:new long[]{0,1,0x80000000L,MASK})for(int failed:new int[]{0,1,4}) {
                State s=new State();s.set(POOL+0x30,base);s.set(POOL+0x34,MASK);s.set(POOL+0x38,0x80000000L);
                initializePair(a,b,s,kind,0,0,0,0,0,0,failed,false,true,log);
            }
            for(int kind:new int[]{1,2})for(int failed:new int[]{1,5}) {
                State s=new State();s.set(POOL+0x30,MASK);s.set(POOL+0x34,0x13579bdf);s.set(POOL+0x38,7);
                initializePair(a,b,s,kind,0,0,0,0,0,0,failed,true,true,log);
            }
            for(int flags:new int[]{0,1})for(int capacity:new int[]{0,1,2}) {
                State s=new State();s.set(POOL+0x30,0xdeadbeefL);s.set(POOL+0x34,0xaabbccddL);s.set(POOL+0x38,0xffffffffL);
                // Poison previous topology: all usable links and fields must come from execution.
                for(int offset=0x14;offset<=0x2c;offset+=4)s.set(POOL+offset,0xccccccccL);
                Arrays.fill(s.blocks.get(NODE-16),16,48,(byte)0xcd);
                s=initializePair(a,b,s,0,16,NODE,16*capacity,4,flags,0,0,false,true,log);
                s=initializePair(a,b,s,1,0,0,0,0,0,0,2,false,false,log);
                Config c=new Config();
                for(int round=0;round<3;round++) {
                    s=compare(a,b,s,c,5,false,life); // create/register or exhaustion
                    s=compare(a,b,s,c,capacity==2?5:0,false,life); // duplicate owner or exhausted take
                    s=compare(a,b,s,c,7,false,life); // remove/return if created
                    require(s.get(POOL+0x24)==(capacity==0?0:NODE)&&s.get(POOL+0x2c)==0,"Initialized lifetime reuse");
                    require(s.get(POOL+0x30)==1&&s.get(POOL+0x34)==0&&s.get(POOL+0x38)==0,"Initialized lock lifetime");
                }
                initializedSequences++;
            }
        }
        int sites=0;StringBuilder listing=new StringBuilder();
        for(int i=0;i<3;i++) {
            var f=getFunctionAt(toAddr(INIT[i]));require(f!=null&&f.getBody().getMinAddress().getOffset()==INIT[i]&&f.getBody().getMaxAddress().getOffset()==END_INIT[i]-1,"Saved init extent");
            listing.append(f.getBody()).append('\n');
            for(long pc=INIT[i];pc<END_INIT[i];pc+=4){require(visited.contains(pc),"Unvisited init site");sites++;listing.append(String.format("%08x %s%n",pc,getInstructionAt(toAddr(pc))));}
        }
        Files.writeString(out.resolve("original-ghidra.txt"),listing);
        Files.writeString(out.resolve("visited.txt"),String.join("\n",visited.stream().map(v->String.format("%08x",v)).toList())+"\n");
        Files.writeString(out.resolve("comparison.json"),String.format(Locale.ROOT,
            "{\"initialization_cases\":%d,\"pool_cases\":%d,\"lock_cases\":%d,\"pending_prefixes\":%d,\"new_instruction_sites\":%d,\"exclusive_init_attempts_both\":%d,\"initialized_lifetime_sequences\":%d,\"consumer_calls\":%d,\"consumer_lock_calls_both\":%d,\"consumer_clear_calls_both\":%d,\"max_steps\":%d,\"quotient_executed\":true,\"initial_topology_and_lock_results_executed\":true,\"tls_exclusive_outcomes_services_diagnostics_modeled\":true,\"backing_storage_synthetic\":true,\"live_verified\":false}\n",
            initCases,poolCases,lockCases,pendingCases,sites,initAttempts,initializedSequences,cases,executedLocks,executedClears,maxSteps));
        println("SMT4_POOL_INIT_COMPARE_OK");
    }
}
