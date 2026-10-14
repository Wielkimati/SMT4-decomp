// Complete resource constructor with exact ordered effects and persistent globals.
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

public class CompareResourceGlobalStartup extends CompareResourcePoolInitialize {
    static final long START=0x3f3568, STOP=0x3f36f0, GLOBAL_LOCK=0x4d43d0, BACKING=0x4306c0;
    static final long[] POOLS={0x4d431c,0x4d4358,0x4d4394}, STORAGE={0x4306c0,0x4307c0,0x4308c0};
    long globalEntry;int startupPairs,pendingPairs,startupAttempts,lifetimes;Set<Long> startupVisited=new TreeSet<>();
    State poisoned(int fill) {
        State s=new State();s.blocks.remove(POOL-16);
        s.add(POOL-16,0xc4,fill);s.add(TABLE-16,544,fill^0x39);
        s.add(BACKING-16,0x2a0,fill^0x51);
        // Unrelated backend singleton remains a fixture, not an effect of this constructor.
        s.set(STATE+8,0);s.set(STATE+16,0xdeadbeefL);
        return s;
    }
    class GlobalPlan {
        State s;List<Access> events=new ArrayList<>();
        void write(long at,long value){events.add(new Access("w",at,value));s.set(at,value);}
        boolean lock(long at,int failures,boolean pending) {
            for(int i=0;i<failures+(pending?0:1);i++) {
                events.add(new Access("xload",at,s.get(at)));events.add(new Access("attempt",at,1));
                if(i==failures)write(at,1);
            }
            if(pending)return false;
            write(at+4,0);write(at+8,0);return true;
        }
        GlobalPlan(State initial,int[] failures,int pending) {
            s=new State(initial);
            for(int i=0;i<32;i++)for(int j=0;j<12;j+=4)write(TABLE+16*i+j,0);
            write(STATE+16,0);write(GLOBAL_LOCK,0);
            if(!lock(GLOBAL_LOCK,failures[0],pending==0))return;
            for(int i=0;i<3;i++) {
                long pool=POOLS[i],storage=STORAGE[i],stride=i==0?16:8,bytes=i==2?128:256;
                for(int offset:new int[]{4,8,12,16,20,36,48,52})write(pool+offset,0);
                write(pool+56,MASK);write(pool,0x420b9c);
                write(pool+0x14,0);write(pool+0x18,stride);write(pool+0x1c,storage);
                write(pool+0x20,bytes);write(pool+0x2c,0);write(pool+0x28,4);
                long head=0;
                for(long node=storage+bytes-stride;node>=storage;node-=stride) {
                    write(node,head);events.add(new Access("r",pool+0x18,stride));events.add(new Access("r",pool+0x1c,storage));head=node;
                }
                write(pool+0x24,head);
                if(!lock(pool+0x30,failures[i+1],pending==i+1))return;
            }
        }
    }
    class GlobalMachine extends BackendMachine {
        boolean startup,xload,reserved,attempted,allowed;long exclusiveAt;int cursor;GlobalPlan plan;
        int[] failures,attempts;int pending;
        GlobalMachine(byte[] map,byte[] binary){super(map,binary);}
        void observe(String kind,long at,long value) {
            Access actual=new Access(kind,at,value);
            require(cursor<plan.events.size(),"Extra global event "+actual);
            Access expected=plan.events.get(cursor++);
            require(expected.equals(actual),"Global event "+(cursor-1)+" expected "+expected+" got "+actual);
        }
        int lockIndex(long at) {
            if(at==GLOBAL_LOCK)return 0;
            for(int i=0;i<3;i++)if(at==POOLS[i]+0x30)return i+1;
            throw new IllegalStateException("Global lock address "+Long.toHexString(at));
        }
        @Override public void beforeExecuteInstruction(PcodeThread<byte[]> t,Instruction ins,PcodeProgram program) {
            if(!startup){super.beforeExecuteInstruction(t,ins,program);return;}
            String name=ins.getMnemonicString().toLowerCase(Locale.ROOT);xload=name.equals("ldrex");
            if(name.equals("strex")) {
                require(reserved&&!attempted,"Startup reservation");
                observe("attempt",exclusiveAt,register("r"+(get(ins.getAddress().getOffset())&15)));attempted=true;
            }
        }
        @Override public boolean handleMissingUserop(PcodeThread<byte[]> t,PcodeOp op,PcodeFrame frame,String name,PcodeUseropLibrary<byte[]> library) {
            if(!startup)return super.handleMissingUserop(t,op,frame,name,library);
            require(name.equals("hasExclusiveAccess")&&reserved&&attempted,"Startup exclusive userop");
            byte[] arg=t.getState().getVar(op.getInput(1),Reason.INSPECT);
            require(Utils.bytesToLong(arg,arg.length,false)==exclusiveAt,"Startup exclusive address");
            int index=lockIndex(exclusiveAt);allowed=attempts[index]++>=failures[index];startupAttempts++;
            reserved=attempted=false;
            t.getState().setVar(op.getOutput(),machine.getArithmetic().fromConst(allowed?1:0,op.getOutput().getSize()));return true;
        }
        @Override public void beforeLoad(PcodeThread<byte[]> t,PcodeOp op,AddressSpace sp,byte[] offset,int size) {
            long at=Utils.bytesToLong(offset,offset.length,false);
            if(!startup){super.beforeLoad(t,op,sp,offset,size);return;}
            if(xload) {require(size==4&&!reserved,"Startup LDREX");lockIndex(at);exclusiveAt=at;observe("xload",at,get(at));reserved=true;return;}
            if(within(at,size,POOL,POOL+0xb4)) {
                require(size==4||size==8,"Startup read width");
                for(int i=0;i<size;i+=4)observe("r",at+i,get(at+i));return;
            }
            require(within(at,size,STACK-0x1000,STACK)||within(at,size,BUILD,BUILD+codeSize)||within(at,size,0x100000,0x477000),"Startup read extent");
        }
        @Override public void beforeStore(PcodeThread<byte[]> t,PcodeOp op,AddressSpace sp,byte[] offset,int size,byte[] value) {
            long at=Utils.bytesToLong(offset,offset.length,false);
            if(!startup) {
                if(within(at,size,BACKING,BACKING+256))return;
                super.beforeStore(t,op,sp,offset,size,value);return;
            }
            if(within(at,size,STACK-0x1000,STACK))return;
            require(size==4,"Startup write width");
            if(allowed){require(at==exclusiveAt,"Exclusive destination");allowed=false;}
            observe("w",at,word(value,0));
        }
        void start(GlobalPlan p,int[] failed,int pendingLock) throws Exception {
            initialize(isRebuilt,0,new byte[0x144]);plan=p;failures=failed;attempts=new int[4];pending=pendingLock;
            cursor=0;xload=reserved=attempted=allowed=false;startup=executing=true;
            thread.overrideCounter(toAddr(isRebuilt?globalEntry:START));int steps=0;
            while(thread.getCounter().getOffset()!=RETURN) {
                long pc=thread.getCounter().getOffset(),bits=get(pc);
                if(pending>=0&&cursor==plan.events.size()&&(bits&0x0ff00fffL)==0x01900f9fL)break;
                boolean thumb=within(pc,2,0x2c5fac,0x2c5fce);
                boolean valid=isRebuilt?within(pc,4,BUILD,BUILD+codeSize):within(pc,4,START,STOP)||thumb||
                    within(pc,4,0x3561f0,0x356204)||within(pc,4,INIT[0],END_INIT[0])||
                    within(pc,4,INIT[1],END_INIT[1])||within(pc,4,INIT[2],END_INIT[2])||
                    within(pc,4,0x2c6c64,0x2c6c94)||within(pc,4,0x2c61e4,0x2c62d4)||pc==0x225e68;
                require(valid,"Startup PC "+Long.toHexString(pc));require(++steps<10000,"Startup budget");
                require(thread.getContext().getRegisterValue(currentProgram.getRegister("TMode")).getUnsignedValue().intValue()==(thumb&&!isRebuilt?1:0),"Startup decoding mode");
                if(!isRebuilt)startupVisited.add(pc);monitor.checkCancelled();thread.stepInstruction();
            }
            require(cursor==plan.events.size()&&!reserved&&!attempted&&!allowed,"Startup event completion");check(plan.s,"Full startup guarded bytes");
            if(pending<0){require(register("r0")==POOLS[2],"Startup returned last pool");finish(steps);}
            else require(thread.getCounter().getOffset()!=RETURN,"Pending startup returned");
            for(byte v:memory(STACK-0x1000,0xd00))require(v==(byte)0x96,"Startup stack guard");
            startup=executing=false;
        }
    }
    State startPair(GlobalMachine a,GlobalMachine b,State initial,int[] failures,int pending,boolean seed,PrintWriter log) throws Exception {
        try {
            GlobalPlan p=new GlobalPlan(initial,failures,pending);
            if(seed){a.seed(initial,false);b.seed(initial,true);}
            a.start(p,failures,pending);b.start(p,failures,pending);
            log.printf("%d\t%s\t%d\t%s%n",startupPairs++,Arrays.toString(failures),pending,p.events);
            if(pending>=0)pendingPairs++;return p.s;
        }catch(Exception e){throw new IllegalStateException("Global startup case "+startupPairs,e);}
    }
    @Override public void run() throws Exception {
        Path out=Path.of(getScriptArgs()[0]);loadClear(out);loadLocks(out);require(recoverClear&&recoverLocks,"Recovered dependencies");
        byte[] map=new byte[0x377000];require(currentProgram.getMemory().getBytes(toAddr(0x100000),map)==map.length,"Map");
        require(HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(map)).equals("834938d18d2b7c688311c46c27bed813d0d7a9f8e3cbb61da8a6a3f23d360ebd"),"Hash");
        require(word(map,0x225e68-0x100000)==0xe12fff1eL,"Tail BX LR");
        byte[] binary=Files.readAllBytes(out.resolve("resource-worker-backend.bin"));codeSize=binary.length;
        var lines=Files.readAllLines(out.resolve("entries.txt"));for(int i=0;i<11;i++)entry[i]=Long.parseLong(lines.get(i));
        globalEntry=Long.parseLong(Files.readString(out.resolve("global-entry.txt")).trim());
        StringBuilder membership=new StringBuilder();
        for(long pc=START;pc<STOP;pc+=4) {
            require(currentProgram.getProgramContext().getValue(currentProgram.getRegister("TMode"),toAddr(pc),false).intValue()==0,"Saved startup ARM");
            membership.append(String.format("%08x %08x saved_instruction=%s function=%s%n",pc,word(map,(int)(pc-0x100000)),getInstructionAt(toAddr(pc)),getFunctionContaining(toAddr(pc))));
        }
        Files.writeString(out.resolve("original-startup-membership.txt"),membership);
        GlobalMachine a=new GlobalMachine(map,binary),b=new GlobalMachine(map,binary);
        try(PrintWriter log=new PrintWriter(Files.newBufferedWriter(out.resolve("global-startup-results.tsv")));PrintWriter life=new PrintWriter(Files.newBufferedWriter(out.resolve("global-lifetimes.tsv")))) {
            for(int fill:new int[]{0,0xff,0xa5})for(int[] schedule:new int[][]{{0,0,0,0},{1,2,3,4},{4,0,1,2}})
                startPair(a,b,poisoned(fill),schedule,-1,true,log);
            for(int pending=0;pending<4;pending++)for(int n:new int[]{1,5}) {
                int[] failures={1,1,1,1};failures[pending]=n;
                startPair(a,b,poisoned(0xc3),failures,pending,true,log);
            }
            for(int fill:new int[]{0x31,0xee}) {
                State s=startPair(a,b,poisoned(fill),new int[]{2,1,0,3},-1,true,log);
                // Repeat only while unused: payloads/tails and unrelated fields stay intact.
                s=startPair(a,b,s,new int[]{0,0,0,0},-1,false,log);
                Config c=new Config();c.effect=1; // Explicit archive-open service publication model.
                s=compare(a,b,s,c,8,false,life); // absent prefix
                c.status=0x80000001L;s=compare(a,b,s,c,5,false,life);c.status=0;
                for(int round=0;round<3;round++) {
                    s=compare(a,b,s,c,5,false,life);s=compare(a,b,s,c,5,false,life);
                    c.status=1;s=compare(a,b,s,c,8,false,life);c.status=0;
                    s=compare(a,b,s,c,7,false,life);s=compare(a,b,s,c,8,false,life);
                    require(s.get(POOL+0x24)==BACKING&&s.get(POOL+0x2c)==0&&s.get(STATE+8)==0,"Global reuse");
                }
                for(int n=0;n<17;n++)s=compare(a,b,s,c,0,false,life);
                require(s.get(POOL+0x24)==0&&s.get(POOL+0x2c)==16,"Actual global capacity exhausted");
                s=compare(a,b,s,c,1,false,life);lifetimes++;
            }
        }
        for(long pc=START;pc<STOP;pc+=4)require(startupVisited.contains(pc),"Startup unvisited "+Long.toHexString(pc));
        require(startupVisited.contains(0x225e68L),"Tail unvisited");
        Files.writeString(out.resolve("startup-visited.txt"),String.join("\n",startupVisited.stream().map(v->String.format("%08x",v)).toList())+"\n");
        Files.writeString(out.resolve("comparison.json"),String.format(Locale.ROOT,
            "{\"startup_pairs\":%d,\"pending_pairs\":%d,\"startup_instruction_sites\":98,\"previously_recovered_slice_sites\":5,\"tail_stub_sites\":1,\"exclusive_attempts_both\":%d,\"persistent_global_sequences\":%d,\"consumer_pairs\":%d,\"consumer_lock_calls_both\":%d,\"guarded_ordered_effects_checked\":true,\"registry_pool_lock_initialization_executed\":true,\"actual_global_backing_used\":true,\"services_tls_exclusive_outcomes_modeled\":true,\"live_verified\":false}\n",
            startupPairs,pendingPairs,startupAttempts,lifetimes,cases,executedLocks));
        println("SMT4_GLOBAL_STARTUP_COMPARE_OK");
    }
}
