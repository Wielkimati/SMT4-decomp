// Startup traversal; other constructors are explicit ABI-clobber/BX-LR models.
// @category SMT4
import ghidra.pcode.emu.PcodeThread;
import ghidra.pcode.exec.*;
import ghidra.pcode.utils.Utils;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.lang.RegisterValue;
import ghidra.program.model.pcode.PcodeOp;
import java.math.BigInteger;
import java.nio.file.*;
import java.security.MessageDigest;
import java.util.*;
import java.io.*;

public class CompareStartupDispatch extends CompareResourceGlobalStartup {
    static final long REL=0x100cb8, ABS=0x102338, FIRST=0x42a188, LAST=0x42ab78;
    long[] dispatchEntries=new long[4];
    int pairs,callbacks,constructors,tableReads,thumbCallbacks;
    Set<Long> dispatchVisited=new TreeSet<>();
    class DispatchMachine extends GlobalMachine {
        List<Long> addresses,targets;int readIndex,callIndex;boolean dispatching;
        DispatchMachine(byte[] map,byte[] binary){super(map,binary);}
        int mode(){return thread.getContext().getRegisterValue(currentProgram.getRegister("TMode")).getUnsignedValue().intValue();}
        @Override public void beforeLoad(PcodeThread<byte[]> t,PcodeOp op,AddressSpace space,byte[] offset,int size) {
            if(startup){super.beforeLoad(t,op,space,offset,size);return;}
            long at=Utils.bytesToLong(offset,offset.length,false);
            if(dispatching && readIndex<addresses.size() && at==addresses.get(readIndex)) {
                require(size==4&&readIndex==callIndex,"One table read before each callback");readIndex++;tableReads++;return;
            }
            require(within(at,size,STACK-0x1000,STACK)||within(at,size,BUILD,BUILD+codeSize)||
                at==0x100cd4||at==0x100cd8||at==0x102364||at==0x102368,
                "Dispatch unexpected read "+Long.toHexString(at));
        }
        @Override public void beforeStore(PcodeThread<byte[]> t,PcodeOp op,AddressSpace space,byte[] offset,int size,byte[] value) {
            if(startup){super.beforeStore(t,op,space,offset,size,value);return;}
            long at=Utils.bytesToLong(offset,offset.length,false);
            require(within(at,size,STACK-0x1000,STACK),"Dispatcher wrote outside stack");
        }
        State construct(State s,int[] failed) throws Exception {
            long ret=register("lr")&~1L,sp=register("sp");int returnMode=(int)(register("lr")&1);
            long[] saved=new long[8];for(int i=0;i<8;i++)saved[i]=register("r"+(i+4));
            plan=new GlobalPlan(s,failed,-1);failures=failed;attempts=new int[4];cursor=0;
            xload=reserved=attempted=allowed=false;startup=true;
            if(isRebuilt)thread.overrideCounter(toAddr(globalEntry));
            int steps=0;
            do {
                long pc=thread.getCounter().getOffset();boolean thumb=within(pc,2,0x2c5fac,0x2c5fce);
                require(isRebuilt?within(pc,4,BUILD,BUILD+codeSize):within(pc,4,START,STOP)||thumb||
                    within(pc,4,0x3561f0,0x356204)||within(pc,4,INIT[0],END_INIT[0])||
                    within(pc,4,INIT[1],END_INIT[1])||within(pc,4,INIT[2],END_INIT[2])||
                    within(pc,4,0x2c6c64,0x2c6c94)||within(pc,4,0x2c61e4,0x2c62d4)||pc==0x225e68,
                    "Connected constructor PC "+Long.toHexString(pc));
                require(mode()==(thumb&&!isRebuilt?1:0),"Constructor mode");
                require(++steps<10000,"Constructor budget");thread.stepInstruction();
            }while(thread.getCounter().getOffset()!=ret);
            require(cursor==plan.events.size()&&!reserved&&!attempted&&!allowed,"Connected constructor events");
            require(register("sp")==sp&&mode()==returnMode,"Constructor return SP/mode");
            for(int i=0;i<8;i++)require(register("r"+(i+4))==saved[i],"Constructor preserved registers");
            check(plan.s,"Connected constructor guarded state");startup=false;constructors++;return plan.s;
        }
        State otherCallback(State s,long target,int index) throws Exception { callbackModel(target,index);return s; }
        void callbackModel(long target,int index) throws Exception {
            // Execute a model BX LR, including real interworking on return. No
            // original instruction at this unrelated constructor is executed.
            long pc=target&~1L;boolean thumb=(target&1)!=0;
            byte[] old=memory(pc,4);
            memory(pc,thumb?new byte[]{0x70,0x47,0,0}:new byte[]{0x1e,(byte)0xff,0x2f,(byte)0xe1});
            for(int r:new int[]{0,1,2,3,12})register("r"+r,(0xa5070031L*(index+1)+r)&MASK);
            register("cpsr",0xa0000010L|(thumb?0x20:0));
            thread.stepInstruction();memory(pc,old);
        }
        State dispatch(State initial,boolean rebuilt,int kind,long begin,long end,List<Long> slots,List<Long> calls,
                       boolean pinned,boolean mutate,int[] failed) throws Exception {
            seed(initial,rebuilt);initialize(rebuilt,0,new byte[0x144]);
            addresses=slots;targets=calls;readIndex=callIndex=0;dispatching=true;startup=false;
            if(!rebuilt) {
                if(kind==0){writeWord(0x100cd4,(begin-0x100cc0)&MASK);writeWord(0x100cd8,(end-0x100cc4)&MASK);}
                else {writeWord(0x102364,begin);writeWord(0x102368,end);}
            }
            register("r0",begin);register("r1",end);
            int initialMode=!rebuilt&&kind==0?1:0;
            thread.overrideContext(new RegisterValue(currentProgram.getRegister("TMode"),BigInteger.valueOf(initialMode)));
            register("cpsr",0x10|(initialMode<<5));
            thread.overrideCounter(toAddr(rebuilt?dispatchEntries[kind+(pinned?0:2)]:kind==0?REL:ABS));
            State expected=new State(initial);executing=true;int steps=0;
            while(thread.getCounter().getOffset()!=RETURN) {
                long pc=thread.getCounter().getOffset();
                if(callIndex<targets.size()&&readIndex==callIndex+1&&pc==(targets.get(callIndex)&~1L)) {
                    long target=targets.get(callIndex);int returnMode=(int)(register("lr")&1);long ret=register("lr")&~1L;
                    require(mode()==(int)(target&1),"Callback target mode");require((register("sp")&7)==0,"Callback stack alignment");
                    if((target&1)!=0)thumbCallbacks++;
                    if(target==START)expected=construct(expected,failed);
                    else expected=otherCallback(expected,target,callIndex);
                    require(thread.getCounter().getOffset()==ret&&mode()==returnMode,"Callback interworking return");
                    if(mutate&&callIndex==0) {
                        long at=addresses.get(1),next=targets.get(1),v=kind==0?(next-at)&MASK:next;
                        writeWord(at,v);expected.set(at,v);
                    }
                    callIndex++;callbacks++;continue;
                }
                require(rebuilt?within(pc,4,BUILD,BUILD+codeSize):kind==0?within(pc,2,REL,0x100cd2):within(pc,4,ABS,0x102364),
                    "Dispatch PC "+Long.toHexString(pc));
                require(mode()==initialMode,"Dispatcher mode");
                if(!rebuilt)dispatchVisited.add(pc);
                require(++steps<20000,"Dispatch budget");monitor.checkCancelled();thread.stepInstruction();
            }
            require(readIndex==slots.size()&&callIndex==targets.size(),"Dispatch calls/reads complete");
            require(mode()==0,"Dispatch returned to ARM caller");finish(steps);check(expected,"Dispatch full guarded state");
            for(byte v:memory(STACK-0x1000,0xd00))require(v==(byte)0x96,"Dispatch stack guard");
            executing=dispatching=false;return expected;
        }
    }
    DispatchMachine newDispatchMachine(byte[] map,byte[] binary) { return new DispatchMachine(map,binary); }
    void pair(byte[] map,byte[] binary,String name,int kind,long begin,long end,List<Long> calls,boolean pinned,boolean mutate,int[] failed,PrintWriter log) throws Exception {
        try {
            State s=poisoned(0xa5);List<Long> slots=new ArrayList<>();
            if(pinned) {
                byte[] table=Arrays.copyOfRange(map,(int)(FIRST-16-0x100000),(int)(LAST+16-0x100000));
                s.blocks.put(FIRST-16,table);
            } else {
                for(int i=0;i<calls.size();i++) {
                    long at=(begin+4L*i)&MASK;slots.add(at);s.add(at,4,0);
                    s.set(at,kind==0?(calls.get(i)-at)&MASK:calls.get(i));
                }
                // Guard bytes on both sides, including wraparound.
                s.add((begin-8)&MASK,8,0x68);s.add((begin+4L*calls.size())&MASK,8,0x79);
                if(mutate){long at=slots.get(1);s.set(at,kind==0?(0x780000-at)&MASK:0x780000);}
            }
            if(pinned)for(int i=0;i<calls.size();i++)slots.add(begin+4L*i);
            DispatchMachine a=newDispatchMachine(map,binary),b=newDispatchMachine(map,binary);
            // Synthetic model targets need initialized decoder bytes; pinned
            // callbacks use the hash-bound map, temporarily replaced by models.
            a.memory(0x780000,new byte[16]);b.memory(0x780000,new byte[16]);
            State sa=a.dispatch(s,false,kind,begin,end,slots,calls,pinned,mutate,failed);
            State sb=b.dispatch(s,true,kind,begin,end,slots,calls,pinned,mutate,failed);
            for(var e:sa.blocks.entrySet())require(Arrays.equals(e.getValue(),sb.blocks.get(e.getKey())),"Pair state");
            log.printf("%s\t%s\t%d\t%08x\t%08x\t%s%n",name,pinned?"pinned":"synthetic",kind,begin,end,calls);
            pairs++;
        }catch(Exception e){throw new IllegalStateException("Startup dispatch case "+name,e);}
    }
    @Override public void run() throws Exception {
        Path out=Path.of(getScriptArgs()[0]);loadClear(out);loadLocks(out);
        byte[] map=new byte[0x377000];require(currentProgram.getMemory().getBytes(toAddr(0x100000),map)==map.length,"Map");
        require(HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(map)).equals("834938d18d2b7c688311c46c27bed813d0d7a9f8e3cbb61da8a6a3f23d360ebd"),"Hash");
        require(word(map,0xcd4)+0x100cc0==FIRST&&word(map,0xcd8)+0x100cc4==LAST,"Relative pinned endpoints");
        require(word(map,0x2364)==LAST&&word(map,0x2368)==LAST,"Absolute pinned empty");
        byte[] binary=Files.readAllBytes(out.resolve("resource-worker-backend.bin"));codeSize=binary.length;
        var lines=Files.readAllLines(out.resolve("entries.txt"));for(int i=0;i<11;i++)entry[i]=Long.parseLong(lines.get(i));
        lines=Files.readAllLines(out.resolve("dispatch-entries.txt"));for(int i=0;i<4;i++)dispatchEntries[i]=Long.parseLong(lines.get(i));
        globalEntry=Long.parseLong(Files.readString(out.resolve("global-entry.txt")).trim());
        List<Long> targets=new ArrayList<>();StringBuilder binding=new StringBuilder("index\tentry\toffset\ttarget\n");
        for(long at=FIRST;at<LAST;at+=4) {
            long offset=word(map,(int)(at-0x100000)),target=(at+offset)&MASK;
            require(within(target,4,0x100000,0x3fe69c)&&(target&1)==0,"Pinned callback ARM/text");
            binding.append(String.format("%d\t%08x\t%08x\t%08x%n",targets.size(),at,offset,target));targets.add(target);
        }
        require(targets.size()==636&&targets.get(331)==START&&Collections.frequency(targets,START)==1,"Constructor binding");
        Files.writeString(out.resolve("table-binding.tsv"),binding);
        try(PrintWriter log=new PrintWriter(Files.newBufferedWriter(out.resolve("dispatch-results.tsv")))) {
            pair(map,binary,"pinned-relative",0,FIRST,LAST,targets,true,false,new int[]{0,0,0,0},log);
            pair(map,binary,"pinned-relative-retries",0,FIRST,LAST,targets,true,false,new int[]{1,2,3,4},log);
            pair(map,binary,"pinned-absolute-empty",1,LAST,LAST,List.of(),true,false,new int[4],log);
            for(int kind=0;kind<2;kind++) {
                pair(map,binary,"empty-"+kind,kind,0x920000,0x920000,List.of(),false,false,new int[4],log);
                pair(map,binary,"single-"+kind,kind,0x920000,0x920004,List.of(0x780005L),false,false,new int[4],log);
                pair(map,binary,"mixed-reload-"+kind,kind,0x920000,0x92000c,List.of(0x780000L,0x780005L,0x780000L),false,true,new int[4],log);
                pair(map,binary,"unsigned-high-"+kind,kind,0x80000000L,0x80000008L,List.of(0x780005L,0x780000L),false,false,new int[4],log);
            }
            pair(map,binary,"relative-cursor-wrap",0,0xfffffff8L,4,List.of(0x780000L,0x780005L,0x780000L),false,false,new int[4],log);
            pair(map,binary,"absolute-reversed",1,0x920004,0x920000,List.of(),false,false,new int[4],log);
            pair(map,binary,"absolute-unsigned-reversed",1,0x80000000L,0x7ffffffc,List.of(),false,false,new int[4],log);
            pair(map,binary,"absolute-unaligned-end",1,0x920000,0x920006,List.of(0x780000L,0x780005L),false,false,new int[4],log);
        }
        for(long pc=REL;pc<0x100cd2;pc+=2)require(dispatchVisited.contains(pc),"Relative site missing");
        for(long pc=ABS;pc<0x102364;pc+=4)require(dispatchVisited.contains(pc),"Absolute site missing");
        Files.writeString(out.resolve("dispatch-visited.txt"),String.join("\n",dispatchVisited.stream().map(v->String.format("%08x",v)).toList())+"\n");
        Files.writeString(out.resolve("comparison.json"),String.format(Locale.ROOT,
            "{\"dispatch_pairs\":%d,\"pinned_pairs\":3,\"synthetic_pairs\":%d,\"callbacks_both\":%d,\"table_reads_both\":%d,\"concrete_resource_constructors_both\":%d,\"thumb_callbacks_both\":%d,\"constructor_exclusive_attempts_both\":%d,\"original_dispatch_sites\":24,\"guarded_state_and_order_checked\":true,\"other_constructor_bodies_modeled\":true,\"synthetic_endpoints_emulator_only\":true,\"live_verified\":false}\n",
            pairs,pairs-3,callbacks,tableReads,constructors,thumbCallbacks,startupAttempts));
        println("SMT4_STARTUP_DISPATCH_COMPARE_OK");
    }
}
