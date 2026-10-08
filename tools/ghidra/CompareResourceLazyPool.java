// Persistent lazy allocation; no initializer/pool/lock call interception.
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

public class CompareResourceLazyPool extends CompareResourceWorkerBackend {
    static final long P=0x4d42e0,O=0x4d43d0,B=0x430940,G=STATE+12;
    long lazyEntry; int lazyCases,guardCalls;
    record Write(long at,long value) {}
    class Plan {
        State s; List<Write> writes=new ArrayList<>();long result;int reads;
        void w(long at,long value){value&=MASK;writes.add(new Write(at,value));s.set(at,value);}
        void acquire(long at){if(s.get(at+4)!=LOCK_TLS){w(at,MASK);w(at+4,LOCK_TLS);}w(at+8,s.get(at+8)+1);}
        void release(long at){long n=(s.get(at+8)-1)&MASK;w(at+8,n);if(n==0){w(at+4,0);w(at,1);}}
        Plan(State initial){
            s=new State(initial);acquire(O);long guard=s.get(G);reads=(guard&1)!=0?1:2;
            if(guard==0){
                w(G,1);
                for(int off:new int[]{4,8,12,16,20,36,48})w(P+off,0);
                w(P,0x420b9c);w(P+56,MASK);w(P+52,0);
                w(P+20,0);w(P+24,0x130);w(P+28,B);w(P+32,0x1300);w(P+44,0);w(P+40,4);
                long head=0;for(int i=15;i>=0;i--){long node=B+0x130*i;w(node,head);head=node;}w(P+36,head);
                w(P+48,1);w(P+52,0);w(P+56,0);
            }
            w(STATE+4,P);acquire(P+48);result=s.get(P+36);
            if(result!=0){w(P+36,s.get(result));w(P+44,s.get(P+44)+1);}
            release(P+48);release(O);
        }
    }
    class LazyMachine extends SyncMachine {
        State layout;List<Write> observed=new ArrayList<>();int reads;boolean reserved,pending,allowed,xload;long exclusive;
        LazyMachine(byte[] map,byte[] binary){super(map,binary);}
        long get(long at){return word(memory(at,4),0);}
        @Override public void beforeExecuteInstruction(PcodeThread<byte[]> t,Instruction ins,PcodeProgram program){
            String n=ins.getMnemonicString().toLowerCase(Locale.ROOT);xload=n.equals("ldrex");
            if(n.equals("strex")){require(reserved&&!pending,"Exclusive reservation");pending=true;}
        }
        @Override public boolean handleMissingUserop(PcodeThread<byte[]> t,PcodeOp op,PcodeFrame f,String name,PcodeUseropLibrary<byte[]> lib){
            require(name.equals("hasExclusiveAccess")&&reserved&&pending,"Exclusive userop");
            byte[] arg=t.getState().getVar(op.getInput(1),Reason.INSPECT);
            require(Utils.bytesToLong(arg,arg.length,false)==exclusive,"Exclusive address");
            reserved=pending=false;allowed=true;
            t.getState().setVar(op.getOutput(),machine.getArithmetic().fromConst(1,op.getOutput().getSize()));return true;
        }
        @Override public void beforeLoad(PcodeThread<byte[]> t,PcodeOp op,AddressSpace sp,byte[] offset,int size){
            long at=Utils.bytesToLong(offset,offset.length,false);
            if(at==G){require(size==4,"Guard width");reads++;}
            if(xload){require(size==4&&(at==O||at==P+48)&&!reserved,"Exclusive load");exclusive=at;reserved=true;}
            boolean ok=within(at,size,0x100000,0x477000)||within(at,size,BUILD,BUILD+codeSize)||within(at,size,STACK-0x1000,STACK);
            for(var e:layout.blocks.entrySet())ok|=within(at,size,e.getKey(),e.getKey()+e.getValue().length);
            require(ok,"Read extent");
        }
        @Override public void beforeStore(PcodeThread<byte[]> t,PcodeOp op,AddressSpace sp,byte[] offset,int size,byte[] value){
            long at=Utils.bytesToLong(offset,offset.length,false);
            if(within(at,size,STACK-0x1000,STACK))return;
            require(size==4,"Store width");
            if(at==O||at==P+48){
                // Constructor's ordinary zero store precedes exclusive initialization.
                if(at==P+48&&word(value,0)==0&&!allowed){}
                else {require(allowed&&at==exclusive,"Exclusive store");allowed=false;}
            }
            observed.add(new Write(at,word(value,0)));
        }
        void seed(State s){executing=false;layout=s;for(var e:s.blocks.entrySet())memory(e.getKey(),e.getValue());}
        void call(boolean rebuiltPath,Plan p)throws Exception{
            initialize(rebuiltPath,0,new byte[0x144]);observed.clear();reads=0;reserved=pending=allowed=xload=false;
            thread.overrideCounter(toAddr(rebuiltPath?lazyEntry:0x146284));executing=true;int steps=0;
            while(thread.getCounter().getOffset()!=RETURN){
                long pc=thread.getCounter().getOffset();
                boolean ok=rebuiltPath?within(pc,4,BUILD,BUILD+codeSize):
                    within(pc,4,0x146284,0x146350)||within(pc,2,0x2c0128,0x2c013a)||
                    within(pc,4,0x2a4eb4,0x2a4f54)||within(pc,4,0x2c3b54,0x2c3b70)||within(pc,4,0x138f44,0x138f5c)||
                    within(pc,4,0x2c6c64,0x2c6c94)||within(pc,4,0x2c61e4,0x2c62d4)||
                    within(pc,4,0x2c3afc,0x2c3b34)||within(pc,4,0x2c3a78,0x2c3a98)||
                    within(pc,4,0x1464f8,0x1465d4)||within(pc,4,0x138fc0,0x139010)||within(pc,4,0x2b5d6c,0x2b5dd0);
                require(ok,"Lazy PC "+Long.toHexString(pc));require(++steps<4096,"Budget");
                if(!rebuiltPath)visited.add(pc);
                long bits=get(pc);
                if((bits&0xffff0fffL)==0xee1d0f70L){register("r"+((bits>>>12)&15),LOCK_TLS);thread.overrideCounter(toAddr(pc+4));continue;}
                monitor.checkCancelled();thread.stepInstruction();
            }
            require(observed.equals(p.writes),"Ordered writes expected "+p.writes+" got "+observed);
            require(reads==p.reads,"Guard predicates/read count");require(register("r0")==p.result,"Result");
            for(var e:p.s.blocks.entrySet())require(Arrays.equals(e.getValue(),memory(e.getKey(),e.getValue().length)),"Full fixture "+Long.toHexString(e.getKey()));
            require(!reserved&&!pending&&!allowed,"Exclusive completion");finish(steps);
            for(byte v:memory(STACK-0x1000,0xd00))require(v==(byte)0x96,"Stack guard");executing=false;
        }
    }
    State fixture(long guard,int nested){
        State s=new State();s.blocks.clear();s.add(P-16,0x60,0x81);s.add(O-16,0x30,0x82);s.add(STATE-16,0x40,0x83);s.add(B-16,0x1320,0x84);
        s.set(G,guard);s.set(O,nested==0?1:MASK);s.set(O+4,nested==0?0:LOCK_TLS);s.set(O+8,nested);
        if(guard!=0){s.set(P+20,0);s.set(P+24,0x130);s.set(P+36,B);s.set(P+44,7);s.set(P+48,1);s.set(P+52,0);s.set(P+56,0);s.set(B,B+0x130);s.set(B+0x130,0);}
        return s;
    }
    @Override public void run()throws Exception{
        Path out=Path.of(getScriptArgs()[0]);byte[] map=new byte[0x377000];require(currentProgram.getMemory().getBytes(toAddr(0x100000),map)==map.length,"Map");
        require(HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(map)).equals("834938d18d2b7c688311c46c27bed813d0d7a9f8e3cbb61da8a6a3f23d360ebd"),"Hash");
        byte[] binary=Files.readAllBytes(out.resolve("resource-worker-backend.bin"));codeSize=binary.length;lazyEntry=Long.parseLong(Files.readString(out.resolve("lazy-entry.txt")));
        LazyMachine a=new LazyMachine(map,binary),b=new LazyMachine(map,binary);
        try(PrintWriter log=new PrintWriter(Files.newBufferedWriter(out.resolve("results.tsv")))){
            for(long guard:new long[]{0,1,2,0x80000000L,0xfffffffeL,0xffffffffL})for(int nested:new int[]{0,3}){
                State s=fixture(guard,nested);a.seed(s);b.seed(s);
                for(int i=0;i<(guard==0?18:4);i++){
                    try{Plan p=new Plan(s);a.call(false,p);b.call(true,p);s=p.s;log.printf("%d\t%x\t%d\t%d\t%x\t%s%n",lazyCases++,guard,nested,i,p.result,p.writes);}
                    catch(Exception e){throw new IllegalStateException("Lazy pool case "+lazyCases,e);}
                }
            }
        }
        int sites=0;for(long pc=0x146284;pc<0x146350;pc+=4){require(visited.contains(pc),"Caller site");sites++;}
        for(long pc=0x2c0128;pc<0x2c013a;pc+=2){require(visited.contains(pc),"Guard site");sites++;}
        Files.writeString(out.resolve("visited.txt"),String.join("\n",visited.stream().map(v->String.format("%08x",v)).toList()));
        Files.writeString(out.resolve("comparison.json"),"{\"persistent_sequences\":12,\"calls\":"+lazyCases+",\"new_instruction_sites\":"+sites+",\"ordered_writes_and_guard_reads_checked\":true,\"initializers_quotient_locks_take_executed\":true,\"tls_and_successful_exclusives_modeled\":true,\"outer_lock_and_storage_synthetic\":true,\"live_verified\":false}\n");
        println("SMT4_LAZY_POOL_COMPARE_OK");
    }
}
