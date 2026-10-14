// Wrapper instructions plus real base-lock instructions; scheduled TLS/exclusives/arbitration.
// @category SMT4
import ghidra.program.model.lang.RegisterValue;
import ghidra.pcode.emu.PcodeThread;
import ghidra.pcode.exec.*;
import ghidra.pcode.utils.Utils;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.pcode.PcodeOp;
import java.math.BigInteger;
import java.nio.file.*;
import java.security.MessageDigest;
import java.util.*;
import java.io.*;

public class CompareResourceRecursiveLock extends CompareResourceLock {
    static final long RA=0x2c3afc, RE=0x2c3a78;
    int cases, pending, tlsReads, baseCalls, sequences;
    record WEvent(String kind,long value) {}
    class RecursiveMachine extends LockMachine {
        List<WEvent> events;
        int wi; long tls; boolean inBase;
        RecursiveMachine(byte[] map,byte[] binary) { super(map,binary); }
        void event(String kind,long value) {
            require(wi<events.size(),"Extra wrapper event "+kind);
            WEvent e=events.get(wi++);
            require(e.kind().equals(kind) && e.value()==value,"Wrapper event expected "+e+" got "+kind+":"+Long.toHexString(value));
        }
        @Override public void beforeLoad(PcodeThread<byte[]> t,PcodeOp op,AddressSpace sp,byte[] offset,int size) {
            long a=Utils.bytesToLong(offset,offset.length,false);
            if(a==DATA+4 || a==DATA+8) {
                require(size==4,"Wrapper load width"); event(a==DATA+4?"owner-read":"count-read",word(memory(a,4),0)); return;
            }
            super.beforeLoad(t,op,sp,offset,size);
        }
        @Override public void beforeStore(PcodeThread<byte[]> t,PcodeOp op,AddressSpace sp,byte[] offset,int size,byte[] value) {
            long a=Utils.bytesToLong(offset,offset.length,false);
            if(a==DATA+4 || a==DATA+8) {
                require(size==4,"Wrapper store width"); long v=word(value,0);
                event(a==DATA+4?"owner-write":"count-write",v);put(expected,(int)(a-DATA+32),v);return;
            }
            super.beforeStore(t,op,sp,offset,size,value);
        }
        void invoke(boolean path,boolean release,long initial,long owner,long count,long firstTls,long nextTls,
                long[] reads,boolean[] failures,int limit,boolean mutation,boolean persistent) throws Exception {
            executing=false;
            long incomingR2=persistent?register("r2"):(count^firstTls^0x12340002L)&MASK;
            plan=new Plan(release,initial,reads,failures,limit,0x87654321L,0x13579bdfL,false);
            boolean usesBase=release ? count==1 : owner!=firstTls;
            long afterCount=mutation && usesBase && plan.calls>0 && !release ? 0xfffffffeL : count;
            events=new ArrayList<>();wi=0;
            if(!release) {
                events.add(new WEvent("tls",firstTls));events.add(new WEvent("owner-read",owner));
                if(usesBase) {
                    events.add(new WEvent("base",0));
                    if(!plan.pending) {events.add(new WEvent("base-return",0));events.add(new WEvent("tls",nextTls));events.add(new WEvent("owner-write",nextTls));}
                }
                if(!usesBase || !plan.pending) {events.add(new WEvent("count-read",afterCount));events.add(new WEvent("count-write",(afterCount+1)&MASK));}
            } else {
                events.add(new WEvent("count-read",count));events.add(new WEvent("count-write",(count-1)&MASK));
                if(usesBase) {events.add(new WEvent("owner-write",0));events.add(new WEvent("base",1));if(!plan.pending)events.add(new WEvent("base-return",1));}
            }
            if(!persistent) {
                expected=new byte[96];new Random(0x2c3afc).nextBytes(expected);
                put(expected,32,initial);put(expected,36,owner);put(expected,40,count);memory(DATA-32,expected);
            } else {
                expected=memory(DATA-32,96);
                require(word(expected,32)==initial && word(expected,36)==owner && word(expected,40)==count,"Persistent input");
            }
            cursor=loads=calls=0;handle=0x13579bdfL;writeWord(HANDLE,handle);
            reservation=exclusiveLoad=success=storePending=inBase=false;tls=firstTls;
            byte[] stack=new byte[0x1000];Arrays.fill(stack,(byte)0x96);memory(STACK-0x1000,stack);
            for(var r:currentProgram.getLanguage().getRegisters())if(r.isBaseRegister()&&!r.isProcessorContext())register(r,0);
            for(int r=0;r<=12;r++)register("r"+r,0x12340000L+r);
            register("cpsr",0x10);register("sp",STACK);register("lr",RETURN);register("r0",DATA);
            register("r2",incomingR2);
            thread.overrideContext(new RegisterValue(currentProgram.getProgramContext().getBaseContextRegister(),BigInteger.ZERO));
            thread.overrideCounter(toAddr(path?rebuilt[release?1:0]:release?RE:RA));executing=true;
            int steps=0;long baseReturn=-1;
            while(true) {
                long pc=thread.getCounter().getOffset();
                if(inBase && pc==baseReturn) {
                    require(cursor==plan.events.size(),"Base schedule not consumed");event("base-return",release?1:0);
                    require(register("r2")==plan.returnedR2,"Base return r2 before wrapper continuation");
                    inBase=false;tls=nextTls;
                }
                if(pc==RETURN)break;
                if(!inBase && pc==(path?rebuilt[release?3:2]:release?RELEASE:ACQUIRE)) {
                    event("base",release?1:0);require(register("r0")==DATA && (register("sp")&7)==0,"Base arguments/alignment");
                    require(Arrays.equals(memory(DATA-32,96),expected),"State before base");
                    baseReturn=register("lr");inBase=true;baseCalls++;
                }
                if(pc==ARBITRATE) {
                    Event e=take("arbitrate");
                    require(inBase && !reservation && (register("sp")&7)==0,"Arbitration state");
                    require(register("r0")==handle && register("r1")==DATA && register("r2")==e.value() && register("r3")== (e.value()==1?0:1),"Arbitration args");
                    require(Arrays.equals(memory(register("sp"),8),new byte[8]),"Timeout");
                    require(Arrays.equals(memory(DATA-32,96),expected),"Arbitration state/guards");
                    if(release)require(word(expected,36)==0 && word(expected,40)==0,"Release publication before arbitration");
                    if(mutation) {put(expected,36,0xaaaa5555L);if(!release)put(expected,40,afterCount);memory(DATA-32,expected);}
                    calls++;boundaryCalls++;handle=(handle+0x1020304L)&MASK;writeWord(HANDLE,handle);
                    long lr=register("lr");for(String r:new String[]{"r0","r1","r2","r3","r12"})register(r,0xdeadbeefL);
                    register("cpsr",0xa0000010L);thread.overrideContext(new RegisterValue(currentProgram.getProgramContext().getBaseContextRegister(),BigInteger.ZERO));
                    thread.overrideCounter(toAddr(lr));continue;
                }
                require(path?within(pc,4,BUILD,BUILD+codeSize):within(pc,4,RA,0x2c3b34)||within(pc,4,RE,0x2c3a98)||within(pc,4,ACQUIRE,ACQUIRE_END)||within(pc,4,RELEASE,RELEASE_END),"PC extent");
                long bits=word(memory(pc,4),0);
                if(inBase && plan.pending && cursor==plan.events.size() && (bits&0x0ff00fffL)==0x01900f9fL)break;
                require(++steps<4096,"Wrapper budget");if(!path)visited.add(pc);
                if((bits&0xffff0fffL)==0xee1d0f70L) {
                    require(!inBase,"TLS inside base");event("tls",tls);tlsReads++;
                    register("r"+((bits>>>12)&15),tls);thread.overrideCounter(toAddr(pc+4));continue;
                }
                monitor.checkCancelled();thread.stepInstruction();
            }
            require(wi==events.size(),"Missing wrapper events");
            require(!reservation && !storePending && !success,"Exclusive state");
            require(!usesBase || cursor==plan.events.size(),"Missing base events");
            require(Arrays.equals(memory(DATA-32,96),expected),"Final object/guards");
            require(word(expected,32)==(usesBase?plan.current:initial),"Final base oracle");
            if(!usesBase || !plan.pending) {
                if(!usesBase)require(register("r2")==incomingR2,"Recursive no-base r2 preservation");
                else require(register("r2")==plan.returnedR2,"Recursive base r2 return");
                require(register("sp")==STACK,"SP restoration");for(int r=4;r<=11;r++)require(register("r"+r)==0x12340000L+r,"Callee saved");
            } else require(pcPending(),"Pending returned");
            for(byte b:memory(STACK-0x1000,0xf00))require(b==(byte)0x96,"Stack guard");
            maxSteps=Math.max(maxSteps,steps);executing=false;
        }
        boolean pcPending() {return thread.getCounter().getOffset()!=RETURN;}
    }
    void compare(RecursiveMachine a,RecursiveMachine b,PrintWriter log,boolean release,long initial,long owner,long count,long tls,long next,
            long[] reads,boolean[] failures,int limit,boolean mutate,boolean persistent) throws Exception {
        try {
            a.invoke(false,release,initial,owner,count,tls,next,reads,failures,limit,mutate,persistent);
            b.invoke(true,release,initial,owner,count,tls,next,reads,failures,limit,mutate,persistent);
            require(Arrays.equals(a.memory(DATA-32,96),b.memory(DATA-32,96)),"Original/rebuilt object");
            log.printf("%d\t%b\t%x\t%x\t%x\t%x\t%x\t%b\t%s\t%s\t%s\t%s\t%s%n",cases,release,initial,owner,count,tls,next,mutate,Arrays.toString(reads),Arrays.toString(failures),a.events,a.plan.events.subList(0,a.cursor),HexFormat.of().formatHex(a.memory(DATA,12)));
            cases++;if(a.pcPending())pending++;
        } catch(Exception e) {throw new IllegalStateException("Recursive case "+cases+" release="+release+" count="+Long.toHexString(count),e);}
    }
    @Override public void run() throws Exception {
        Path out=Path.of(getScriptArgs()[0]);byte[] map=new byte[0x377000];
        require(currentProgram.getMemory().getBytes(toAddr(0x100000),map)==map.length,"Map");
        require(HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(map)).equals("834938d18d2b7c688311c46c27bed813d0d7a9f8e3cbb61da8a6a3f23d360ebd"),"Hash");
        byte[] binary=Files.readAllBytes(out.resolve("resource-recursive-lock.bin"));codeSize=binary.length;
        var lines=Files.readAllLines(out.resolve("entries.txt"));require(lines.size()==4,"Entries");for(int i=0;i<4;i++)rebuilt[i]=Long.parseLong(lines.get(i));
        RecursiveMachine a=new RecursiveMachine(map,binary),b=new RecursiveMachine(map,binary);
        try(PrintWriter log=new PrintWriter(Files.newBufferedWriter(out.resolve("results.tsv")))) {
            log.println("case\trelease\tbase\towner\tcount\ttls\tnext_tls\tmutate\treads\tfailures\twrapper_events\tconsumed_base_events\tfinal_lock_bytes");
            for(long count:STATES)for(long tls:new long[]{0,0x919000,0xffffffffL})for(boolean same:new boolean[]{false,true}) {
                long owner=same?tls:tls^0x12345678L;
                compare(a,b,log,false,2,owner,count,tls,tls^0x11223344L,new long[]{2,-1,-1},new boolean[]{true,false},32,false,false);
                compare(a,b,log,true,0xfffffffeL,owner,count,tls,tls,new long[]{0xfffffffeL,-1},new boolean[]{true,false},32,false,false);
            }
            for(long count:STATES)for(long[] schedule:new long[][]{{0,0,2},{MASK,-1,0,2},{MASK,-1,2}})for(boolean mutation:new boolean[]{false,true})
                compare(a,b,log,false,schedule[0],0x1234,count,0x919000,0x929000,schedule,new boolean[]{true,false},32,mutation,false);
            for(long base:STATES)compare(a,b,log,true,base,0x919000,1,0,0,new long[]{base,-1},new boolean[]{true,false},32,true,false);
            for(int n:new int[]{1,7}) {
                compare(a,b,log,false,0,0,9,0x919000,0x929000,new long[n],new boolean[]{false},n,false,false);
                compare(a,b,log,true,2,0x919000,1,0,0,new long[]{2,-1,-1,-1,-1,-1,-1},new boolean[]{true},n,false,false);
            }
            // Persistent acquire, nested acquire/release, final release; never reseed object between calls.
            for(long tls:new long[]{0x919000,0xffffffffL}) {
                compare(a,b,log,false,1,0,0,tls,tls,new long[]{-1},new boolean[]{false},32,false,false);
                compare(a,b,log,false,MASK,tls,1,tls,tls,new long[]{-1},new boolean[]{false},32,false,true);
                compare(a,b,log,true,MASK,tls,2,tls,tls,new long[]{-1},new boolean[]{false},32,false,true);
                compare(a,b,log,true,MASK,tls,1,tls,tls,new long[]{-1},new boolean[]{false},32,false,true);sequences++;
            }
        }
        StringBuilder listing=new StringBuilder();int sites=0;
        for(long[] range:new long[][]{{RA,0x2c3b34},{RE,0x2c3a98}}) {
            var f=getFunctionAt(toAddr(range[0]));require(f!=null && f.getBody().getMaxAddress().getOffset()==range[1]-1,"Saved extent");
            listing.append(f.getBody()).append('\n');
            for(long pc=range[0];pc<range[1];pc+=4){require(visited.contains(pc),"Unvisited wrapper");sites++;listing.append(String.format("%08x %s%n",pc,getInstructionAt(toAddr(pc))));}
        }
        Files.writeString(out.resolve("original-ghidra.txt"),listing);
        Files.writeString(out.resolve("visited.txt"),String.join("\n",visited.stream().map(v->String.format("%08x",v)).toList())+"\n");
        Files.writeString(out.resolve("comparison.json"),String.format(Locale.ROOT,"{\"cases\":%d,\"pending_prefixes\":%d,\"persistent_sequences\":%d,\"new_instruction_sites\":%d,\"total_original_sites\":%d,\"tls_reads_both\":%d,\"base_calls_both\":%d,\"arbitrations_both\":%d,\"exclusive_attempts_both\":%d,\"max_steps\":%d,\"base_locks_executed\":true,\"tls_exclusives_arbitration_modeled\":true,\"live_verified\":false}\n",cases,pending,sequences,sites,visited.size(),tlsReads,baseCalls,boundaryCalls,attempts,maxSteps));
        println("SMT4_RECURSIVE_LOCK_COMPARE_OK");
    }
}
