// Fixed-pool records and both fixed router routes. Recursive metadata release modeled.
// @category SMT4
import ghidra.pcode.emu.PcodeThread;
import ghidra.pcode.utils.Utils;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.pcode.PcodeOp;
import java.nio.file.*;
import java.security.MessageDigest;
import java.util.*;
import java.io.*;

public class CompareResourceFixedFree extends CompareResourceSync {
    static final long FREE=0x138354, INSERT=0x2c3928, ROUTER=0x1244e8, RELEASE=0x2c43b4;
    static final long STATE=0x465170, RAW=0x940000, MASK=0xffffffffL;
    int cases,insertCases,freeCases,routedCases,lifetimes,textSize;
    int[] merges=new int[4],positions=new int[4];
    long reads,writes,releases;
    static long u(long v) { return v&MASK; }
    @Override boolean originalCode(long pc) {
        return within(pc,4,FREE,0x1384b8) || within(pc,4,INSERT,0x2c39bc) || within(pc,4,ROUTER,0x1245e4);
    }
    // Byte oracle with declarative list insertion/removal. Snapshots at release
    // boundaries verify intermediate state, not only the final coalesced result.
    class Pool {
        long object,base;
        TreeMap<Long,byte[]> regions=new TreeMap<>();
        List<Long> used=new ArrayList<>(),free=new ArrayList<>();
        Pool(int high,int route) {
            object=route<0 ? (high==0 ? 0x910000 : 0x89100000L) : route==0 ? 0x4e4100 : 0x4e411c;
            base=high==0 ? 0x920000 : 0x89200000L;
            // Includes both adjacent fixed objects, so accidental route aliasing fails.
            region(route<0 ? object-16 : 0x4e40f0,96); region(base,0x500);
            region(STATE-16,48); region(RAW-16,0x130);
            set(STATE+4,RAW);
            for(int off:new int[]{0x14,0x80,0xec,0xf8}) { set(RAW+off,0); set(RAW+off+4,0); }
            set(object+8,0); set(object+20,0); set(object+24,0);
        }
        Pool(Pool p) { object=p.object; base=p.base; p.regions.forEach((a,b)->regions.put(a,b.clone())); used.addAll(p.used); free.addAll(p.free); }
        void region(long a,int size) { byte[] b=new byte[size]; new Random(a+cases).nextBytes(b); regions.put(a,b); }
        Map.Entry<Long,byte[]> findRegion(long a,int n) {
            var e=regions.floorEntry(a); require(e!=null && within(a,n,e.getKey(),e.getKey()+e.getValue().length),"Oracle bounds"); return e;
        }
        long get(long a) { var e=findRegion(a,4); return word(e.getValue(),(int)(a-e.getKey())); }
        void set(long a,long v) { var e=findRegion(a,4); put(e.getValue(),(int)(a-e.getKey()),v); }
        long node(int i) { return base+0x20+0x30*i; }
        long add(boolean available,int i,long key,long size) {
            long n=node(i); set(n,key); set(n+4,size); (available ? free : used).add(n); return n;
        }
        void relink(List<Long> list,long roots) {
            set(roots,list.isEmpty() ? 0 : list.get(0)); set(roots+4,list.isEmpty() ? 0 : list.get(list.size()-1));
            for(int i=0;i<list.size();i++) { set(list.get(i)+8,i==0 ? 0 : list.get(i-1)); set(list.get(i)+12,i+1==list.size() ? 0 : list.get(i+1)); }
        }
        void link() { relink(used,object); relink(free,object+12); }
        void insert(long n) {
            int index=0; while(index<free.size() && get(free.get(index))<get(n)) index++;
            free.add(index,n); relink(free,object+12); set(object+20,get(object+20)+1);
        }
        void remove(List<Long> list,long roots,long n) {
            require(list.remove(Long.valueOf(n)),"Oracle membership"); relink(list,roots); set(n+8,0); set(n+12,0); set(roots+8,get(roots+8)-1);
        }
    }
    class Event {
        long node; Pool before,after;
        Event(long n,Pool a,Pool b) { node=n; before=a; after=b; }
    }
    void effect(Pool p,long retired,long live,int mode) {
        if(mode==0) return;
        // A bounded synthetic release effect: reclaimed metadata is poisoned;
        // accounting can change recursively. This is not recovered release logic.
        for(int i=0;i<16;i+=4) p.set(retired+i,0xc0ffee00L+i);
        p.set(p.object+20,p.get(p.object+20)+0x80000001L);
        p.set(p.object+24,p.get(p.object+24)+0xfffffff9L);
        if(mode==2 && live!=0 && p.free.contains(live)) {
            int index=p.free.indexOf(live);
            if(index>0) { long left=p.free.get(index-1); p.set(left+4,p.get(left+4)+1); }
        }
    }
    void retire(Pool p,long retired,long live,int mode,List<Event> events) {
        Pool before=new Pool(p); effect(p,retired,live,mode); events.add(new Event(retired,before,new Pool(p)));
    }
    List<Event> release(Pool p,long address,int mode) {
        long n=0; for(long candidate:p.used) if(p.get(candidate)==address) { n=candidate; break; }
        require(n!=0,"Valid used record required"); int index=p.used.indexOf(n);
        positions[p.used.size()==1 ? 0 : index==0 ? 1 : index+1==p.used.size() ? 2 : 3]++;
        p.remove(p.used,p.object,n); p.set(p.object+24,p.get(p.object+24)+p.get(n+4)); p.insert(n);
        List<Event> events=new ArrayList<>(); boolean right=false,left=false;
        index=p.free.indexOf(n);
        if(index+1<p.free.size()) {
            long r=p.free.get(index+1);
            if(u(p.get(n)+p.get(n+4))==p.get(r)) {
                right=true; p.set(n+4,p.get(n+4)+p.get(r+4)); p.remove(p.free,p.object+12,r); retire(p,r,n,mode,events);
            }
        }
        index=p.free.indexOf(n);
        if(index>0) {
            long l=p.free.get(index-1);
            if(u(p.get(l)+p.get(l+4))==p.get(n)) {
                left=true; p.set(l+4,p.get(l+4)+p.get(n+4)); p.remove(p.free,p.object+12,n); retire(p,n,0,mode,events);
            }
        }
        merges[(left ? 1 : 0)|(right ? 2 : 0)]++; return events;
    }
    class PoolMachine extends SyncMachine {
        Pool domain; List<String> trace=new ArrayList<>();
        PoolMachine(byte[] map,byte[] binary) { super(map,binary); }
        boolean data(long a,int n) { var e=domain.regions.floorEntry(a); return e!=null && within(a,n,e.getKey(),e.getKey()+e.getValue().length); }
        @Override public void beforeLoad(PcodeThread<byte[]> t,PcodeOp op,AddressSpace space,byte[] offset,int n) {
            long a=Utils.bytesToLong(offset,offset.length,false);
            if(within(a,n,STACK-256,STACK+32) || within(a,n,BUILD,BUILD+codeSize) || within(a,n,0x1245e4,0x1245f0)) return;
            require(data(a,n),"Read outside fixture "+Long.toHexString(a)); trace.add("R:"+Long.toHexString(a)+":"+n); reads++;
        }
        @Override public void beforeStore(PcodeThread<byte[]> t,PcodeOp op,AddressSpace space,byte[] offset,int n,byte[] value) {
            long a=Utils.bytesToLong(offset,offset.length,false);
            if(within(a,n,STACK-256,STACK)) return;
            require(data(a,n),"Write outside fixture "+Long.toHexString(a));
            trace.add("W:"+Long.toHexString(a)+":"+n+":"+Long.toHexString(Utils.bytesToLong(value,n,false))); CompareResourceFixedFree.this.writes++;
        }
        void seed(Pool p) { executing=false; p.regions.forEach((a,b)->memory(a,b)); }
        void check(Pool p,String label) {
            p.regions.forEach((a,b)->require(Arrays.equals(b,memory(a,b.length)),label+" bytes/guards at "+Long.toHexString(a)));
        }
        void call(boolean build,int kind,long arg,Pool before,Pool after,List<Event> events) throws Exception {
            domain=before; initialize(build,0,new byte[0x144]); check(before,"Persistent prestate"); trace.clear();
            byte[] caller=new byte[32]; new Random(cases).nextBytes(caller); memory(STACK,caller);
            register("r0",kind==2 ? arg : kind==1 ? before.object+12 : before.object); register("r1",arg);
            for(int r=16;r<32;r++) register("s"+r,0x81234000L+r);
            thread.overrideCounter(toAddr(build ? entries[kind] : kind==0 ? FREE : kind==1 ? INSERT : ROUTER));
            executing=true; int steps=0,count=0,insertions=0,freeEntries=0;
            while(thread.getCounter().getOffset()!=RETURN) {
                long pc=thread.getCounter().getOffset();
                if(pc==RELEASE) {
                    require(count<events.size(),"Unexpected metadata release"); Event e=events.get(count++);
                    require(register("r0")==e.node && (register("sp")&7)==0,"Metadata release argument/alignment");
                    check(e.before,"Release prestate"); seed(e.after); executing=true;
                    trace.add("C:"+Long.toHexString(e.node)); releases++;
                    for(int r=0;r<16;r++) register("s"+r,0xdead0000L+r);
                    externalReturn(u(0xaabbcc00L+count)); continue;
                }
                if(pc==(build ? entries[0] : FREE)) {
                    freeEntries++; require(register("r0")==before.object && register("r1")==arg,"Free entry forwarding");
                }
                if(pc==(build ? entries[1] : INSERT)) {
                    insertions++; require(register("r0")==before.object+12 && (register("sp")&7)==0,"Insertion argument/alignment");
                }
                require(build ? within(pc,4,BUILD,BUILD+textSize) : originalCode(pc),"Unexpected execution "+Long.toHexString(pc));
                if(!build) visited.add(pc); require(++steps<3000,"Instruction budget"); monitor.checkCancelled(); thread.stepInstruction();
            }
            executing=false; require(count==events.size() && insertions==1 && freeEntries==(kind==1 ? 0 : 1),"Missing call");
            if(kind==1) require(register("r0")==before.object+12,"Insertion observed r0");
            check(after,"Final"); require(Arrays.equals(caller,memory(STACK,caller.length)),"Caller stack");
            byte[] stack=memory(STACK-0x1000,0x1000); for(int i=0;i<stack.length-256;i++) require(stack[i]==(byte)0x96,"Stack guard");
            for(int r=16;r<32;r++) require(register("s"+r)==0x81234000L+r,"Saved VFP"); finish(steps);
        }
    }
    void compare(PoolMachine a,PoolMachine b,Pool p,int kind,long arg,int mode,PrintWriter log) throws Exception {
        Pool before=new Pool(p); List<Event> events;
        if(kind==1) { p.insert(arg); events=List.of(); } else events=release(p,arg,mode);
        try {
            a.call(false,kind,arg,before,p,events); b.call(true,kind,arg,before,p,events);
            require(a.trace.equals(b.trace),"Ordered accesses\noriginal="+a.trace+"\nrebuilt="+b.trace);
        } catch(Exception ex) { throw new IllegalStateException("Fixed pool case "+cases+" kind="+kind+" mode="+mode+" arg="+Long.toHexString(arg),ex); }
        if(kind==1) insertCases++; else if(kind==2) routedCases++; else freeCases++;
        log.printf("%d\t%d\t%x\t%x\t%d\t%d%n",cases++,kind,p.object,arg,mode,events.size());
    }
    void counters(Pool p,int profile) {
        long[] values={0,1,MASK,0x80000000L}; p.set(p.object+8,values[profile%4]); p.set(p.object+20,values[(profile+1)%4]); p.set(p.object+24,values[(profile+2)%4]);
    }
    @Override public void run() throws Exception {
        Path out=Path.of(getScriptArgs()[0]); require(!Files.exists(out.resolve("comparison.json")),"Existing output");
        byte[] map=new byte[0x377000]; require(currentProgram.getMemory().getBytes(toAddr(0x100000),map)==map.length,"Map");
        require(HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(map)).equals("834938d18d2b7c688311c46c27bed813d0d7a9f8e3cbb61da8a6a3f23d360ebd"),"Hash");
        byte[] binary=Files.readAllBytes(out.resolve("resource-fixed-free.bin")); codeSize=binary.length;
        textSize=Integer.parseInt(Files.readString(out.resolve("text-size.txt")).trim());
        List<String> lines=Files.readAllLines(out.resolve("entries.txt")); require(lines.size()==3,"Entries"); for(int i=0;i<3;i++) entries[i]=Long.parseLong(lines.get(i));
        for(long[] range:new long[][]{{FREE,0x1384b8},{INSERT,0x2c39bc}}) {
            var f=getFunctionAt(toAddr(range[0])); require(f!=null && f.getBody().getMinAddress().getOffset()==range[0] && f.getBody().getMaxAddress().getOffset()==range[1]-1,"Saved boundary");
        }
        PoolMachine a=new PoolMachine(map,binary),b=new PoolMachine(map,binary);
        try(PrintWriter log=new PrintWriter(Files.newBufferedWriter(out.resolve("results.tsv")))) {
            // Equal keys, zero/max/high-bit keys, all insertion positions, counter wrap.
            long[][] keys={{},{0},{MASK},{0x100,0x200,0x300},{0,0,0x80000000L,0x80000000L,MASK},{0x7fffffffL,0x80000000L}};
            for(int high=0;high<2;high++) for(long[] list:keys) for(long key:new long[]{0,1,0xff,0x100,0x180,0x200,0x300,0x301,0x7fffffffL,0x80000000L,MASK}) for(int counter=0;counter<4;counter++) {
                Pool p=new Pool(high,-1); for(int i=0;i<list.length;i++) p.add(true,i,list[i],0x25+i); p.link(); counters(p,counter);
                long n=p.node(10); p.set(n,key); p.set(n+4,MASK); a.seed(p); b.seed(p); compare(a,b,p,1,n,0,log);
            }
            // Valid record membership; synthetic accounting need not equal list length.
            for(int route=-1;route<2;route++) for(int high=0;high<2;high++) for(int neighbors=0;neighbors<4;neighbors++)
            for(int topology=0;topology<4;topology++) for(int used=0;used<4;used++) for(int mode=0;mode<3;mode++) {
                Pool p=new Pool(high,route); long key=high==0 ? 0x3000 : 0x80003000L,size=0x40;
                if((neighbors&1)!=0) { p.add(true,0,key-0x100,0x20); p.add(true,1,key-0x40,(topology&1)!=0 ? 0x40 : 0x20); }
                if((neighbors&2)!=0) { p.add(true,2,key+((topology&2)!=0 ? size : size+0x20),0x30); p.add(true,3,key+0x100,0x20); }
                int count=used==0 ? 1 : 3,selected=used==0 || used==1 ? 0 : used==2 ? 2 : 1;
                for(int i=0;i<count;i++) p.add(false,5+i,i==selected ? key : key+0x200+i*0x100,i==selected ? size : 0x20);
                p.link(); counters(p,cases%4);
                if(route>=0) { int off=route==0 ? 0xec : 0xf8; p.set(RAW+off,key); p.set(RAW+off+4,size); }
                a.seed(p); b.seed(p); compare(a,b,p,route<0 ? 0 : 2,key,mode,log);
            }
            // Left adjacency and merged sizes use modulo-u32 arithmetic. These
            // synthetic large extents are arithmetic probes, not physical arenas.
            for(int high=0;high<2;high++) for(int mode=0;mode<3;mode++) {
                Pool p=new Pool(high,-1); p.add(true,0,0x10,0xfffffff0L); p.add(false,1,0,0x10); p.link(); counters(p,2);
                a.seed(p); b.seed(p); compare(a,b,p,0,0,mode,log);
                p=new Pool(high,-1); p.add(true,0,0x10,0x10); p.add(false,1,0x20,0xfffffff0L); p.link(); counters(p,3);
                a.seed(p); b.seed(p); compare(a,b,p,0,0x20,mode,log);
            }
            // Persistent drains: no fixture rewrite between actual frees.
            int[][] orders={{0,1,2,3},{3,2,1,0},{1,3,0,2},{2,0,3,1},{1,2,0,3},{0,3,2,1}};
            for(int route=-1;route<2;route++) for(int high=0;high<2;high++) for(int[] order:orders) {
                Pool p=new Pool(high,route); long key=high==0 ? 0x3000 : 0x80003000L;
                p.add(true,0,key-0x20,0x20); p.add(true,1,key+0x80,0x20);
                for(int i=0;i<4;i++) p.add(false,2+i,key+0x20*i,0x20); p.link(); p.set(p.object+8,4); p.set(p.object+20,2); p.set(p.object+24,0x40);
                if(route>=0) { int off=route==0 ? 0xec : 0xf8; p.set(RAW+off,key); p.set(RAW+off+4,0x80); }
                a.seed(p); b.seed(p); lifetimes++;
                for(int i:order) compare(a,b,p,route<0 ? 0 : 2,key+0x20*i,0,log);
                require(p.used.isEmpty() && p.free.size()==1 && p.get(p.free.get(0)+4)==0xc0 && p.get(p.object+8)==0 && p.get(p.object+20)==1 && p.get(p.object+24)==0xc0,"Restored pool extent/accounting");
            }
        }
        StringBuilder listing=new StringBuilder(); int count=0,visitedNew=0;
        for(long[] range:new long[][]{{FREE,0x1384b8},{INSERT,0x2c39bc}}) for(long pc=range[0];pc<range[1];pc+=4) {
            require(pc==0x138384 || visited.contains(pc),"Unvisited valid-domain instruction "+Long.toHexString(pc)); var ins=currentProgram.getListing().getInstructionAt(toAddr(pc)); require(ins!=null,"Instruction");
            listing.append(String.format("%08x %s %s%n",pc,HexFormat.of().formatHex(ins.getBytes()),ins)); count++; if(visited.contains(pc)) visitedNew++;
        }
        Files.writeString(out.resolve("original-ghidra.txt"),listing);
        Files.writeString(out.resolve("comparison.json"),String.format(Locale.ROOT,"{\"cases\":%d,\"insert_cases\":%d,\"direct_frees\":%d,\"routed_frees\":%d,\"persistent_drains\":%d,\"merges\":%s,\"used_positions\":%s,\"new_instruction_addresses\":%d,\"valid_domain_visited_new_instructions\":%d,\"missing_record_path_tested\":false,\"metadata_release_calls_both_paths\":%d,\"external_reads_both_paths\":%d,\"external_writes_both_paths\":%d,\"max_steps\":%d,\"recursive_metadata_release_modeled\":true,\"live_verified\":false}\n",cases,insertCases,freeCases,routedCases,lifetimes,Arrays.toString(merges),Arrays.toString(positions),count,visitedNew,releases,reads,writes,maxSteps));
        println("SMT4_FIXED_FREE_COMPARE_OK");
    }
}
