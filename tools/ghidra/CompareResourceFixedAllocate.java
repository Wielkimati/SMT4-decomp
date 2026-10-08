// Fixed allocation, recovered insertion/free and both fixed router lifetimes.
// @category SMT4
import ghidra.pcode.emu.PcodeThread;
import ghidra.pcode.utils.Utils;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.pcode.PcodeOp;
import java.nio.file.*;
import java.security.MessageDigest;
import java.util.*;
import java.io.*;

public class CompareResourceFixedAllocate extends CompareResourceFixedFree {
    static final long ALLOC=0x144978, ALLOC_ROUTER=0x2b26f0, METADATA=0x2c5544;
    int allocationCases,exactCases,splitCases,noFitCases,zeroRouterCases,overruns,wraps,allocationLifetimes;
    long metadataCalls;
    @Override boolean originalCode(long pc) {
        return super.originalCode(pc) || within(pc,4,ALLOC,0x144ab4) ||
            (within(pc,4,ALLOC_ROUTER,0x2b285c) && !within(pc,4,0x2b2724,0x2b273c));
    }
    class Allocation {
        long result,record; Pool before,after;
    }
    Allocation allocate(Pool p,long size,long metadata,int mode,boolean routed) {
        Allocation result=new Allocation();
        if(routed && size==0) { zeroRouterCases++; return result; }
        long selected=0;
        for(long n:p.free) if(p.get(n+4)>=size) { selected=n; break; }
        if(selected==0) { noFitCases++; return result; }
        // Independent arithmetic oracle uses quotient/remainder, not the C mask.
        long rounded=u(((size+127)/128)*128);
        if(rounded<size) wraps++;
        if(rounded>p.get(selected+4)) overruns++;
        long n=selected;
        if(p.get(selected+4)==rounded) {
            exactCases++;
            p.set(p.object+24,p.get(p.object+24)-rounded);
            p.remove(p.free,p.object+12,selected);
        } else {
            splitCases++; result.record=metadata; result.before=new Pool(p);
            if(mode!=0) {
                // Synthetic recursive effects, disjoint fresh metadata. No claim
                // that the original metadata heap actually performs these edits.
                p.set(selected,p.get(selected)+0x20);
                p.set(selected+4,p.get(selected+4)+0x43);
                p.set(p.object+8,p.get(p.object+8)+0x80000001L);
                p.set(p.object+24,p.get(p.object+24)+0xfffffff9L);
                p.set(STATE+4,RAW+0x10);
            }
            result.after=new Pool(p); n=metadata;
            p.set(n,p.get(selected)); p.set(n+4,rounded); p.set(n+8,0); p.set(n+12,0);
            p.set(selected,p.get(selected)+rounded); p.set(selected+4,p.get(selected+4)-rounded);
            p.set(p.object+24,p.get(p.object+24)-rounded);
        }
        int index=0; while(index<p.used.size() && p.get(p.used.get(index))<p.get(n)) index++;
        p.used.add(index,n); p.relink(p.used,p.object); p.set(p.object+8,p.get(p.object+8)+1);
        result.result=p.get(n); return result;
    }
    class AllocationMachine extends PoolMachine {
        AllocationMachine(byte[] map,byte[] binary) { super(map,binary); }
        @Override public void beforeLoad(PcodeThread<byte[]> t,PcodeOp op,AddressSpace space,byte[] offset,int n) {
            long a=Utils.bytesToLong(offset,offset.length,false);
            if(within(a,n,0x144ab4,0x144ab8) || within(a,n,0x2b285c,0x2b2868) || within(a,n,0x2b2724,0x2b273c)) return;
            super.beforeLoad(t,op,space,offset,n);
        }
        void allocateCall(boolean build,int route,long size,Pool before,Pool after,Allocation expected) throws Exception {
            domain=before; initialize(build,0,new byte[0x144]); check(before,"Persistent allocation prestate"); trace.clear();
            byte[] caller=new byte[32]; new Random(cases).nextBytes(caller); put(caller,0,cases%2==0 ? 0 : 0x100); memory(STACK,caller);
            register("r0",route<0 ? before.object : route==0 ? 0x20000 : 0x30000);
            register("r1",route<0 ? size : 0x100+cases%7);
            register("r2",u(0xfedcba98L+cases)); register("r3",route<0 ? u(cases) : size);
            for(int r=16;r<32;r++) register("s"+r,0x81234000L+r);
            thread.overrideCounter(toAddr(build ? entries[route<0 ? 3 : 4] : route<0 ? ALLOC : ALLOC_ROUTER));
            executing=true; int steps=0,calls=0,insertions=0,allocations=0;
            while(thread.getCounter().getOffset()!=RETURN) {
                long pc=thread.getCounter().getOffset();
                if(pc==METADATA) {
                    require(expected.before!=null && ++calls==1,"Unexpected metadata allocation");
                    require(register("r0")==0x100 && register("r1")==0x100 && register("r2")==0 && register("r3")==16 && word(memory(register("sp"),4),0)==1,"Metadata allocation arguments");
                    require((register("sp")&7)==0,"Metadata stack alignment"); check(expected.before,"Metadata allocation prestate");
                    seed(expected.after); executing=true; metadataCalls++; trace.add("A:"+Long.toHexString(expected.record));
                    for(int r=0;r<16;r++) register("s"+r,0xdead0000L+r);
                    externalReturn(expected.record); continue;
                }
                if(pc==(build ? entries[3] : ALLOC)) {
                    allocations++; require(register("r0")==before.object && register("r1")==size,"Allocation forwarding");
                }
                if(pc==(build ? entries[1] : INSERT)) {
                    insertions++; require(register("r0")==before.object && (register("sp")&7)==0,"Used insertion argument/alignment");
                }
                require(build ? within(pc,4,BUILD,BUILD+textSize) : originalCode(pc),"Unexpected execution "+Long.toHexString(pc));
                if(!build) visited.add(pc); require(++steps<3000,"Instruction budget"); monitor.checkCancelled(); thread.stepInstruction();
            }
            executing=false;
            require(calls==(expected.before==null ? 0 : 1) && allocations==(route>=0 && size==0 ? 0 : 1),"Missing allocation call");
            require(insertions==(after.used.size()>before.used.size() ? 1 : 0),"Missing insertion");
            require(register("r0")==expected.result,"Allocation result"); check(after,"Allocation final");
            require(Arrays.equals(caller,memory(STACK,caller.length)),"Caller stack");
            byte[] stack=memory(STACK-0x1000,0x1000); for(int i=0;i<stack.length-256;i++) require(stack[i]==(byte)0x96,"Stack guard");
            for(int r=16;r<32;r++) require(register("s"+r)==0x81234000L+r,"Saved VFP"); finish(steps);
        }
    }
    long compareAllocation(AllocationMachine a,AllocationMachine b,Pool p,int route,long size,int fresh,int mode,PrintWriter log) throws Exception {
        Pool before=new Pool(p); Allocation expected=allocate(p,size,p.node(fresh),mode,route>=0);
        try {
            a.allocateCall(false,route,size,before,p,expected); b.allocateCall(true,route,size,before,p,expected);
            require(a.trace.equals(b.trace),"Ordered allocation accesses\noriginal="+a.trace+"\nrebuilt="+b.trace);
        } catch(Exception ex) { throw new IllegalStateException("Fixed allocation case "+cases+" route="+route+" size="+Long.toHexString(size)+" mode="+mode,ex); }
        log.printf("%d\tallocate\t%d\t%x\t%x\t%d%n",cases++,route,size,expected.result,mode); allocationCases++; return expected.result;
    }
    @Override public void run() throws Exception {
        Path out=Path.of(getScriptArgs()[0]); require(!Files.exists(out.resolve("comparison.json")),"Existing output");
        byte[] map=new byte[0x377000]; require(currentProgram.getMemory().getBytes(toAddr(0x100000),map)==map.length,"Map");
        require(HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(map)).equals("834938d18d2b7c688311c46c27bed813d0d7a9f8e3cbb61da8a6a3f23d360ebd"),"Hash");
        byte[] binary=Files.readAllBytes(out.resolve("resource-fixed-allocate.bin")); codeSize=binary.length;
        textSize=Integer.parseInt(Files.readString(out.resolve("text-size.txt")).trim());
        List<String> lines=Files.readAllLines(out.resolve("entries.txt")); require(lines.size()==5,"Entries"); for(int i=0;i<5;i++) entries[i]=Long.parseLong(lines.get(i));
        var f=getFunctionAt(toAddr(ALLOC)); require(f!=null && f.getBody().getMinAddress().getOffset()==ALLOC && f.getBody().getMaxAddress().getOffset()==0x144ab3,"Saved boundary");
        AllocationMachine a=new AllocationMachine(map,binary),b=new AllocationMachine(map,binary);
        try(PrintWriter log=new PrintWriter(Files.newBufferedWriter(out.resolve("results.tsv")))) {
            // Empty/no-fit, zero, rounding boundaries, unsigned size and address wrap.
            long[][] extents={{},{0},{1},{127},{128},{129},{256},{0x7fffffffL},{0x80000000L},{MASK},{0x20,0x80,0x40,0x200}};
            long[] requests={0,1,127,128,129,256,257,0x7fffffffL,0x80000000L,0xffffff80L,0xffffff81L,MASK};
            for(int route=-1;route<2;route++) for(int high=0;high<2;high++) for(long[] sizes:extents) for(long size:requests) for(int mode=0;mode<2;mode++) {
                Pool p=new Pool(high,route); long key=high==0 ? 0x3000 : 0xffffff00L;
                for(int i=0;i<sizes.length;i++) p.add(true,i,u(key+i*0x100),sizes[i]);
                // Ordered used keys force head/equal/middle/tail insertions across addresses.
                p.add(false,6,0,16); p.add(false,7,0x3000,32); p.add(false,8,0xffffff80L,64);
                p.link(); counters(p,cases%4); a.seed(p); b.seed(p); compareAllocation(a,b,p,route,size,10,mode,log);
            }
            // Exact transfer of singleton/head/middle/tail; first-fit skips undersized nodes.
            for(int route=-1;route<2;route++) for(int selected=0;selected<4;selected++) {
                Pool p=new Pool(0,route); int count=selected==0 ? 1 : 3,ix=selected==0 || selected==1 ? 0 : selected==2 ? 1 : 2;
                for(int i=0;i<count;i++) p.add(true,i,0x4000+0x200*i,i==ix ? 128 : i<ix ? 64 : 256);
                p.link(); p.set(p.object+20,count); p.set(p.object+24,1024);
                a.seed(p); b.seed(p); compareAllocation(a,b,p,route,128,10,0,log);
            }
            // Real machine state persists through allocation, exhaustion, free and reuse.
            int[][] orders={{0,1,2,3},{3,2,1,0},{1,3,0,2},{2,0,3,1},{1,2,0,3},{0,3,2,1}};
            for(int route=-1;route<2;route++) for(int high=0;high<2;high++) for(int[] order:orders) {
                Pool p=new Pool(high,route); long key=high==0 ? 0x3000 : 0x80003000L;
                p.add(true,0,key,512); p.link(); p.set(p.object+20,1); p.set(p.object+24,512);
                if(route>=0) { int off=route==0 ? 0xec : 0xf8; p.set(RAW+off,key); p.set(RAW+off+4,512); }
                a.seed(p); b.seed(p); allocationLifetimes++; long[] allocated=new long[4];
                for(int i=0;i<4;i++) allocated[i]=compareAllocation(a,b,p,route,1+31*i,10+i,0,log);
                require(p.free.isEmpty() && p.used.size()==4 && p.get(p.object+24)==0,"Exhausted pool");
                compareAllocation(a,b,p,route,1,14,0,log);
                for(int i:order) compare(a,b,p,route<0 ? 0 : 2,allocated[i],0,log);
                require(p.used.isEmpty() && p.free.size()==1 && p.get(p.free.get(0))==key && p.get(p.free.get(0)+4)==512 && p.get(p.object+8)==0 && p.get(p.object+20)==1 && p.get(p.object+24)==512,"Restored lifetime extent/accounting");
                long reused=compareAllocation(a,b,p,route,512,15,0,log); require(reused==key,"Payload reuse");
                compare(a,b,p,route<0 ? 0 : 2,reused,0,log);
                require(p.used.isEmpty() && p.free.size()==1 && p.get(p.object+24)==512,"Restored reused pool");
            }
        }
        StringBuilder listing=new StringBuilder(); int count=0,visitedNew=0;
        for(long pc=ALLOC;pc<0x144ab4;pc+=4) {
            // Second rounding arm is unreachable: first rounding always clears low 7 bits.
            require((pc>=0x1449c4 && pc<=0x1449cc) || visited.contains(pc),"Unvisited allocation instruction "+Long.toHexString(pc));
            var ins=currentProgram.getListing().getInstructionAt(toAddr(pc)); require(ins!=null,"Instruction");
            listing.append(String.format("%08x %s %s%n",pc,HexFormat.of().formatHex(ins.getBytes()),ins)); count++; if(visited.contains(pc)) visitedNew++;
        }
        Files.writeString(out.resolve("original-ghidra.txt"),listing);
        Files.writeString(out.resolve("comparison.json"),String.format(Locale.ROOT,"{\"cases\":%d,\"allocation_cases\":%d,\"free_cases\":%d,\"exact_transfers\":%d,\"splits\":%d,\"no_fit\":%d,\"router_zero_size\":%d,\"rounded_overruns\":%d,\"rounding_wrap\":%d,\"persistent_lifetimes\":%d,\"new_instruction_addresses\":%d,\"visited_new_instructions\":%d,\"metadata_allocation_calls_both_paths\":%d,\"metadata_release_calls_both_paths\":%d,\"external_reads_both_paths\":%d,\"external_writes_both_paths\":%d,\"max_steps\":%d,\"metadata_allocation_and_release_modeled\":true,\"live_verified\":false}\n",cases,allocationCases,freeCases+routedCases,exactCases,splitCases,noFitCases,zeroRouterCases,overruns,wraps,allocationLifetimes,count,visitedNew,metadataCalls,releases,reads,writes,maxSteps));
        println("SMT4_FIXED_ALLOCATE_COMPARE_OK");
    }
}
