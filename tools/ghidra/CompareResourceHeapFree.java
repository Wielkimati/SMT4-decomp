// Persistent arena allocation/free/reallocation; no intercepted dependencies.
// @category SMT4
import ghidra.pcode.emu.PcodeThread;
import ghidra.pcode.utils.Utils;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.pcode.PcodeOp;
import java.nio.file.*;
import java.security.MessageDigest;
import java.util.*;
import java.io.*;

public class CompareResourceHeapFree extends CompareResourceHeapCommitBlock {
    static final long FREE=0x14699c, FREE_END=0x146ad4, FREE_WRAPPER=0x2b33d8;
    int directFrees,wrapperFrees,underflows,reallocations,minimumExtents;
    int[] merges=new int[4],usedPositions=new int[4];
    @Override boolean originalCode(long pc) {
        return super.originalCode(pc) || within(pc,4,FREE,FREE_END) || within(pc,4,FREE_WRAPPER,0x2b33f8);
    }
    // Independent interval/list oracle. Relinking only remaining nodes preserves
    // obsolete header bytes, which are still compared over the entire arena.
    long release(Arena a,long payload,boolean wrapper) {
        long node=payload-16,origin=node-((a.get(node+2,2)>>>8)&127),end=payload+a.get(node+4,4);
        int pos=a.used.indexOf(node); require(pos>=0,"Free of non-live payload");
        usedPositions[a.used.size()==1 ? 0 : pos==0 ? 1 : pos==a.used.size()-1 ? 2 : 3]++;
        a.used.remove(pos); a.relink(a.used,a.lists+8);
        long left=0,right=0;
        for(long n:a.free) { if(n<origin) left=n; else { right=n; break; } }
        boolean mergeRight=right!=0 && end==right;
        boolean mergeLeft=left!=0 && left+16+a.get(left+4,4)==origin;
        merges[(mergeLeft ? 1 : 0)|(mergeRight ? 2 : 0)]++;
        if(mergeRight) { end=right+16+a.get(right+4,4); a.free.remove(Long.valueOf(right)); a.relink(a.free,a.lists); }
        if(mergeLeft) { origin=left; a.free.remove(Long.valueOf(left)); a.relink(a.free,a.lists); }
        long predecessor=0; for(long n:a.free) if(n<origin) predecessor=n;
        long extent=end-origin; require(extent>=16,"Invalid valid-lifetime extent");
        if(extent==16) minimumExtents++;
        a.set(origin,2,0x4652); a.set(origin+2,2,0); a.set(origin+4,4,extent-16);
        a.free.add(origin); Collections.sort(a.free); a.relink(a.free,a.lists);
        if(wrapper) {
            long old=a.get(a.heap+0x54,4),count=u(old-1); a.set(a.heap+0x54,4,count);
            if(old==0) underflows++; return count;
        }
        return predecessor;
    }
    class FreeMachine extends CommitMachine {
        FreeMachine(byte[] map,byte[] binary) { super(map,binary); }
        @Override public void beforeLoad(PcodeThread<byte[]> t,PcodeOp op,AddressSpace space,byte[] offset,int n) {
            long address=Utils.bytesToLong(offset,offset.length,false);
            if(within(address,n,FREE_END,FREE_END+4)) return;
            super.beforeLoad(t,op,space,offset,n);
        }
        void freeCall(boolean rebuiltPath,boolean wrapper,long payload,Arena initial,Arena expected,long result) throws Exception {
            arena=initial; initialize(rebuiltPath,0,new byte[0x144]); trace.clear();
            byte[] caller=new byte[32]; new Random(cases).nextBytes(caller); memory(STACK,caller);
            register("r0",wrapper ? arena.heap : arena.heap+0x18); register("r1",payload);
            for(int r=16;r<32;r++) register("s"+r,0x81234000L+r);
            thread.overrideCounter(toAddr(rebuiltPath ? entries[wrapper ? 3 : 2] : wrapper ? FREE_WRAPPER : FREE));
            executing=true; int steps=0,innerCalls=0;
            while(thread.getCounter().getOffset()!=RETURN) {
                long pc=thread.getCounter().getOffset();
                require(rebuiltPath ? within(pc,4,BUILD,BUILD+textSize) : originalCode(pc),"Unexpected execution "+Long.toHexString(pc));
                if(pc==(rebuiltPath ? entries[2] : FREE)) {
                    innerCalls++; require((register("sp")&7)==0,"Inner entry stack alignment");
                    require(register("r0")==arena.heap+0x18 && register("r1")==payload,"Inner arguments");
                }
                if(!rebuiltPath) visited.add(pc);
                require(++steps<5000,"Instruction budget"); monitor.checkCancelled(); thread.stepInstruction();
            }
            require(innerCalls==1,"Missing/extra inner free");
            require(register("r0")==result,"Free return");
            require(Arrays.equals(expected.head,memory(expected.heap,expected.head.length)),"Free header bytes/guards");
            require(Arrays.equals(expected.data,memory(expected.base,expected.data.length)),"Free arena bytes/guards");
            require(Arrays.equals(caller,memory(STACK,caller.length)),"Free caller stack");
            byte[] stack=memory(STACK-0x1000,0x1000);
            for(int i=0;i<stack.length-256;i++) require(stack[i]==(byte)0x96,"Free stack guard");
            for(int r=16;r<32;r++) require(register("s"+r)==0x81234000L+r,"Free callee-saved VFP");
            finish(steps);
        }
    }
    void compareFree(FreeMachine a,FreeMachine b,Arena state,long payload,boolean wrapper,PrintWriter log) throws Exception {
        Arena before=new Arena(state); long result=release(state,payload,wrapper);
        try {
            a.freeCall(false,wrapper,payload,before,state,result); b.freeCall(true,wrapper,payload,before,state,result);
            require(a.trace.equals(b.trace),"Ordered free access trace\noriginal="+a.trace+"\nrebuilt="+b.trace);
        } catch(Exception ex) { throw new IllegalStateException("Heap free case "+cases+" wrapper="+wrapper,ex); }
        if(wrapper) wrapperFrees++; else directFrees++;
        log.printf("%d\tfree\t%b\t%x\t%x\t%d\t%d%n",cases++,wrapper,payload,result,state.free.size(),state.used.size());
    }
    long allocate(FreeMachine a,FreeMachine b,Arena state,long size,long alignment,int policy,int split,PrintWriter log) throws Exception {
        Call c=new Call(); c.integrated=true; c.size=size; c.alignment=alignment; c.policy=policy; c.split=split;
        c.group=new long[]{0,0xffffffffL,0x1234,0x80}[cases%4]; int old=state.used.size();
        try { compare(a,b,state,c,log); }
        catch(Exception ex) { throw new IllegalStateException("Heap free case "+cases+" allocation",ex); }
        return old==state.used.size() ? 0 : state.used.get(state.used.size()-1)+16;
    }
    @Override public void run() throws Exception {
        Path out=Path.of(getScriptArgs()[0]); require(!Files.exists(out.resolve("comparison.json")),"Existing output");
        byte[] map=new byte[0x377000]; require(currentProgram.getMemory().getBytes(toAddr(0x100000),map)==map.length,"Map");
        require(HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(map)).equals(
            "834938d18d2b7c688311c46c27bed813d0d7a9f8e3cbb61da8a6a3f23d360ebd"),"Hash");
        byte[] binary=Files.readAllBytes(out.resolve("resource-heap-free.bin")); codeSize=binary.length;
        textSize=Integer.parseInt(Files.readString(out.resolve("text-size.txt")).trim());
        require(textSize>0 && textSize<=codeSize && codeSize<0x2000,"Text extent");
        List<String> lines=Files.readAllLines(out.resolve("entries.txt")); require(lines.size()==4,"Entries");
        for(int i=0;i<4;i++) entries[i]=Long.parseLong(lines.get(i));
        for(long[] range:new long[][]{{FREE,FREE_END},{FREE_WRAPPER,0x2b33f8}}) {
            var function=getFunctionAt(toAddr(range[0]));
            require(function!=null && function.getBody().getMinAddress().getOffset()==range[0] &&
                function.getBody().getMaxAddress().getOffset()==range[1]-1,"Saved free boundary");
        }
        FreeMachine a=new FreeMachine(map,binary),b=new FreeMachine(map,binary);
        int[][] orders={{0,1,2,3},{3,2,1,0},{1,3,0,2},{2,0,3,1},{0,2,1,3},{3,1,2,0}};
        try(PrintWriter log=new PrintWriter(Files.newBufferedWriter(out.resolve("results.tsv")))) {
            for(int address=0;address<2;address++) for(int align:new int[]{4,32,128})
            for(int dir=0;dir<2;dir++) for(int policy=0;policy<2;policy++) for(int split=0;split<2;split++)
            for(int clear=0;clear<2;clear++) for(int order=0;order<orders.length;order++) {
                Arena state=new Arena(address,cases); state.addFree(0,2048,0);
                if(order%2==0) state.addFree(3,96,0);
                state.link(); state.set(state.lists-4,4,clear==0 ? 2 : 3);
                state.set(state.heap+0x54,4,new long[]{0,MASK,0x80000000L}[order%3]);
                a.seed(state); b.seed(state); scenarios++;
                long alignment=dir==0 ? align : u(-align); long[] live=new long[4];
                for(int i=0;i<4;i++) {
                    live[i]=allocate(a,b,state,new int[]{20,33,4,73}[i],alignment,policy,split,log);
                    require(live[i]!=0,"Fixture initial allocation");
                }
                require(allocate(a,b,state,8192,alignment,policy,split,log)==0,"Oversize must fail");
                for(int i=0;i<3;i++) compareFree(a,b,state,live[orders[order][i]],(order+i)%2==0,log);
                long reused=allocate(a,b,state,49,alignment,policy,split,log); require(reused!=0,"Reallocation"); reallocations++;
                compareFree(a,b,state,live[orders[order][3]],true,log);
                compareFree(a,b,state,reused,true,log);
                require(state.used.isEmpty(),"Drain used list");
                require(state.free.get(0)==state.node(0) && state.get(state.node(0)+4,4)==2048,"First extent restored");
                long whole=allocate(a,b,state,2048,4,policy,1,log); require(whole==state.node(0)+16,"Whole extent reuse"); reallocations++;
                compareFree(a,b,state,whole,true,log);
            }
            // Allocation-produced 16-byte extent: direct commit with rounded size
            // zero, an arithmetic boundary not asserted reachable in normal gameplay.
            for(int address=0;address<2;address++) for(int wrapper=0;wrapper<2;wrapper++) {
                Arena state=new Arena(address,cases); state.addFree(0,0,0); state.link();
                state.set(state.lists-4,4,0); state.set(state.lists+20,1,1); state.set(state.heap+0x54,4,0);
                a.seed(state); b.seed(state); Call c=new Call(); c.block=state.node(0); c.payload=c.block+16; c.size=0;
                compare(a,b,state,c,log); compareFree(a,b,state,c.payload,wrapper!=0,log);
            }
        }
        StringBuilder listing=new StringBuilder(); int freeInstructions=0;
        for(long[] range:new long[][]{{FREE,FREE_END},{FREE_WRAPPER,0x2b33f8}})
            for(long pc=range[0];pc<range[1];pc+=4) {
                require(visited.contains(pc),"Unvisited free instruction "+Long.toHexString(pc));
                var ins=currentProgram.getListing().getInstructionAt(toAddr(pc)); require(ins!=null,"Missing instruction");
                listing.append(String.format("%08x %s %s%n",pc,HexFormat.of().formatHex(ins.getBytes()),ins)); freeInstructions++;
            }
        for(int count:merges) require(count>0,"Missing merge topology");
        for(int count:usedPositions) require(count>0,"Missing used-list position");
        Files.writeString(out.resolve("original-ghidra.txt"),listing);
        Files.writeString(out.resolve("comparison.json"),String.format(Locale.ROOT,
            "{\"cases\":%d,\"allocation_calls\":%d,\"direct_frees\":%d,\"wrapper_frees\":%d,\"arena_scenarios\":%d,\"neither_merge\":%d,\"left_merge\":%d,\"right_merge\":%d,\"both_merge\":%d,\"used_singleton\":%d,\"used_head\":%d,\"used_tail\":%d,\"used_middle\":%d,\"counter_underflows\":%d,\"reallocations\":%d,\"minimum_extents\":%d,\"no_fit\":%d,\"free_instruction_addresses\":%d,\"all_instruction_addresses\":%d,\"external_reads_both_paths\":%d,\"external_writes_both_paths\":%d,\"max_steps\":%d,\"modeled_calls\":0,\"live_verified\":false}\n",
            cases,directCases+integratedCases,directFrees,wrapperFrees,scenarios,merges[0],merges[1],merges[2],merges[3],
            usedPositions[0],usedPositions[1],usedPositions[2],usedPositions[3],underflows,reallocations,minimumExtents,noFit,
            freeInstructions,visited.size(),reads,writes,maxSteps));
        println("SMT4_HEAP_FREE_COMPARE_OK "+cases);
    }
}
