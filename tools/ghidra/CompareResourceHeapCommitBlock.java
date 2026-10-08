// Arena-backed allocation mutation and connected selection/wrapper execution.
// No dependency interception or original code on the rebuilt path.
// @category SMT4
import ghidra.pcode.emu.PcodeThread;
import ghidra.pcode.utils.Utils;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.pcode.PcodeOp;
import java.nio.file.*;
import java.security.MessageDigest;
import java.util.*;
import java.io.*;

public class CompareResourceHeapCommitBlock extends CompareResourceSync {
    static final long COMMIT=0x14f608, END_COMMIT=0x14f7e4, WRAPPER=0x2c3a98;
    static final long MASK=0xffffffffL;
    int cases,directCases,integratedCases,scenarios,textSize,noFit,prefixSplits,suffixSplits;
    int absorbedPrefixes,absorbedSuffixes,cleared,clearWords,counterWraps,repeatSuccess;
    long reads,writes;
    @Override boolean originalCode(long pc) {
        return within(pc,4,COMMIT,END_COMMIT) || within(pc,4,0x146ad8,0x146c20) ||
            within(pc,4,WRAPPER,0x2c3afc) || within(pc,4,0x146ce0,0x146d20);
    }
    static long u(long x) { return x&MASK; }
    static class Call {
        boolean integrated;
        long block,payload,size,direction,alignment,group,policy,split;
    }
    // Declarative byte oracle: replace the selected list element by residual
    // intervals, append its allocated header to the used list, then relink.
    // It does not reproduce the implementation's ordered load/store algorithm.
    class Arena {
        long heap,base,lists;
        byte[] head=new byte[128],data=new byte[0x1800];
        List<Long> free=new ArrayList<>(),used=new ArrayList<>();
        Arena(int address,int seed) {
            heap=address==0 ? 0x910000 : 0x89100000L;
            base=address==0 ? 0x920000 : 0x89200000L; lists=heap+0x3c;
            Random rng=new Random(0x14f608L+seed); rng.nextBytes(head); rng.nextBytes(data);
        }
        Arena(Arena a) {
            heap=a.heap; base=a.base; lists=a.lists; head=a.head.clone(); data=a.data.clone();
            free.addAll(a.free); used.addAll(a.used);
        }
        long node(int slot) { return base+0x100+slot*0x400; }
        byte[] bytes(long a,int n) {
            if(within(a,n,heap,heap+head.length)) return head;
            require(within(a,n,base,base+data.length),"Oracle outside arena"); return data;
        }
        int offset(long a) { return (int)(a>=base ? a-base : a-heap); }
        long get(long a,int n) {
            byte[] b=bytes(a,n); int off=offset(a); long v=0;
            for(int i=0;i<n;i++) v|=(b[off+i]&255L)<<(8*i); return v;
        }
        void set(long a,int n,long v) {
            byte[] b=bytes(a,n); int off=offset(a);
            for(int i=0;i<n;i++) b[off+i]=(byte)(v>>>(8*i));
        }
        void relink(List<Long> nodes,long roots) {
            set(roots,4,nodes.isEmpty() ? 0 : nodes.get(0));
            set(roots+4,4,nodes.isEmpty() ? 0 : nodes.get(nodes.size()-1));
            for(int i=0;i<nodes.size();i++) {
                set(nodes.get(i)+8,4,i==0 ? 0 : nodes.get(i-1));
                set(nodes.get(i)+12,4,i+1==nodes.size() ? 0 : nodes.get(i+1));
            }
        }
        void addFree(int slot,long capacity,int offset) {
            long n=node(slot); free.add(n); set(n,2,0x4652); set(n+2,2,0x80a5|(offset<<8)); set(n+4,4,capacity);
        }
        void addUsed(int count) {
            for(int i=0;i<count;i++) {
                long n=node(3+i); used.add(n); set(n,2,0x5544); set(n+2,2,0x8111+i); set(n+4,4,32);
            }
        }
        void link() { relink(free,lists); relink(used,lists+8); }
        long evaluate(Call c) {
            long block=c.block,payload=c.payload,size=c.size,dir=c.direction;
            if(c.integrated) {
                set(lists+16,2,c.group); set(lists+18,2,(get(lists+18,2)&0xfffe)|(c.policy&1));
                set(lists+20,1,c.split);
                size=(size==0 ? 4 : size+3)&~3L;
                dir=c.alignment>>>31; long best=MASK; block=0;
                List<Long> order=new ArrayList<>(free); if(dir!=0) Collections.reverse(order);
                for(long n:order) {
                    long cap=get(n+4,4),start=n+16;
                    long magnitude=dir==0 ? c.alignment : u(-c.alignment);
                    long candidate=dir==0 ? (start+magnitude-1)&-magnitude : (start+cap-size)&-magnitude;
                    boolean fit=dir==0 ? candidate+size<=start+cap : candidate>=start;
                    if(fit && cap<best) {
                        best=cap; block=n; payload=candidate;
                        if((c.policy&1)==0 || cap==size) break;
                    }
                }
                if(block==0) { noFit++; return 0; }
            }
            int index=free.indexOf(block); require(index>=0,"Oracle selected membership");
            long origin=block-((get(block+2,2)>>>8)&127),end=block+16+get(block+4,4);
            long header=payload-16,requestedEnd=payload+size;
            require(origin<=header && requestedEnd<=end,"Invalid bounded allocation");
            boolean prefix=header-origin>=20 && (dir!=0 || get(lists+20,1)!=0);
            boolean suffix=end-requestedEnd>=20 && (dir!=1 || get(lists+20,1)!=0);
            long start=prefix ? header : origin,stop=suffix ? requestedEnd : end;
            free.remove(index);
            if(prefix) {
                free.add(index++,origin); set(origin,2,0x4652); set(origin+2,2,0); set(origin+4,4,header-origin-16);
                prefixSplits++;
            } else if(header!=origin) absorbedPrefixes++;
            if(suffix) {
                free.add(index,requestedEnd); set(requestedEnd,2,0x4652); set(requestedEnd+2,2,0); set(requestedEnd+4,4,end-requestedEnd-16);
                suffixSplits++;
            } else if(end!=requestedEnd) absorbedSuffixes++;
            if((get(lists-4,4)&1)!=0) {
                for(long a=start;a+4<=stop;a+=4) { set(a,4,0); clearWords++; }
                cleared++;
            }
            set(header,2,0x5544); set(header+2,2,((dir&1)<<15)|(((header-start)&127)<<8)|(get(lists+16,2)&255));
            set(header+4,4,stop-payload); used.add(header); link();
            if(c.integrated) {
                long count=u(get(heap+0x54,4)+1); set(heap+0x54,4,count); if(count==0) counterWraps++;
            }
            return payload;
        }
    }
    class CommitMachine extends SyncMachine {
        Arena arena;
        List<String> trace=new ArrayList<>();
        CommitMachine(byte[] map,byte[] binary) { super(map,binary); }
        boolean data(long a,int n) {
            return within(a,n,arena.heap,arena.heap+arena.head.length) || within(a,n,arena.base,arena.base+arena.data.length);
        }
        @Override public void beforeLoad(PcodeThread<byte[]> t,PcodeOp op,AddressSpace space,byte[] offset,int n) {
            long a=Utils.bytesToLong(offset,offset.length,false);
            if(within(a,n,STACK-256,STACK+8) || within(a,n,BUILD,BUILD+codeSize) || within(a,n,0x14f7e4,0x14f7ec)) return;
            require(data(a,n),"Read outside arena "+Long.toHexString(a));
            trace.add("R:"+Long.toHexString(a)+":"+n); reads++;
        }
        @Override public void beforeStore(PcodeThread<byte[]> t,PcodeOp op,AddressSpace space,byte[] offset,int n,byte[] value) {
            long a=Utils.bytesToLong(offset,offset.length,false);
            if(within(a,n,STACK-256,STACK)) return;
            require(data(a,n),"Write outside arena "+Long.toHexString(a));
            trace.add("W:"+Long.toHexString(a)+":"+n+":"+Long.toHexString(Utils.bytesToLong(value,n,false))); CompareResourceHeapCommitBlock.this.writes++;
        }
        void seed(Arena a) { executing=false; memory(a.heap,a.head); memory(a.base,a.data); }
        void call(boolean rebuiltPath,Call c,Arena initial,Arena expected,long result) throws Exception {
            arena=initial; initialize(rebuiltPath,0,new byte[0x144]); trace.clear();
            // Arena storage is retained from seed/prior call; initialize resets registers/stack only.
            byte[] caller=new byte[32]; new Random(cases).nextBytes(caller);
            put(caller,0,c.integrated ? c.policy : c.direction); put(caller,4,c.split); memory(STACK,caller);
            register("r0",c.integrated ? arena.heap : arena.lists);
            register("r1",c.integrated ? c.size : c.block);
            register("r2",c.integrated ? c.alignment : c.payload);
            register("r3",c.integrated ? c.group : c.size);
            for(int r=16;r<32;r++) register("s"+r,0x81234000L+r);
            thread.overrideCounter(toAddr(rebuiltPath ? entries[c.integrated ? 1 : 0] : c.integrated ? WRAPPER : COMMIT));
            executing=true; int steps=0;
            while(thread.getCounter().getOffset()!=RETURN) {
                long pc=thread.getCounter().getOffset();
                require(rebuiltPath ? within(pc,4,BUILD,BUILD+textSize) : originalCode(pc),"Unexpected execution "+Long.toHexString(pc));
                if(!rebuiltPath) visited.add(pc);
                require(++steps<5000,"Instruction budget"); monitor.checkCancelled(); thread.stepInstruction();
            }
            require(register("r0")==result,"Return");
            require(Arrays.equals(expected.head,memory(expected.heap,expected.head.length)),"Header bytes/guards");
            require(Arrays.equals(expected.data,memory(expected.base,expected.data.length)),"Arena bytes/guards");
            require(Arrays.equals(caller,memory(STACK,caller.length)),"Caller stack");
            byte[] stack=memory(STACK-0x1000,0x1000);
            for(int i=0;i<stack.length-256;i++) require(stack[i]==(byte)0x96,"Stack guard");
            for(int r=16;r<32;r++) require(register("s"+r)==0x81234000L+r,"Callee-saved VFP");
            finish(steps);
        }
    }
    void compare(CommitMachine a,CommitMachine b,Arena state,Call c,PrintWriter log) throws Exception {
        Arena before=new Arena(state); long result=state.evaluate(c);
        try {
            a.call(false,c,before,state,result); b.call(true,c,before,state,result);
            require(a.trace.equals(b.trace),"Ordered external access trace\noriginal="+a.trace+"\nrebuilt="+b.trace);
        } catch(Exception ex) { throw new IllegalStateException("Heap commit case "+cases+" integrated="+c.integrated,ex); }
        if(c.integrated) integratedCases++; else directCases++;
        log.printf("%d\t%b\t%x\t%x\t%x\t%x\t%d\t%d%n",cases++,c.integrated,c.size,c.alignment,c.direction,result,state.free.size(),state.used.size());
    }
    @Override public void run() throws Exception {
        Path out=Path.of(getScriptArgs()[0]); require(!Files.exists(out.resolve("comparison.json")),"Existing output");
        byte[] map=new byte[0x377000]; require(currentProgram.getMemory().getBytes(toAddr(0x100000),map)==map.length,"Map");
        require(HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(map)).equals(
            "834938d18d2b7c688311c46c27bed813d0d7a9f8e3cbb61da8a6a3f23d360ebd"),"Hash");
        byte[] binary=Files.readAllBytes(out.resolve("resource-heap-commit.bin")); codeSize=binary.length;
        textSize=Integer.parseInt(Files.readString(out.resolve("text-size.txt")).trim());
        require(textSize>0 && textSize<=codeSize && codeSize<0x2000,"Text extent");
        List<String> lines=Files.readAllLines(out.resolve("entries.txt")); require(lines.size()==2,"Entries");
        for(int i=0;i<2;i++) entries[i]=Long.parseLong(lines.get(i));
        var function=getFunctionAt(toAddr(COMMIT));
        require(function!=null && function.getBody().getMinAddress().getOffset()==COMMIT &&
            function.getBody().getMaxAddress().getOffset()==END_COMMIT-1,"Saved function boundary");
        CommitMachine a=new CommitMachine(map,binary),b=new CommitMachine(map,binary);
        try(PrintWriter log=new PrintWriter(Files.newBufferedWriter(out.resolve("results.tsv")))) {
            log.println("case\tintegrated\tsize\talignment\tdirection\tresult\tfree_nodes\tused_nodes");
            for(int address=0;address<2;address++) for(int topology=0;topology<4;topology++)
            for(int used=0;used<2;used++) for(int dir=0;dir<2;dir++) for(int split=0;split<2;split++)
            for(int clear=0;clear<2;clear++) for(int gap:new int[]{0,4,16,20,24,124,128,132})
            for(int suffix:new int[]{0,4,16,20,24,64}) {
                Arena state=new Arena(address,cases); int padding=new int[]{0,4,124}[(cases/6)%3];
                long size=new int[]{4,8,12,32}[cases%4];
                if((topology&1)!=0) state.addFree(0,48,0);
                state.addFree(1,gap+size+suffix,padding);
                if((topology&2)!=0) state.addFree(2,64,0);
                state.addUsed(used==0 ? 0 : 2); state.link();
                state.set(state.lists-4,4,clear==0 ? 0x80000002L : MASK);
                state.set(state.lists+16,2,new int[]{0,255,256,65535}[cases%4]);
                state.set(state.lists+20,1,split==0 ? 0 : new int[]{1,128,255}[cases%3]);
                Call c=new Call(); c.block=state.node(1); c.payload=c.block+16+gap; c.size=size; c.direction=dir;
                a.seed(state); b.seed(state); compare(a,b,state,c,log);
            }
            // Nonboolean direction words are direct-call observations, not selector outputs.
            for(long dir:new long[]{2,0x80000000L,MASK}) for(int offset:new int[]{0,4,124}) {
                Arena state=new Arena(0,cases); state.addFree(1,96,offset); state.addUsed(1); state.link();
                state.set(state.lists-4,4,1); state.set(state.lists+20,1,0);
                Call c=new Call(); c.block=state.node(1); c.payload=c.block+40; c.size=8; c.direction=dir;
                a.seed(state); b.seed(state); compare(a,b,state,c,log);
            }
            for(int address=0;address<2;address++) for(int align:new int[]{4,8,16,32,64,128})
            for(int dir=0;dir<2;dir++) for(int policy=0;policy<2;policy++) for(int split=0;split<2;split++)
            for(int clear=0;clear<2;clear++) for(int profile=0;profile<4;profile++) {
                Arena state=new Arena(address,cases); long[][] caps={{64,256,128},{128,128,128},{4,8,16},{}};
                for(int i=0;i<caps[profile].length;i++) state.addFree(i,caps[profile][i],0);
                state.addUsed(profile%2); state.link(); state.set(state.lists-4,4,clear==0 ? 2 : 3);
                state.set(state.heap+0x54,4,MASK); a.seed(state); b.seed(state); scenarios++;
                for(int step=0;step<6;step++) {
                    Call c=new Call(); c.integrated=true; c.size=new int[]{0,17,4,64,1,4096}[step];
                    c.alignment=dir==0 ? align : u(-align); c.policy=policy; c.split=split==0 ? 0 : 128;
                    c.group=new long[]{0,0x1234,0x100,0xffffffffL,0x80,255}[step];
                    int count=state.used.size(); compare(a,b,state,c,log);
                    if(step>0 && state.used.size()>count) repeatSuccess++;
                }
            }
        }
        StringBuilder listing=new StringBuilder(); int instructionCount=0;
        for(long[] range:new long[][]{{COMMIT,END_COMMIT},{0x146ad8,0x146c20},{WRAPPER,0x2c3afc},{0x146ce0,0x146d20}})
            for(long pc=range[0];pc<range[1];pc+=4) {
                require(visited.contains(pc),"Unvisited original "+Long.toHexString(pc));
                var ins=currentProgram.getListing().getInstructionAt(toAddr(pc)); require(ins!=null,"Missing instruction");
                listing.append(String.format("%08x %s %s%n",pc,HexFormat.of().formatHex(ins.getBytes()),ins)); instructionCount++;
            }
        Files.writeString(out.resolve("original-ghidra.txt"),listing);
        Files.writeString(out.resolve("comparison.json"),String.format(Locale.ROOT,
            "{\"cases\":%d,\"direct_cases\":%d,\"integrated_cases\":%d,\"retained_arena_scenarios\":%d,\"no_fit\":%d,\"prefix_splits\":%d,\"suffix_splits\":%d,\"absorbed_prefixes\":%d,\"absorbed_suffixes\":%d,\"cleared_allocations\":%d,\"cleared_words\":%d,\"counter_wraps\":%d,\"repeat_success\":%d,\"external_reads_both_paths\":%d,\"external_writes_both_paths\":%d,\"original_instruction_addresses\":%d,\"max_steps\":%d,\"modeled_calls\":0,\"live_verified\":false}\n",
            cases,directCases,integratedCases,scenarios,noFit,prefixSplits,suffixSplits,absorbedPrefixes,absorbedSuffixes,
            cleared,clearWords,counterWraps,repeatSuccess,reads,writes,instructionCount,maxSteps));
        println("SMT4_HEAP_COMMIT_COMPARE_OK "+cases);
    }
}
