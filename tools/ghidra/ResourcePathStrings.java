// Shared bounded execution support for the descriptor's concrete string calls.
import java.nio.file.*;
import java.util.*;
import ghidra.program.model.listing.Program;

public class ResourcePathStrings {
    static final long COPY=0x2bf8c0, LENGTH=0x2c32e4;
    final CompareResourceLifecycle owner;
    long copyEntry, lengthEntry, source, destination, stackTop;
    boolean active, copying;
    int next, directPairs, copyCalls, lengthCalls, uqsub8, maxSteps;
    final List<String> expected=new ArrayList<>(), trace=new ArrayList<>();
    final Set<Long> visited=new TreeSet<>();
    ResourcePathStrings(CompareResourceLifecycle owner,Path out,Program program) throws Exception {
        this.owner=owner;
        var entries=Files.readAllLines(out.resolve("string-entries.txt"));
        copyEntry=Long.parseLong(entries.get(0));lengthEntry=Long.parseLong(entries.get(1));
        owner.require(entries.size()==2,"String entries");
        for(long entry:new long[]{copyEntry,lengthEntry})
            owner.require(CompareResourceLifecycle.within(entry,4,CompareResourceLifecycle.BUILD,
                CompareResourceLifecycle.BUILD+owner.codeSize),"String entry extent");
        for(long[] range:new long[][]{{COPY,0x2bf924},{LENGTH,0x2c3340}}) {
            var f=program.getFunctionManager().getFunctionAt(program.getAddressFactory().getDefaultAddressSpace().getAddress(range[0]));
            owner.require(f!=null && f.getBody().getNumAddresses()==range[1]-range[0] &&
                f.getBody().getMinAddress().getOffset()==range[0] &&
                f.getBody().getMaxAddress().getOffset()==range[1]-1,"String saved membership");
        }
    }
    long boundary(boolean rebuilt,long pc) {
        if(rebuilt && pc==copyEntry)return COPY;
        if(rebuilt && pc==lengthEntry)return LENGTH;
        return pc;
    }
    void access(String operation,long address,int size) {
        String value=operation+":"+address+":"+size;
        owner.require(next<expected.size() && expected.get(next).equals(value),
            "String access width/order: "+value+" expected "+(next<expected.size()?expected.get(next):"end"));
        next++;trace.add(value);
    }
    void read(long address,int size) {
        if(!active)return;
        if(CompareResourceLifecycle.within(address,size,CompareResourceLifecycle.STACK-0x1000,stackTop))return;
        // Only the original length/copy literals are non-payload data reads.
        if((address==0x2bf924 || address==0x2c3340) && size==4)return;
        access("R",address,size);
    }
    void write(long address,int size) {
        if(!active)return;
        if(CompareResourceLifecycle.within(address,size,CompareResourceLifecycle.STACK-0x1000,stackTop))return;
        access("W",address,size);
    }
    int execute(CompareResourceLifecycle.Machine m,boolean rebuilt,long kind,byte[] bytes) throws Exception {
        owner.require(!active && (kind==COPY || kind==LENGTH),"String invocation");
        copying=kind==COPY;source=m.register(copying?"r1":"r0");destination=copying?m.register("r0"):0;
        long ret=m.register("lr"),sp=m.register("sp");stackTop=sp;long[] saved=new long[8];
        for(int r=4;r<=11;r++)saved[r-4]=m.register("r"+r);
        int length=bytes.length;
        owner.require(Arrays.equals(m.memory(source,length),bytes) && m.memory(source+length,1)[0]==0,"String fixture input");
        expected.clear();trace.clear();next=0;
        if(copying) {
            if(((source|destination)&3)==0) {
                int offset=0;
                while(offset+4<=length) {
                    expected.add("R:"+(source+offset)+":4");expected.add("W:"+(destination+offset)+":4");offset+=4;
                }
                expected.add("R:"+(source+offset)+":4");
                for(;offset<=length;offset++)expected.add("W:"+(destination+offset)+":1");
            } else for(int i=0;i<=length;i++) {
                expected.add("R:"+(source+i)+":1");expected.add("W:"+(destination+i)+":1");
            }
            copyCalls++;
        } else {
            int i=0;
            while(((source+i)&3)!=0 && i<=length)expected.add("R:"+(source+i++)+":1");
            for(;i<=length;i+=4)expected.add("R:"+(source+i)+":4");
            lengthCalls++;
        }
        int steps=0;active=true;
        while(m.thread.getCounter().getOffset()!=ret) {
            long pc=m.thread.getCounter().getOffset();
            owner.require(rebuilt?CompareResourceLifecycle.within(pc,4,CompareResourceLifecycle.BUILD,
                CompareResourceLifecycle.BUILD+owner.codeSize):CompareResourceLifecycle.within(pc,4,kind,copying?0x2bf924:0x2c3340),"String PC");
            owner.require(++steps<=8192,"String instruction budget");
            if(!rebuilt){visited.add(pc);owner.visited.add(pc);}
            if(!rebuilt && (pc==0x2bf8dc || pc==0x2c330c)) {
                boolean copy=pc==0x2bf8dc;
                owner.require(CompareResourceLifecycle.word(m.memory(pc,4),0)==(copy?0xe66ceff3L:0xe6621ff1L),"Pinned UQSUB8 encoding");
                long left=m.register(copy?"r12":"r2"),right=m.register(copy?"r3":"r1"),result=0;
                for(int shift=0;shift<32;shift+=8)
                    result|=(long)Math.max(0,((int)(left>>>shift)&255)-((int)(right>>>shift)&255))<<shift;
                m.register(copy?"lr":"r1",result);uqsub8++;
                m.thread.overrideCounter(m.thread.getCounter().add(4));
            } else m.thread.stepInstruction();
        }
        active=false;
        owner.require(next==expected.size(),"String incomplete access trace");
        owner.require(m.register("r0")==(copying?destination:length),"String exact return");
        owner.require(m.register("sp")==sp,"String SP restoration");
        for(int r=4;r<=11;r++)owner.require(saved[r-4]==m.register("r"+r),"String callee saved");
        owner.require(Arrays.equals(m.memory(source,length),bytes) && m.memory(source+length,1)[0]==0,"String input preservation");
        if(copying)owner.require(Arrays.equals(m.memory(destination,length),bytes) && m.memory(destination+length,1)[0]==0,"String copied payload/NUL");
        maxSteps=Math.max(maxSteps,steps);return steps;
    }
    void evidence(Path out,boolean direct) throws Exception {
        // Integrated callers are aligned; the direct corpus supplies the byte path.
        if(direct)for(long[] range:new long[][]{{COPY,0x2bf924},{LENGTH,0x2c3340}})
            for(long pc=range[0];pc<range[1];pc+=4)owner.require(visited.contains(pc),"Unvisited string site "+Long.toHexString(pc));
        if(!direct)for(long[] range:new long[][]{{COPY,0x2bf900},{LENGTH,0x2c32ec},{0x2c32fc,0x2c3340}})
            for(long pc=range[0];pc<range[1];pc+=4)owner.require(visited.contains(pc),"Unvisited aligned string site "+Long.toHexString(pc));
        Files.writeString(out.resolve("strings-comparison.json"),String.format(Locale.ROOT,
            "{\"direct_pairs\":%d,\"copy_calls_both_paths\":%d,\"length_calls_both_paths\":%d,\"ordered_accesses_checked\":true,\"original_string_sites\":%d,\"uqsub8_host_instructions\":%d,\"max_string_steps\":%d,\"new_contracts\":1,\"reused_length_contracts\":1,\"live_verified\":false}\n",
            directPairs,copyCalls,lengthCalls,visited.size(),uqsub8,maxSteps));
    }
}
