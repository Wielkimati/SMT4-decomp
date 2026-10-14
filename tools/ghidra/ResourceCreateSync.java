// Bounded execution of constructor synchronization/result source. Kernel and
// diagnostic/break outcomes are models; no wrapper output is written by a model.
import java.nio.file.*;
import java.util.*;
import ghidra.program.model.listing.Program;

public class ResourceCreateSync {
    static final long ACQUIRE=0x2c4350, RELEASE=0x2c54a4, CHECK=0x2c54bc;
    static final long KERNEL=0x1ff80014, DEBUG=0x44e7a8, DIAGNOSTIC=0x1284a8, BREAK=0x2bce9c;
    static final long[] START={ACQUIRE,RELEASE,CHECK}, END={0x2c4374,0x2c54bc,0x2c5524};
    final CompareResourceLifecycle owner;
    final ResourceResultDiagnostic diagnostic;
    final long[] entries=new long[3];
    final Set<Long> visited=new TreeSet<>();
    final List<String> trace=new ArrayList<>();
    boolean active,svcSeen;
    long kind,output,stackTop;
    int stores,flagReads,directPairs,acquires,releases,checks,diagnostics,breaks,maxSteps;
    ResourceCreateSync(CompareResourceLifecycle owner,Path out,Program program) throws Exception {
        this.owner=owner;
        diagnostic=Files.exists(out.resolve("result-diagnostic-entry.txt"))?new ResourceResultDiagnostic(owner,out,program):null;
        var lines=Files.readAllLines(out.resolve("sync-entries.txt"));
        owner.require(lines.size()==3,"Sync entries");
        StringBuilder membership=new StringBuilder();
        for(int i=0;i<3;i++) {
            entries[i]=Long.parseLong(lines.get(i));
            owner.require(CompareResourceLifecycle.within(entries[i],4,CompareResourceLifecycle.BUILD,
                CompareResourceLifecycle.BUILD+owner.codeSize),"Sync entry extent");
            var f=program.getFunctionManager().getFunctionAt(program.getAddressFactory().getDefaultAddressSpace().getAddress(START[i]));
            membership.append(Long.toHexString(START[i])).append(" ").append(f==null?"missing":f.getBody()).append("\n");
            Files.writeString(out.resolve("sync-membership.txt"),membership.toString());
            owner.require(f!=null && f.getBody().getNumAddresses()==END[i]-START[i] &&
                f.getBody().getMinAddress().getOffset()==START[i] &&
                f.getBody().getMaxAddress().getOffset()==END[i]-1,"Sync saved membership");
        }
    }
    long boundary(boolean rebuilt,long pc) {
        if(rebuilt)for(int i=0;i<3;i++)if(pc==entries[i])return START[i];
        return pc;
    }
    void setup(CompareResourceLifecycle.Machine m,long seed) {
        int[] flags={0,1,2,0x80,0xff};
        m.memory(KERNEL,new byte[]{(byte)flags[(int)(seed%5)]});
        m.memory(DEBUG,new byte[]{(byte)flags[(int)((seed/5)%5)]});
    }
    boolean read(long a,int size) {
        if(diagnostic!=null && diagnostic.read(a,size))return true;
        if(!active)return false;
        if(a==KERNEL || a==DEBUG) {
            owner.require(kind==CHECK && size==1 && a==(flagReads==0?KERNEL:DEBUG) && flagReads<2,"Result flag read width/order");
            flagReads++;trace.add("R:"+Long.toHexString(a)+":1");return true;
        }
        owner.require(CompareResourceLifecycle.within(a,size,CompareResourceLifecycle.STACK-0x1000,stackTop+8) ||
            CompareResourceLifecycle.within(a,size,CompareResourceLifecycle.BUILD,CompareResourceLifecycle.BUILD+owner.codeSize) ||
            (size==4 && (a==0x2c5524 || a==0x2c5528)),"Sync unexpected data read "+Long.toHexString(a));
        return true;
    }
    boolean write(long a,int size,long value) {
        if(diagnostic!=null && diagnostic.write(a,size,value))return true;
        if(!active)return false;
        if(kind!=CHECK && a==output) {
            owner.require(svcSeen && size==4 && ++stores==1,"SVC output store width/order");
            trace.add("W:output:4:"+Long.toHexString(value));return true;
        }
        owner.require(CompareResourceLifecycle.within(a,size,CompareResourceLifecycle.STACK-0x1000,stackTop),"Sync unexpected store");
        return true;
    }
    void jump(CompareResourceLifecycle.Machine m,long pc) {
        m.thread.overrideCounter(m.thread.getCounter().getAddressSpace().getAddress(pc));
    }
    void modelReturn(CompareResourceLifecycle.Machine m,long result,long payload) {
        long lr=m.register("lr");
        m.register("r0",result);m.register("r1",0xa1b2c3d4L);m.register("r2",payload);
        m.register("r3",0xd3d3d3d3L);m.register("r12",0xdcdcdcdcL);m.register("cpsr",0xa0000010L);
        jump(m,lr);
    }
    void execute(CompareResourceLifecycle.Machine m,boolean rebuilt,long call,long svcResult,long svcOutput) throws Exception {
        owner.require(!active,"Nested sync");kind=call;output=m.register("r0");
        long ret=m.register("lr"),sp=m.register("sp"),arg1=m.register("r1"),arg2=m.register("r2"),arg3=m.register("r3");
        stackTop=sp;long[] saved=new long[8];for(int r=4;r<=11;r++)saved[r-4]=m.register("r"+r);
        long low=0,high=0;if(kind==ACQUIRE){low=CompareResourceLifecycle.word(m.memory(sp,8),0);high=CompareResourceLifecycle.word(m.memory(sp,8),4);}
        int enabled=(m.memory(KERNEL,1)[0]&1)|m.memory(DEBUG,1)[0];
        int classification=((int)output)>>27;
        boolean diag=kind==CHECK && (enabled!=0?(classification!=-7 && classification!=1):classification==-1);
        boolean brk=kind==CHECK && enabled==0;
        trace.clear();stores=0;flagReads=0;svcSeen=false;active=true;int steps=0,dc=0,bc=0;
        if(kind==ACQUIRE)acquires++;else if(kind==RELEASE)releases++;else checks++;
        while(m.thread.getCounter().getOffset()!=ret) {
            long pc=m.thread.getCounter().getOffset();
            if(pc==(rebuilt && diagnostic!=null?diagnostic.entry:DIAGNOSTIC)) {
                owner.require(diag && dc++==0 && bc==0 && flagReads==2,"Diagnostic order");
                owner.require(m.register("r0")==output && m.register("r1")==0 && m.register("r2")==ret,"Diagnostic result/caller transport");
                owner.require((m.register("sp")&7)==0,"Diagnostic ABI alignment");
                trace.add("diagnostic:result:"+Long.toHexString(output)+":caller");diagnostics++;
                if(diagnostic==null)modelReturn(m,0x8badf00dL,0x9abcdef0L);
                else {
                    diagnostic.delivery.variant=0;
                    diagnostic.execute(m,rebuilt,0x8badf00dL,0x9abcdef0L);
                    trace.addAll(diagnostic.trace);
                }
                continue;
            }
            if(pc==BREAK) {
                owner.require(brk && bc++==0 && dc==(diag?1:0) && flagReads==2,"Break order");
                // Existing recovered zero-reason entry ignores r0/r1, consumes r2.
                owner.require(m.register("r2")== (diag?0x9abcdef0L:0),"Break r2 transport");
                owner.require((m.register("sp")&7)==0,"Break ABI alignment");
                trace.add("break:payload:"+Long.toHexString(m.register("r2")));breaks++;
                modelReturn(m,0x87654321L,0xfacefeedL);continue;
            }
            int index=kind==ACQUIRE?0:kind==RELEASE?1:2;
            owner.require(rebuilt?CompareResourceLifecycle.within(pc,4,CompareResourceLifecycle.BUILD,CompareResourceLifecycle.BUILD+owner.codeSize):
                CompareResourceLifecycle.within(pc,4,START[index],END[index]),"Sync PC "+Long.toHexString(pc));
            owner.require(++steps<=128,"Sync budget");
            if(!rebuilt){visited.add(pc);owner.visited.add(pc);}
            long opcode=CompareResourceLifecycle.word(m.memory(pc,4),0);
            if(opcode==0xef000025L || opcode==0xef000016L) {
                owner.require(!svcSeen && opcode==(kind==ACQUIRE?0xef000025L:0xef000016L),"SVC selection/count");
                owner.require(m.register("r1")==arg1,"SVC r1");
                if(kind==ACQUIRE)owner.require(m.register("r0")==low && m.register("r2")==arg2 &&
                    m.register("r3")==arg3 && m.register("r4")==high,"SVC timeout/count/mode marshalling");
                else owner.require(m.register("r0")==output,"Release SVC r0 pointer");
                trace.add(kind==ACQUIRE?"svc:25":"svc:16");svcSeen=true;
                m.register("r0",svcResult);m.register("r1",svcOutput);
                m.register("r2",0xc2c2c2c2L);m.register("r3",0xc3c3c3c3L);m.register("r12",0xccccccccL);
                if(kind==ACQUIRE)m.register("r4",0xc4c4c4c4L);
                m.register("cpsr",0x60000010L);jump(m,pc+4);
            } else m.thread.stepInstruction();
        }
        active=false;
        owner.require(m.register("sp")==sp,"Sync SP restoration");
        for(int r=4;r<=11;r++)owner.require(m.register("r"+r)==saved[r-4],"Sync callee saved");
        if(kind!=CHECK) {
            owner.require(svcSeen && stores==1 && flagReads==0,"Sync output publication");
            owner.require(CompareResourceLifecycle.word(m.memory(output,4),0)==svcOutput && m.register("r0")==svcResult,"SVC output/result");
        } else {
            owner.require(flagReads==2 && dc==(diag?1:0) && bc==(brk?1:0) && stores==0,"Result dispatch branch effects");
            owner.require(m.register("r0")== (brk?0x87654321L:diag?0x8badf00dL:output),"Result dispatch return");
        }
        maxSteps=Math.max(maxSteps,steps);
    }
    void evidence(Path out,boolean direct) throws Exception {
        if(diagnostic!=null)diagnostic.evidence(out,direct);
        for(int i=0;i<3;i++)for(long pc=START[i];pc<END[i];pc+=4)
            // Constructor errors never have either enabled skip class (-7 or 1).
            if(direct || pc!=0x2c5520)owner.require(visited.contains(pc),"Unvisited sync site "+Long.toHexString(pc));
        Files.writeString(out.resolve("sync-comparison.json"),String.format(Locale.ROOT,
            "{\"direct_pairs\":%d,\"acquire_calls_both_paths\":%d,\"release_calls_both_paths\":%d,\"result_calls_both_paths\":%d,\"diagnostic_models\":%d,\"break_models\":%d,\"original_sync_sites\":%d,\"max_sync_steps\":%d,\"svc_marshalling_checked\":true,\"failure_publication_checked\":true,\"caller_r2_transport_checked\":true,\"flag_read_order_checked\":true,\"live_verified\":false}\n",
            directPairs,acquires,releases,checks,diagnostic==null?diagnostics:0,breaks,visited.size(),maxSteps));
    }
}
