// Delivery return extension. Reuses original/rebuilt IPC/copy/connect/delay;
// lower lock/wait and kernel outcomes are explicit fixtures, never game source.
import java.nio.file.*;
import java.util.*;
import ghidra.program.model.listing.Program;

public class ResourceDiagnosticDelivery {
    static final long START=0x2ad7e8, END=0x2ad8f0, RECORD=0x4d4200;
    static final long HANDLE=0x44e608, CONSTANTS=0x407f9c, LOCK=0x4d4280, TLS=0x980000;
    static final long ACQUIRE=0x2c3afc, RELEASE=0x2c3a78, INIT=0x2c5470, WAIT=0x2c367c, SLEEP=0x1382e4;
    static final long[][] RANGES={{START,END},{0x1382cc,0x1382e4},{0x144900,0x144918},
        {0x138f44,0x138f5c},{0x2c5470,0x2c54a4},{0x2c367c,0x2c373c},{0x2a88fc,0x2a8914},{0x146964,0x14699c},{0x2bcfac,0x2bd020},{0x2bb4f0,0x2bb518}};
    final CompareResourceLifecycle owner;
    final long entry,initEntry,waitEntry;
    long exclusiveAddress;int exclusiveFailures,exclusiveAttempts,arbitrations,initializations;
    final Set<Long> visited=new TreeSet<>();
    final List<String> trace=new ArrayList<>();
    boolean active;
    long top;
    int variant,calls,maxSteps,retries,directReturns,waitReturns;
    long returnedResult,returnedPayload;
    ResourceDiagnosticDelivery(CompareResourceLifecycle owner,Path out,Program program) throws Exception {
        this.owner=owner;var waitEntries=Files.readAllLines(out.resolve("wait-entries.txt"));initEntry=Long.parseLong(waitEntries.get(0));waitEntry=Long.parseLong(waitEntries.get(1));entry=Long.parseLong(Files.readString(out.resolve("delivery-entry.txt")).trim());
        var f=program.getFunctionManager().getFunctionAt(program.getAddressFactory().getDefaultAddressSpace().getAddress(START));
        Files.writeString(out.resolve("delivery-membership.txt"),f==null?"missing":f.getBody()+"\n");
        owner.require(f!=null && f.getBody().getMinAddress().getOffset()==START &&
            f.getBody().getMaxAddress().getOffset()==END-1,"Delivery membership");
    }
    boolean exclusive(CompareResourceLifecycle.Machine m,ghidra.pcode.emu.PcodeThread<byte[]> t,
            ghidra.program.model.pcode.PcodeOp op,String name) {
        if(!active || !name.equals("hasExclusiveAccess"))return false;
        long address=ghidra.pcode.utils.Utils.bytesToLong(t.getState().getVar(op.getInput(1),ghidra.pcode.exec.PcodeExecutorStatePiece.Reason.INSPECT),4,false);
        owner.require(address==exclusiveAddress && exclusiveAddress!=0,"Delivery exclusive reservation");
        boolean success=exclusiveFailures==0;if(!success)exclusiveFailures--;exclusiveAttempts++;
        trace.add("exclusive:"+(success?1:0));exclusiveAddress=0;
        t.getState().setVar(op.getOutput(),m.machine.getArithmetic().fromConst(success?1:0,op.getOutput().getSize()));return true;
    }
    boolean read(long a,int n) {
        if(!active)return false;
        owner.require(CompareResourceLifecycle.within(a,n,CompareResourceLifecycle.STACK-0x1000,top) ||
            CompareResourceLifecycle.within(a,n,CompareResourceLifecycle.BUILD,CompareResourceLifecycle.BUILD+owner.codeSize) ||
            CompareResourceLifecycle.within(a,n,0x100000,0x477000) ||
            CompareResourceLifecycle.within(a,n,RECORD-16,RECORD+144) ||
            CompareResourceLifecycle.within(a,n,TLS,TLS+256),"Delivery read extent "+Long.toHexString(a));return true;
    }
    boolean write(long a,int n,long value) {
        if(!active)return false;
        if(CompareResourceLifecycle.within(a,n,CompareResourceLifecycle.STACK-0x1000,top))return true;
        owner.require(CompareResourceLifecycle.within(a,n,RECORD+12,RECORD+16) ||
            CompareResourceLifecycle.within(a,n,HANDLE,HANDLE+4) ||
            CompareResourceLifecycle.within(a,n,TLS+128,TLS+260),"Delivery store extent");
        // Normalize individual bytes; copy's original batching differs from GCC.
        for(int i=0;i<n;i++)trace.add("W:"+Long.toHexString(a+i)+":"+((value>>>(i*8))&255));
        return true;
    }
    long get(CompareResourceLifecycle.Machine m,long a){return CompareResourceLifecycle.word(m.memory(a,4),0);}
    void jump(CompareResourceLifecycle.Machine m,long pc){m.thread.overrideCounter(m.thread.getCounter().getAddressSpace().getAddress(pc));}
    void outcome(CompareResourceLifecycle.Machine m,long result,long payload,long pc){
        m.register("r0",result);m.register("r1",0xa1b2c3d4L);m.register("r2",payload);
        m.register("r3",0xd3d3d3d3L);m.register("r12",0xdcdcdcdcL);m.register("cpsr",0xa0000010L);jump(m,pc);
    }
    void execute(CompareResourceLifecycle.Machine m,boolean rebuilt,long result,long payload) throws Exception {
        owner.require(!active,"Nested delivery");active=true;trace.clear();calls++;
        long ret=m.register("lr");top=m.register("sp");long[] saved=new long[8];
        for(int r=4;r<=11;r++)saved[r-4]=m.register("r"+r);
        byte[] before=m.memory(RECORD-16,160),expected=before.clone();
        int type=before[16]&255,mode=variant%10;
        // 0 cached handle, 1 successful connect, 2 failure, 3/4 finite retry,
        // 5 failed connect publishes handle, 6/7 post-release type mutation,
        // 8/9 process/request handle mutation. Earlier worker corpus covers
        // every retry-status bit and all protocol result signs independently.
        long handle=mode==0 || mode>=6?0x81234567L:0;
        m.writeWord(HANDLE,handle);m.memory(TLS,new byte[272]);
        int connects=0,locks=0,unlocks=0,processes=0,requests=0,closes=0,sleeps=0,waits=0;
        long waitPointer=0,processValue=result^payload;
        int steps=0;boolean delayed=false;exclusiveAddress=0;exclusiveFailures=variant%3;
        m.writeWord(0x471b58,0x89abcdefL);
        while(m.thread.getCounter().getOffset()!=ret){
            long pc=m.thread.getCounter().getOffset(),r0=m.register("r0"),r1=m.register("r1");
            if(pc==(rebuilt?initEntry:INIT)){
                owner.require(type!=2 && type!=5 && locks==unlocks && r1==1 && get(m,r0)==0 && get(m,r0+4)==0,"Delivery wait initialization");
                waitPointer=r0;initializations++;trace.add("initialize");
            }
            if(pc==(rebuilt?waitEntry:WAIT)){
                owner.require(r0==waitPointer && get(m,r0)==0xfffffffeL && get(m,r0+4)==1,"Delivery wait object");waits++;trace.add("wait");
            }
            if(pc==ACQUIRE || pc==RELEASE || pc==SLEEP){
                owner.require((m.register("sp")&7)==0,"Delivery lower-call alignment");
                if(pc==ACQUIRE){owner.require(r0==LOCK && locks==unlocks,"Delivery acquire order");locks++;}
                if(pc==RELEASE){
                    owner.require(r0==LOCK && locks==unlocks+1,"Delivery release order");unlocks++;
                    if(mode==6 || mode==7){type=mode==6?5:0;expected[16]=(byte)type;m.memory(RECORD,new byte[]{(byte)type});}
                    expected[16+63]=(byte)(payload^unlocks);m.memory(RECORD+63,new byte[]{expected[79]});
                    if(delayed){retries++;delayed=false;}
                }
                if(pc==SLEEP){owner.require(r0==5000000 && r1==0 && locks==unlocks+1,"Delivery retry delay");sleeps++;delayed=true;}
                trace.add("call:"+Long.toHexString(pc));
                long p=pc==WAIT?payload:pc==RELEASE?payload^0x55555555L^unlocks:0xc2c2c2c2L;
                outcome(m,pc==WAIT?result:0x12344321,p,m.register("lr"));continue;
            }
            boolean valid=rebuilt?CompareResourceLifecycle.within(pc,4,CompareResourceLifecycle.BUILD,CompareResourceLifecycle.BUILD+owner.codeSize):false;
            if(!rebuilt)for(long[] range:RANGES)valid|=CompareResourceLifecycle.within(pc,4,range[0],range[1]);
            owner.require(valid,"Delivery PC "+Long.toHexString(pc));owner.require(++steps<2500,"Delivery bounded budget");
            if(!rebuilt)visited.add(pc); // separate evidence; do not inflate caller-site counts
            long op=get(m,pc);
            if((op&0x0ff00fffL)==0x01900f9fL){
                owner.require(exclusiveAddress==0,"Delivery overlapping reservation");
                exclusiveAddress=m.register("r"+((op>>>16)&15));
                owner.require(exclusiveAddress==waitPointer || exclusiveAddress==waitPointer+4,"Delivery exclusive extent");
                trace.add("ldrex:"+(exclusiveAddress-waitPointer)+":"+get(m,exclusiveAddress));
            }
            if((op&0x0ff00ff0L)==0x01800f90L){
                long address=m.register("r"+((op>>>16)&15)),value=m.register("r"+(op&15));
                owner.require(address==exclusiveAddress && value==(address==waitPointer?0xfffffffeL:1),"Delivery initializer store/order");
                if(address==waitPointer)owner.require(get(m,waitPointer+4)==1,"Delivery base initialized first");
            }
            if((op&0xffff0fffL)==0xee1d0f70L){m.register("r"+((op>>>12)&15),TLS);jump(m,pc+4);continue;}
            if(!rebuilt && (pc==0x2bcfbc || pc==0x2bcfd4)){jump(m,pc+4);continue;} // PLD cache hints
            if((op&0xff000000L)==0xef000000L){
                int svc=(int)(op&255);long status=0xffffffffL,value=0xc1c1c1c1L;
                if(svc==0x22){
                    owner.require(r0==get(m,0x471b58) && r1==waitPointer && m.register("r2")==1 && m.register("r3")==0 && m.register("r4")==0 && m.register("r5")==0,"Delivery arbitration arguments");
                    owner.require(get(m,waitPointer)==0xfffffffeL && get(m,waitPointer+4)==1 && exclusiveAddress==0,"Delivery arbitration state");
                    arbitrations++;trace.add("arbitrate:"+result+":"+payload);
                    outcome(m,result,payload,pc+4);m.register("r4",0x44444444);m.register("r5",0x55555555);continue;
                }else if(svc==0x2d){
                    owner.require(r0==HANDLE && r1==get(m,CONSTANTS+8),"Delivery connect args");
                    owner.require(Arrays.equals(m.memory(r1,6),new byte[]{'e','r','r',':','f',0}),"Delivery port name");
                    connects++;status=mode==2?0x80000000L:(mode==3 || mode==4 || mode==5)&&connects<=2?0xd0401834L:1;
                    value=mode==3 || mode==4?0:0x87654321L;
                }else if(svc==0x35){
                    owner.require(r0==RECORD+12 && r1==get(m,CONSTANTS),"Delivery process args");processes++;
                    value=processValue;CompareResourceLifecycle.put(expected,28,value);
                    if(mode==8){handle=0x8abc1234L;m.writeWord(HANDLE,handle);}
                }else if(svc==0x32){
                    owner.require(r0==get(m,HANDLE) && get(m,TLS+128)==0x10800,"Delivery IPC handle/header");
                    owner.require(Arrays.equals(m.memory(TLS+132,128),Arrays.copyOfRange(expected,16,144)),"Delivery IPC record");requests++;
                    if(mode==9)m.writeWord(HANDLE,0);else if(mode==8)m.writeWord(HANDLE,0xfedcba98L);
                    status=(variant&1)==0?0:0x80000001L;m.writeWord(TLS+132,0xdeadbeefL);
                }else if(svc==0x23){owner.require(r0!=0 && r0==get(m,HANDLE),"Delivery close reloaded handle");closes++;m.writeWord(HANDLE,0x77778888);}
                else throw new IllegalStateException("Unexpected delivery SVC");
                trace.add("svc:"+svc+":"+Long.toHexString(status)+":"+Long.toHexString(value));
                outcome(m,status,0xc2c2c2c2L,pc+4);m.register("r1",value);continue;
            }
            m.thread.stepInstruction();
        }
        active=false;
        boolean direct=type==2 || type==5;
        long expectedResult=direct?type:result,expectedPayload=direct?payload^0x55555555L^unlocks:payload;
        returnedResult=expectedResult;returnedPayload=expectedPayload;
        owner.require(m.register("r0")==expectedResult && m.register("r2")==expectedPayload,"Delivery returned r0/r2");
        owner.require(locks==unlocks && locks>=1 && processes==requests && waits==(direct?0:1),"Delivery completed event counts");
        int originalType=before[16]&255;
        int expectedSleeps=(originalType==2 && (mode==3 || mode==4))?2:(originalType==2 && mode==5)?1:0;
        owner.require(sleeps==expectedSleeps && locks==sleeps+1,"Delivery finite retry count");
        boolean sent=mode!=2 && !((mode==3 || mode==4 || mode==5) && originalType!=2);
        owner.require(requests==(sent?1:0) && closes==(sent && mode!=9 && mode!=3 && mode!=4?1:0),"Delivery IPC/close route");
        owner.require(get(m,HANDLE)==(closes>0?get(m,CONSTANTS+4):!sent && mode!=3 && mode!=4?0x87654321L:0),"Delivery final handle/publication");
        owner.require(Arrays.equals(m.memory(RECORD-16,160),expected),"Delivery record mutations/guards");
        owner.require(m.register("sp")==top,"Delivery restored SP");
        for(int r=4;r<=11;r++)owner.require(m.register("r"+r)==saved[r-4],"Delivery callee saved");
        if(direct)directReturns++;else waitReturns++;maxSteps=Math.max(maxSteps,steps);
    }
    void evidence(Path out) throws Exception {
        int deliverySites=0;
        for(long pc=START;pc<END;pc+=4)if(visited.contains(pc))deliverySites++;
        // Chain has only type-zero cached-handle failures; direct producer corpus
        // covers all delivery sites, including retry and direct-return paths.
        if(directReturns>0)owner.require(deliverySites==66,"Delivery complete instruction visitation");
        owner.require(initializations==waitReturns && arbitrations==waitReturns,"Connected wait/init counts");
        Files.writeString(out.resolve("wait-return-connected.json"),String.format(Locale.ROOT,
            "{\"initializations_both\":%d,\"arbitrations_both\":%d,\"exclusive_attempts_both\":%d,\"r0_r2_checked\":true,\"wait_initializer_models_removed\":true}\n",initializations,arbitrations,exclusiveAttempts));
        Files.writeString(out.resolve("delivery-visited.txt"),String.join("\n",visited.stream().map(Long::toHexString).toList()));
        Files.writeString(out.resolve("delivery-comparison.json"),String.format(Locale.ROOT,
            "{\"calls_both_paths\":%d,\"original_sites\":%d,\"delivery_sites\":%d,\"max_steps\":%d,\"retry_iterations_both\":%d,\"direct_returns_both\":%d,\"wait_returns_both\":%d,\"r0_r2_checked\":true,\"ipc_record_checked\":true,\"abi_guards_checked\":true,\"lower_locks_kernel_modeled\":true,\"live_verified\":false}\n",
            calls,visited.size(),deliverySites,maxSteps,retries,directReturns,waitReturns));
    }
}
