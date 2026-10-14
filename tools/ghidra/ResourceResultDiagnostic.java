// Producer and delivery recovery; lower lock/wait/kernel outcomes stay explicit.
import java.nio.file.*;
import java.util.*;
import ghidra.program.model.listing.Program;

public class ResourceResultDiagnostic {
    static final long START=0x1284a8, END=0x1284d8, DELIVERY=0x2ad7e8, RECORD=0x4d4200;
    final CompareResourceLifecycle owner;
    final long entry;
    final ResourceDiagnosticDelivery delivery;
    final Set<Long> visited=new TreeSet<>();
    final List<String> trace=new ArrayList<>();
    boolean active;
    long stackTop;
    int stores,calls,directPairs,maxSteps;
    long[] values;
    static final int[] OFFSETS={1,0,2,8,4}, WIDTHS={1,1,2,4,4};
    ResourceResultDiagnostic(CompareResourceLifecycle owner,Path out,Program program) throws Exception {
        this.owner=owner;
        delivery=new ResourceDiagnosticDelivery(owner,out,program);
        entry=Long.parseLong(Files.readString(out.resolve("result-diagnostic-entry.txt")).trim());
        owner.require(CompareResourceLifecycle.within(entry,4,CompareResourceLifecycle.BUILD,
            CompareResourceLifecycle.BUILD+owner.codeSize),"Diagnostic entry extent");
        var f=program.getFunctionManager().getFunctionAt(program.getAddressFactory().getDefaultAddressSpace().getAddress(START));
        Files.writeString(out.resolve("result-diagnostic-membership.txt"),f==null?"missing\n":f.getBody()+"\n");
        owner.require(f!=null && f.getBody().getNumAddresses()==END-START &&
            f.getBody().getMinAddress().getOffset()==START && f.getBody().getMaxAddress().getOffset()==END-1,
            "Diagnostic saved membership");
    }
    boolean read(long a,int size) {
        if(delivery.read(a,size))return true;
        if(!active)return false;
        owner.require(CompareResourceLifecycle.within(a,size,CompareResourceLifecycle.STACK-0x1000,stackTop) ||
            CompareResourceLifecycle.within(a,size,CompareResourceLifecycle.BUILD,CompareResourceLifecycle.BUILD+owner.codeSize) ||
            (size==4 && (a==END || a==END+4)),"Diagnostic unexpected read "+Long.toHexString(a));
        return true;
    }
    boolean write(long a,int size,long value) {
        if(delivery.write(a,size,value))return true;
        if(!active)return false;
        if(CompareResourceLifecycle.within(a,size,RECORD-16,RECORD+144)) {
            owner.require(stores<5 && a==RECORD+OFFSETS[stores] && size==WIDTHS[stores],"Diagnostic store width/order");
            owner.require(value==values[stores],"Diagnostic store value/type narrowing");
            trace.add("W:"+OFFSETS[stores]+":"+size+":"+Long.toHexString(value));stores++;
        } else owner.require(CompareResourceLifecycle.within(a,size,CompareResourceLifecycle.STACK-0x1000,stackTop),
            "Diagnostic unexpected store "+Long.toHexString(a));
        return true;
    }
    void execute(CompareResourceLifecycle.Machine m,boolean rebuilt,long outcome,long payload) throws Exception {
        owner.require(!active,"Nested diagnostic producer");
        long result=m.register("r0"),type=m.register("r1"),site=m.register("r2"),ret=m.register("lr");
        stackTop=m.register("sp");long[] saved=new long[8];for(int r=4;r<=11;r++)saved[r-4]=m.register("r"+r);
        byte[] expected=new byte[160];new Random(result^type^site).nextBytes(expected);m.memory(RECORD-16,expected);
        values=new long[]{0,type&255,0xbca3,site,result};
        for(int i=0;i<5;i++)for(int j=0;j<WIDTHS[i];j++)expected[16+OFFSETS[i]+j]=(byte)(values[i]>>>(j*8));
        trace.clear();stores=0;active=true;int steps=0,deliveries=0;
        while(m.thread.getCounter().getOffset()!=ret) {
            long pc=m.thread.getCounter().getOffset();
            if(pc==(rebuilt?delivery.entry:DELIVERY)) {
                owner.require(deliveries++==0 && stores==5,"Diagnostic delivery order");
                owner.require(m.register("r0")==RECORD,"Diagnostic delivery pointer");
                owner.require(m.register("lr")==ret && m.register("sp")==stackTop && (stackTop&7)==0,
                    "Diagnostic tail LR/SP");
                for(int r=4;r<=11;r++)owner.require(m.register("r"+r)==saved[r-4],"Diagnostic delivery callee saved");
                owner.require(Arrays.equals(m.memory(RECORD-16,160),expected),"Diagnostic record and unknown-byte guards");
                delivery.execute(m,rebuilt,outcome,payload);
                trace.addAll(delivery.trace);
                expected=m.memory(RECORD-16,160);
                outcome=delivery.returnedResult;payload=delivery.returnedPayload;
                continue;
            }
            owner.require(rebuilt?CompareResourceLifecycle.within(pc,4,CompareResourceLifecycle.BUILD,CompareResourceLifecycle.BUILD+owner.codeSize):
                CompareResourceLifecycle.within(pc,4,START,END),"Diagnostic PC "+Long.toHexString(pc));
            owner.require(++steps<=64,"Diagnostic budget");
            if(!rebuilt){visited.add(pc);owner.visited.add(pc);}
            m.thread.stepInstruction();
        }
        active=false;
        owner.require(deliveries==1 && stores==5,"Diagnostic delivery count");
        owner.require(m.register("r0")==outcome && m.register("r2")==payload,"Diagnostic returned r0/r2");
        owner.require(m.register("sp")==stackTop,"Diagnostic SP restoration");
        for(int r=4;r<=11;r++)owner.require(m.register("r"+r)==saved[r-4],"Diagnostic callee saved");
        owner.require(Arrays.equals(m.memory(RECORD-16,160),expected),"Diagnostic delivery mutations preserved");
        calls++;maxSteps=Math.max(maxSteps,steps);
    }
    void evidence(Path out,boolean direct) throws Exception {
        delivery.evidence(out);
        for(long pc=START;pc<END;pc+=4)owner.require(visited.contains(pc),"Unvisited diagnostic site");
        owner.require(directPairs==(direct?120:0),"Diagnostic direct corpus");
        Files.writeString(out.resolve("result-diagnostic-comparison.json"),String.format(Locale.ROOT,
            "{\"direct_pairs\":%d,\"calls_both_paths\":%d,\"original_sites\":%d,\"max_steps\":%d,\"record_store_order_widths_checked\":true,\"type_narrowing_checked\":true,\"unknown_bytes_guards_checked\":true,\"tail_lr_sp_checked\":true,\"delivery_r0_r2_transport_checked\":true,\"delivery_modeled\":false,\"live_verified\":false}\n",
            directPairs,calls,visited.size(),maxSteps));
    }
}
