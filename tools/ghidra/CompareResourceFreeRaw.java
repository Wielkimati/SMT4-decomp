// Ordered routing probes and allocation-produced arena release. Explicit lock/pool models.
// @category SMT4
import ghidra.pcode.emu.PcodeThread;
import ghidra.pcode.utils.Utils;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.pcode.PcodeOp;
import java.nio.file.*;
import java.security.MessageDigest;
import java.util.*;
import java.io.*;

public class CompareResourceFreeRaw extends CompareResourceHeapFree {
    static final long ROUTER=0x1244e8, ROUTER_END=0x1245e4, STATE=0x465170;
    static final long ACQUIRE=0x2c3afc, UNLOCK=0x2c3a78, FIXED=0x138354;
    static final int[] OFF={0x14,0x80,0xec,0xf8};
    int routerCases,arenaFrees,directProbes; int[] routes=new int[5];
    long modeledCalls;
    @Override boolean originalCode(long pc) { return super.originalCode(pc) || within(pc,4,ROUTER,ROUTER_END); }
    class RouterMachine extends FreeMachine {
        long routingBase; boolean routing,backed;
        List<String> routeReads=new ArrayList<>(),calls=new ArrayList<>();
        RouterMachine(byte[] map,byte[] binary) { super(map,binary); }
        boolean routingBytes(long a,int n) { return u(a-u(routingBase-16))+n<=0x130; }
        @Override public void beforeLoad(PcodeThread<byte[]> t,PcodeOp op,AddressSpace space,byte[] offset,int n) {
            long a=Utils.bytesToLong(offset,offset.length,false);
            if(routing && (a==STATE+4 || routingBytes(a,n))) {
                // Arena fields share the routing object's storage; only router instructions
                // belong to the independent range-read oracle.
                long pc=thread.getCounter().getOffset();
                boolean inRouter=within(pc,4,ROUTER,ROUTER_END) || (rebuilt && within(pc,4,entries[4],entries[2]));
                if(inRouter) routeReads.add("R:"+Long.toHexString(a)+":"+n);
                trace.add("R:"+Long.toHexString(a)+":"+n); reads++; return;
            }
            if(within(a,n,ROUTER_END,ROUTER_END+12)) return;
            super.beforeLoad(t,op,space,offset,n);
        }
        @Override public void beforeStore(PcodeThread<byte[]> t,PcodeOp op,AddressSpace space,byte[] offset,int n,byte[] value) {
            long a=Utils.bytesToLong(offset,offset.length,false);
            if(routing && !backed) require(within(a,n,STACK-256,STACK),"Direct router wrote external state");
            super.beforeStore(t,op,space,offset,n,value);
        }
        boolean rebuilt;
        void bytes(long a,byte[] v) { for(int i=0;i<v.length;i++) memory(u(a+i),new byte[]{v[i]}); }
        byte[] bytes(long a,int n) { byte[] v=new byte[n]; for(int i=0;i<n;i++) v[i]=memory(u(a+i),1)[0]; return v; }
        void routeCall(boolean build,long base,byte[] object,long payload,int selected,int effect,Arena before,Arena after) throws Exception {
            routing=false; arena=before; initialize(build,0,new byte[0x144]); routingBase=base; rebuilt=build; backed=after!=null;
            byte[] expectedObject=object.clone(),global=new byte[48]; new Random(cases+91).nextBytes(global); put(global,20,base);
            if(backed) {
                // Only routing descriptors/guards are initialized here. Arena allocation
                // bytes persist from the preceding real allocation call.
                require(Arrays.equals(before.head,memory(before.heap,before.head.length)),"Pre-free header persistence");
                System.arraycopy(after.head,0,expectedObject,(int)(after.heap-base+16),after.head.length);
            }
            for(int i=0;i<object.length;i++) {
                long address=u(base-16+i);
                if(!backed || !within(address,1,before.heap,before.heap+before.head.length))
                    memory(address,new byte[]{object[i]});
            }
            memory(STATE-16,global);
            byte[] caller=new byte[32]; new Random(cases).nextBytes(caller); memory(STACK,caller);
            register("r0",payload); for(int r=16;r<32;r++) register("s"+r,0x81234000L+r);
            thread.overrideCounter(toAddr(build ? entries[4] : ROUTER)); trace.clear(); routeReads.clear(); calls.clear();
            List<String> expectedReads=new ArrayList<>(); expectedReads.add("R:"+Long.toHexString(STATE+4)+":4");
            for(int i=0;i<4;i++) {
                expectedReads.add("R:"+Long.toHexString(u(base+OFF[i]))+":4");
                if(word(object,16+OFF[i])<=payload) expectedReads.add("R:"+Long.toHexString(u(base+OFF[i]+4))+":4");
                if(i==selected) break;
            }
            List<Long> expectedCalls=selected<2 ? List.of(ACQUIRE,FREE_WRAPPER,UNLOCK) : selected<4 ? List.of(FIXED) : List.of();
            int count=0,steps=0,inner=0; routing=true; executing=true;
            while(thread.getCounter().getOffset()!=RETURN) {
                long pc=thread.getCounter().getOffset();
                boolean counted=pc==(build ? entries[3] : FREE_WRAPPER);
                if(pc==ACQUIRE || pc==UNLOCK || pc==FIXED || counted) {
                    long kind=counted ? FREE_WRAPPER : pc;
                    require(count<expectedCalls.size() && kind==expectedCalls.get(count),"Dependency order");
                    require((register("sp")&7)==0,"Dependency alignment");
                    long heap=u(base+(selected==0 ? 0x1c : 0x88)),lock=u(heap+0x58);
                    long arg=kind==FREE_WRAPPER ? heap : kind==FIXED ? (selected==2 ? 0x4e4100 : 0x4e411c) : lock;
                    require(register("r0")==arg,"Captured object/lock argument");
                    if(counted || pc==FIXED) require(register("r1")==payload,"Payload forwarding");
                    calls.add(Long.toHexString(kind)+":"+Long.toHexString(arg)+(counted || pc==FIXED ? ":"+Long.toHexString(payload) : "")); count++;
                    if(!(counted && backed)) {
                        if(effect!=0) { put(global,20,u(base+0x12345678L*count)); memory(STATE-16,global); }
                        for(int r=0;r<16;r++) register("s"+r,0xdead0000L+r);
                        externalReturn(u(0xabcdef01L+count)); modeledCalls++; continue;
                    }
                }
                if(pc==(build ? entries[2] : FREE)) {
                    inner++; require(backed && register("r0")==before.heap+0x18 && register("r1")==payload,"Inner free arguments");
                }
                require(build ? within(pc,4,BUILD,BUILD+textSize) : originalCode(pc),"Unexpected execution");
                if(!build) visited.add(pc);
                require(++steps<5000,"Instruction budget"); monitor.checkCancelled(); thread.stepInstruction();
            }
            executing=false; routing=false;
            require(count==expectedCalls.size() && inner==(backed ? 1 : 0),"Missing dependency/inner free");
            require(routeReads.equals(expectedReads),"Ordered short-circuit range reads: "+routeReads+" expected "+expectedReads);
            require(Arrays.equals(expectedObject,bytes(u(base-16),object.length)),"Routing object/guards");
            require(Arrays.equals(global,memory(STATE-16,global.length)),"Global/guards");
            if(backed) {
                require(Arrays.equals(after.head,memory(after.heap,after.head.length)),"Freed header/guards");
                require(Arrays.equals(after.data,memory(after.base,after.data.length)),"Freed arena/guards");
            }
            require(Arrays.equals(caller,memory(STACK,caller.length)),"Caller stack");
            byte[] stack=memory(STACK-0x1000,0x1000); for(int i=0;i<stack.length-256;i++) require(stack[i]==(byte)0x96,"Stack guard");
            for(int r=16;r<32;r++) require(register("s"+r)==0x81234000L+r,"Saved VFP");
            finish(steps); // void interface: r0 is an unconsumed scratch register.
        }
    }
    byte[] object(long[][] ranges) {
        byte[] v=new byte[0x130]; new Random(routerCases+123).nextBytes(v);
        for(int i=0;i<4;i++) { put(v,16+OFF[i],ranges[i][0]); put(v,20+OFF[i],ranges[i][1]); } return v;
    }
    int select(byte[] object,long payload) {
        for(int i=0;i<4;i++) {
            long start=word(object,16+OFF[i]),end=u(start+word(object,20+OFF[i]));
            if(start<=payload && payload<end) return i;
        } return 4;
    }
    void probe(RouterMachine a,RouterMachine b,long base,byte[] object,long payload,int effect,Arena state,PrintWriter log) throws Exception {
        int selected=select(object,payload); Arena before=state==null ? new Arena(0,0) : new Arena(state);
        if(state!=null) { require(selected<2 && state.heap==base+(selected==0 ? 0x1c : 0x88),"Arena route fixture"); release(state,payload,true); }
        try {
            a.routeCall(false,base,object,payload,selected,effect,before,state);
            b.routeCall(true,base,object,payload,selected,effect,before,state);
            require(a.trace.equals(b.trace),"External access trace"); require(a.calls.equals(b.calls),"Call trace");
        } catch(Exception ex) { throw new IllegalStateException("Raw free case "+routerCases+" selected="+selected+" payload="+Long.toHexString(payload)+" backed="+(state!=null),ex); }
        routes[selected]++; routerCases++; if(state==null) directProbes++; else arenaFrees++;
        log.printf("%d\trouter\t%x\t%x\t%d\t%b%n",cases++,base,payload,selected,state!=null);
    }
    @Override public void run() throws Exception {
        Path out=Path.of(getScriptArgs()[0]); require(!Files.exists(out.resolve("comparison.json")),"Existing output");
        byte[] map=new byte[0x377000]; require(currentProgram.getMemory().getBytes(toAddr(0x100000),map)==map.length,"Map");
        require(HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(map)).equals("834938d18d2b7c688311c46c27bed813d0d7a9f8e3cbb61da8a6a3f23d360ebd"),"Hash");
        byte[] binary=Files.readAllBytes(out.resolve("resource-free-raw.bin")); codeSize=binary.length;
        textSize=Integer.parseInt(Files.readString(out.resolve("text-size.txt")).trim());
        List<String> lines=Files.readAllLines(out.resolve("entries.txt")); require(lines.size()==5,"Entries"); for(int i=0;i<5;i++) entries[i]=Long.parseLong(lines.get(i));
        require(entries[4]<entries[2],"Router text region before free source");
        var f=getFunctionAt(toAddr(ROUTER)); require(f!=null && f.getBody().getMinAddress().getOffset()==ROUTER && f.getBody().getMaxAddress().getOffset()==ROUTER_END-1,"Saved boundary");
        for(int i=0;i<3;i++) require(word(map,(int)(ROUTER_END-0x100000+4*i))==new long[]{STATE,0x4e4100,0x4e411c}[i],"Literal");
        RouterMachine a=new RouterMachine(map,binary),b=new RouterMachine(map,binary);
        try(PrintWriter log=new PrintWriter(Files.newBufferedWriter(out.resolve("results.tsv")))) {
            long[][][] profiles={{{0x100,0x80},{0x200,0x80},{0x300,0x80},{0x400,0x80}},{{0x100,0x100},{0x100,0x200},{0x100,0x300},{0x100,0x400}},{{0,1},{1,1},{2,1},{3,1}},{{0x80000000L,0x100},{0xffffff00L,0x80},{0xfffffff0L,0x40},{0,0xffffffffL}},{{0x100,0},{0x200,0},{0x300,0},{0x400,0}},{{0x80000000L,0x80000000L},{0xfffffff0L,0x20},{0xfffffffcL,3},{0xffffffffL,1}}};
            for(long[][] ranges:profiles) {
                Set<Long> probes=new TreeSet<>(List.of(0L,1L,0x7fffffffL,0x80000000L,MASK));
                for(long[] r:ranges) for(long x:new long[]{r[0],u(r[0]+r[1])}) for(int d=-1;d<=1;d++) probes.add(u(x+d));
                for(long base:new long[]{0x930000,0x89300000L,0xffffff80L}) for(int effect=0;effect<2;effect++)
                    for(long payload:probes) probe(a,b,base,object(ranges),payload,effect,null,log);
            }
            Random rng=new Random(ROUTER);
            for(int i=0;i<384;i++) {
                long[][] ranges=new long[4][2]; for(long[] r:ranges) { r[0]=Integer.toUnsignedLong(rng.nextInt()); r[1]=Integer.toUnsignedLong(rng.nextInt()); }
                long payload=i%2==0 ? ranges[i%4][0] : Integer.toUnsignedLong(rng.nextInt());
                probe(a,b,0x930000,object(ranges),payload,i%2,null,log);
            }
            // Persistent allocation -> routed free -> allocation -> routed free on
            // each heap route; real inner routines, locks alone are intercepted.
            for(int route=0;route<2;route++) for(int high=0;high<2;high++) for(int sign=0;sign<2;sign++)
            for(int policy=0;policy<2;policy++) for(int split=0;split<2;split++) {
                Arena state=new Arena(high,cases); long base=state.heap; state.heap+=route==0 ? 0x1c : 0x88; state.lists=state.heap+0x3c;
                state.addFree(0,2048,0); state.link(); state.set(state.lists-4,4,3); state.set(state.heap+0x54,4,MASK);
                a.seed(state); b.seed(state); scenarios++; long[] live=new long[3]; long alignment=sign==0 ? 128 : u(-128);
                for(int i=0;i<3;i++) live[i]=allocate(a,b,state,new int[]{20,49,73}[i],alignment,policy,split,log);
                for(int step=0;step<4;step++) {
                    long payload=step<3 ? live[new int[]{1,0,2}[step]] : allocate(a,b,state,2048,4,policy,1,log);
                    require(payload!=0,"Arena allocation succeeded");
                    long[][] ranges=new long[4][2]; ranges[route]=new long[]{state.base,0x1800};
                    byte[] obj=object(ranges); System.arraycopy(state.head,0,obj,(int)(state.heap-base+16),state.head.length);
                    // Overlaying heap bytes may replace later (unread) range slots.
                    probe(a,b,base,obj,payload,1,state,log);
                }
                require(state.used.isEmpty() && state.get(state.node(0)+4,4)==2048,"Arena restored and reused");
            }
        }
        StringBuilder listing=new StringBuilder(); int count=0;
        for(long pc=ROUTER;pc<ROUTER_END;pc+=4) { require(visited.contains(pc),"Unvisited router instruction"); var ins=currentProgram.getListing().getInstructionAt(toAddr(pc)); require(ins!=null,"Instruction"); listing.append(String.format("%08x %s %s%n",pc,HexFormat.of().formatHex(ins.getBytes()),ins)); count++; }
        Files.writeString(out.resolve("original-ghidra.txt"),listing);
        Files.writeString(out.resolve("comparison.json"),String.format(Locale.ROOT,"{\"cases\":%d,\"router_cases\":%d,\"direct_probes\":%d,\"arena_frees\":%d,\"allocation_calls\":%d,\"arena_scenarios\":%d,\"routes\":%s,\"router_instruction_addresses\":%d,\"modeled_calls_both_paths\":%d,\"external_reads_both_paths\":%d,\"external_writes_both_paths\":%d,\"max_steps\":%d,\"r0_unconsumed\":true,\"live_verified\":false}\n",cases,routerCases,directProbes,arenaFrees,integratedCases,scenarios,Arrays.toString(routes),count,modeledCalls,reads,writes,maxSteps));
        println("SMT4_FREE_RAW_COMPARE_OK");
    }
}
