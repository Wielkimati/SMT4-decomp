// Selection plus optional six-word wrapper/configuration integration.
// Only 0x0014F608 is intercepted; no original instructions on the rebuilt path.
// @category SMT4
import ghidra.pcode.emu.PcodeThread;
import ghidra.pcode.utils.Utils;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.pcode.PcodeOp;
import java.nio.file.*;
import java.security.MessageDigest;
import java.util.*;
import java.io.*;

public class CompareResourceHeapAllocateInner extends CompareResourceSync {
    static final long INNER=0x146ad8, INNER_END=0x146c20, COMMIT=0x14f608, MASK=0xffffffffL;
    static final long WRAPPER=0x2c3a98, WRAPPER_END=0x2c3afc;
    int cases, directCases, integratedCases, noFitCases, reverseCases, zeroRoundedCases, textSize;
    int nullModelCases, overflowCounters, firstFitCases, bestFitCases, laterSelections, tieCases;
    long observedReads, observedWrites;
    @Override boolean originalCode(long pc) {
        return within(pc,4,INNER,INNER_END) || within(pc,4,WRAPPER,WRAPPER_END) || within(pc,4,0x146ce0,0x146d20);
    }
    static long u(long v) { return v&MASK; }
    static void half(byte[] b,int off,long v) { b[off]=(byte)v; b[off+1]=(byte)(v>>>8); }
    static long half(byte[] b,int off) { return (b[off]&255L)|((b[off+1]&255L)<<8); }
    static String access(boolean store,long a,int n,long value) {
        return (store ? "W:" : "R:")+Long.toHexString(u(a))+":"+n+(store ? ":"+Long.toHexString(value) : "");
    }
    static class Probe {
        long sub,size,alignment,fourth,fifth,sixth,result,count;
        long[] nodes,caps;
        int flags,effect;
        boolean integrated;
    }
    class Oracle {
        final List<String> trace=new ArrayList<>();
        final Map<Long,byte[]> regions=new LinkedHashMap<>();
        long selected,payload,rounded,reverse,result,header;
        int traversed;
        void read(long a,int n) { trace.add(access(false,a,n,0)); }
        void write(long a,int n,long v) { trace.add(access(true,a,n,v)); }
        Oracle(Probe p) {
            header=u(p.sub+0x10);
            byte[] h=new byte[0x40]; new Random(0x146ad8L+cases).nextBytes(h);
            put(h,0x14,p.nodes.length==0 ? 0 : p.nodes[0]);
            put(h,0x18,p.nodes.length==0 ? 0 : p.nodes[p.nodes.length-1]);
            half(h,0x26,p.flags); put(h,0x2c,p.count); regions.put(header,h);
            for(int i=0;i<p.nodes.length;i++) {
                byte[] b=new byte[32]; new Random(p.nodes[i]+cases).nextBytes(b);
                put(b,12,p.caps[i]); put(b,16,i==0 ? 0 : p.nodes[i-1]);
                put(b,20,i+1==p.nodes.length ? 0 : p.nodes[i+1]); regions.put(p.nodes[i]-8,b);
            }
        }
        void evaluate(Probe p) {
            byte[] h=regions.get(header);
            if(p.integrated) {
                read(u(p.sub+0x34),2); write(u(p.sub+0x34),2,p.fourth&0xffff); half(h,0x24,p.fourth);
                read(u(p.sub+0x36),2); long f=(p.flags&0xfffe)|(p.fifth&1);
                write(u(p.sub+0x36),2,f); half(h,0x26,f);
                read(u(p.sub+0x38),1); write(u(p.sub+0x38),1,p.sixth&255); h[0x28]=(byte)p.sixth;
            }
            boolean first=(half(h,0x26)&1)==0;
            if(first) firstFitCases++; else bestFitCases++;
            rounded=u((p.size==0 ? 1 : p.size)+3)&0xfffffffcL;
            reverse=p.alignment>>>31;
            read(u(p.sub+0x36),2); read(u(p.sub+(reverse==0 ? 0x24 : 0x28)),4);
            long best=MASK;
            // Oracle enumerates the fixture's traversal order; it does not follow emulated pointers.
            for(int ordinal=0;ordinal<p.nodes.length;ordinal++) {
                int i=reverse==0 ? ordinal : p.nodes.length-1-ordinal;
                long node=p.nodes[i], cap=p.caps[i], start=u(node+16), candidate;
                read(node+4,4); traversed++;
                boolean fits;
                if(reverse==0) {
                    long magnitude=p.alignment;
                    candidate=u(start+magnitude-1)&u(~u(magnitude-1));
                    fits=cap>=u(candidate-start+rounded);
                } else {
                    long magnitude=u(-p.alignment);
                    candidate=u(start+cap-rounded)&u(~u(magnitude-1));
                    fits=u(candidate-start)<0x80000000L;
                }
                if(fits && cap==best) tieCases++;
                if(fits && cap<best) {
                    selected=node; payload=candidate; best=cap;
                    if(first || cap==rounded) break;
                }
                read(node+(reverse==0 ? 12 : 8),4);
            }
            if(selected!=0) {
                trace.add("C:"+Long.toHexString(u(p.sub+0x24))+":"+Long.toHexString(selected)+":"+
                    Long.toHexString(payload)+":"+Long.toHexString(rounded)+":"+reverse);
                result=p.result;
                if(p.effect!=0) {
                    // Synthetic dependency changes prove no stale/repeated reads around the boundary.
                    half(h,0x26,half(h,0x26)^0xa55a); put(h,0x14,0xdeadbeefL); put(h,0x18,0xabcdef01L);
                    put(h,0x2c,p.effect==2 ? MASK : p.count^0xa5a55a5aL);
                    for(long node:p.nodes) put(regions.get(node-8),12,0x87654321L);
                }
            }
            if(p.integrated && result!=0) {
                read(u(p.sub+0x3c),4); long next=u(word(h,0x2c)+1);
                write(u(p.sub+0x3c),4,next); put(h,0x2c,next);
                if(next==0) overflowCounters++;
            }
        }
    }
    class InnerMachine extends SyncMachine {
        List<String> trace=new ArrayList<>();
        InnerMachine(byte[] mapped,byte[] binary) { super(mapped,binary); }
        @Override public void beforeStore(PcodeThread<byte[]> t,PcodeOp op,AddressSpace space,byte[] offset,int n,byte[] value) {
            long a=Utils.bytesToLong(offset,offset.length,false);
            if(within(a,n,STACK-128,STACK)) return;
            trace.add(access(true,a,n,Utils.bytesToLong(value,n,false))); observedWrites++;
            require(trace.size()<=128,"External access budget");
        }
        @Override public void beforeLoad(PcodeThread<byte[]> t,PcodeOp op,AddressSpace space,byte[] offset,int n) {
            long a=Utils.bytesToLong(offset,offset.length,false);
            if(within(a,n,STACK-128,STACK+8) || within(a,n,BUILD,BUILD+codeSize)) return;
            trace.add(access(false,a,n,0)); observedReads++;
            require(trace.size()<=128,"External access budget");
        }
        void call(boolean rebuiltPath,Probe p,Oracle expected) throws Exception {
            initialize(rebuiltPath,0,new byte[0x144]); trace.clear();
            Oracle initial=new Oracle(p);
            for(var r:initial.regions.entrySet()) memory(r.getKey(),r.getValue());
            byte[] caller=new byte[32]; new Random(cases).nextBytes(caller);
            put(caller,0,p.fifth); put(caller,4,p.sixth); memory(STACK,caller);
            register("r0",p.integrated ? u(p.sub-24) : p.sub);
            register("r1",p.size); register("r2",p.alignment); register("r3",p.fourth);
            for(int r=16;r<32;r++) register("s"+r,0x81234000L+r);
            thread.overrideCounter(toAddr(rebuiltPath ? entries[p.integrated ? 1 : 0] : p.integrated ? WRAPPER : INNER));
            executing=true;
            int steps=0,calls=0;
            while(thread.getCounter().getOffset()!=RETURN) {
                long pc=thread.getCounter().getOffset();
                if(pc==COMMIT) {
                    require(expected.selected!=0 && ++calls==1,"Unexpected commit");
                    require((register("sp")&7)==0,"Commit stack alignment");
                    long direction=word(memory(register("sp"),4),0);
                    trace.add("C:"+Long.toHexString(register("r0"))+":"+Long.toHexString(register("r1"))+":"+
                        Long.toHexString(register("r2"))+":"+Long.toHexString(register("r3"))+":"+direction);
                    int commitIndex=expected.trace.indexOf(trace.get(trace.size()-1));
                    require(commitIndex>=0 && trace.equals(expected.trace.subList(0,commitIndex+1)),"Selection/call/access trace");
                    // Before commit only configuration setters may have changed external bytes.
                    byte[] h=initial.regions.get(initial.header);
                    if(p.integrated) {
                        half(h,0x24,p.fourth); half(h,0x26,(p.flags&0xfffe)|(p.fifth&1)); h[0x28]=(byte)p.sixth;
                    }
                    for(var r:initial.regions.entrySet()) require(Arrays.equals(r.getValue(),memory(r.getKey(),r.getValue().length)),"Pre-commit memory/guards");
                    if(p.effect!=0) {
                        half(h,0x26,half(h,0x26)^0xa55a); put(h,0x14,0xdeadbeefL); put(h,0x18,0xabcdef01L);
                        put(h,0x2c,p.effect==2 ? MASK : p.count^0xa5a55a5aL);
                        for(long node:p.nodes) put(initial.regions.get(node-8),12,0x87654321L);
                        for(var r:initial.regions.entrySet()) memory(r.getKey(),r.getValue());
                    }
                    for(int r=0;r<16;r++) register("s"+r,0xdead0000L+r);
                    externalReturn(p.result); dependencyCalls++; continue;
                }
                require(!rebuiltPath || within(pc,4,BUILD,BUILD+textSize),"Rebuilt PC outside text");
                step(rebuiltPath,++steps);
            }
            require(calls==(expected.selected==0 ? 0 : 1),"Missing commit");
            require(register("r0")==expected.result,"Allocation result");
            require(trace.equals(expected.trace),"Final access trace: "+trace+" expected "+expected.trace);
            for(var r:expected.regions.entrySet()) require(Arrays.equals(r.getValue(),memory(r.getKey(),r.getValue().length)),"Final memory/guards");
            require(Arrays.equals(caller,memory(STACK,caller.length)),"Caller stack");
            byte[] stack=memory(STACK-0x1000,0x1000);
            for(int i=0;i<stack.length-128;i++) require(stack[i]==(byte)0x96,"Stack guard");
            for(int r=16;r<32;r++) require(register("s"+r)==0x81234000L+r,"Saved VFP register");
            finish(steps);
        }
    }
    void compare(InnerMachine a,InnerMachine b,Probe p,PrintWriter log) throws Exception {
        Oracle expected=new Oracle(p); expected.evaluate(p);
        try { a.call(false,p,expected); b.call(true,p,expected); }
        catch(Exception ex) { throw new IllegalStateException("Heap inner case "+cases+" integrated="+p.integrated+
            " size="+Long.toHexString(p.size)+" alignment="+Long.toHexString(p.alignment),ex); }
        if(p.integrated) integratedCases++; else directCases++;
        if(expected.selected==0) noFitCases++; else if(p.result==0) nullModelCases++;
        if(expected.reverse!=0) reverseCases++;
        if(expected.rounded==0) zeroRoundedCases++;
        if(expected.selected!=0 && expected.selected!=p.nodes[expected.reverse==0 ? 0 : p.nodes.length-1]) laterSelections++;
        log.printf("%d\t%b\t%x\t%x\t%x\t%s\t%s\t%x\t%x\t%x\t%d%n",cases++,p.integrated,p.sub,p.size,p.alignment,
            Arrays.toString(p.nodes),Arrays.toString(p.caps),expected.selected,expected.payload,expected.result,expected.traversed);
    }
    @Override public void run() throws Exception {
        Path out=Path.of(getScriptArgs()[0]); require(!Files.exists(out.resolve("comparison.json")),"Existing output");
        byte[] mapped=new byte[0x377000]; require(currentProgram.getMemory().getBytes(toAddr(0x100000),mapped)==mapped.length,"Map");
        require(HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(mapped)).equals(
            "834938d18d2b7c688311c46c27bed813d0d7a9f8e3cbb61da8a6a3f23d360ebd"),"Hash");
        byte[] binary=Files.readAllBytes(out.resolve("resource-heap-inner.bin")); codeSize=binary.length;
        textSize=Integer.parseInt(Files.readString(out.resolve("text-size.txt")).trim());
        require(textSize>0 && textSize<=codeSize && codeSize<0x2000,"Text extent");
        List<String> lines=Files.readAllLines(out.resolve("entries.txt")); require(lines.size()==2,"Entries");
        for(int i=0;i<2;i++) entries[i]=Long.parseLong(lines.get(i));
        InnerMachine a=new InnerMachine(mapped,binary),b=new InnerMachine(mapped,binary);
        long[] sizes={0,1,3,4,5,16,20,32,64,0x7ffffffcL,0x80000000L,0xfffffffcL,0xfffffffdL,MASK};
        long[] aligns={0,1,3,4,8,16,64,128,0x7fffffffL,0x80000000L,0xffffff80L,0xffffffc0L,0xfffffff0L,0xfffffff8L,0xfffffffcL,0xfffffffdL,MASK};
        long[][] capacities={{},{0},{16},{MASK},{8,64,32},{32,32,32},{64,8,64},{0x80000000L,0x7fffffffL,0xfffffffeL}};
        Random rng=new Random(INNER);
        try(PrintWriter log=new PrintWriter(Files.newBufferedWriter(out.resolve("results.tsv")))) {
            log.println("case\tintegrated\tsubobject\tsize\talignment\tnodes\tcapacities\tselected\tpayload\tresult\tvisited_nodes");
            for(int address=0;address<3;address++) for(long size:sizes) for(long alignment:aligns)
            for(long[] caps:capacities) for(int flag=0;flag<2;flag++) for(int mode=0;mode<2;mode++) {
                Probe p=new Probe(); p.sub=new long[]{0x910000,0x89100000L,0xfffffff0L}[address];
                p.size=size; p.alignment=alignment; p.flags=(rng.nextInt()&0xfffe)|flag;
                p.fourth=Integer.toUnsignedLong(rng.nextInt()); p.fifth=(Integer.toUnsignedLong(rng.nextInt())&0xfffffffeL)|flag;
                p.sixth=Integer.toUnsignedLong(rng.nextInt()); p.integrated=mode!=0; if(p.integrated) p.flags^=1; p.caps=caps;
                p.nodes=new long[caps.length];
                for(int i=0;i<caps.length;i++) p.nodes[i]=address==2 ? (i==0 ? 0xffffffe0L : 0x100L+i*0x104) : 0x920000L+address*0x80000000L+i*0x104;
                // The wrapping subobject's guarded header begins at zero; nodes remain disjoint.
                p.result=new long[]{0,1,0x87654320L,MASK}[(cases/2)%4]; p.count=cases%3==0 ? MASK : Integer.toUnsignedLong(rng.nextInt());
                p.effect=(cases/4)%3; compare(a,b,p,log);
            }
            for(int i=0;i<768;i++) {
                Probe p=new Probe(); p.sub=0x910000; p.size=Integer.toUnsignedLong(rng.nextInt());
                p.alignment=Integer.toUnsignedLong(rng.nextInt()); p.flags=rng.nextInt()&0xffff;
                p.fourth=Integer.toUnsignedLong(rng.nextInt()); p.fifth=Integer.toUnsignedLong(rng.nextInt());
                p.sixth=Integer.toUnsignedLong(rng.nextInt()); p.integrated=(i&1)!=0;
                p.nodes=new long[i%7]; p.caps=new long[i%7];
                for(int j=0;j<p.nodes.length;j++) { p.nodes[j]=0x920000+j*0x104; p.caps[j]=Integer.toUnsignedLong(rng.nextInt()); }
                p.result=i%4==0 ? 0 : Integer.toUnsignedLong(rng.nextInt()); p.count=Integer.toUnsignedLong(rng.nextInt()); p.effect=i%3;
                compare(a,b,p,log);
            }
        }
        StringBuilder listing=new StringBuilder();
        for(long[] range:new long[][]{{INNER,INNER_END},{WRAPPER,WRAPPER_END},{0x146ce0,0x146d20}})
            for(long pc=range[0];pc<range[1];pc+=4) {
                require(visited.contains(pc),"Unvisited original "+Long.toHexString(pc));
                var ins=currentProgram.getListing().getInstructionAt(toAddr(pc)); require(ins!=null,"Missing instruction");
                listing.append(String.format("%08x %s %s%n",pc,HexFormat.of().formatHex(ins.getBytes()),ins));
            }
        Files.writeString(out.resolve("original-ghidra.txt"),listing);
        Files.writeString(out.resolve("comparison.json"),String.format(Locale.ROOT,
            "{\"cases\":%d,\"direct_cases\":%d,\"integrated_cases\":%d,\"no_fit\":%d,\"reverse_cases\":%d,\"zero_rounded\":%d,\"null_commit_returns\":%d,\"counter_overflows\":%d,\"first_fit\":%d,\"best_fit\":%d,\"later_selections\":%d,\"equal_capacity_observations\":%d,\"external_reads_both_paths\":%d,\"external_writes_both_paths\":%d,\"dependency_calls_both_paths\":%d,\"original_instruction_addresses\":%d,\"max_steps\":%d,\"commit_block_modeled\":true,\"live_verified\":false}\n",
            cases,directCases,integratedCases,noFitCases,reverseCases,zeroRoundedCases,nullModelCases,overflowCounters,firstFitCases,bestFitCases,laterSelections,tieCases,observedReads,observedWrites,dependencyCalls,visited.size(),maxSteps));
        println("SMT4_HEAP_INNER_COMPARE_OK");
    }
}
