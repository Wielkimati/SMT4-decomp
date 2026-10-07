// Allocation registration with explicit heap-selector model and independent memory oracle.
// @category SMT4
import ghidra.pcode.emu.PcodeThread;
import ghidra.pcode.utils.Utils;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.pcode.PcodeOp;
import java.nio.file.*;
import java.security.MessageDigest;
import java.util.*;
import java.io.*;

public class CompareResourceAllocateRegister extends CompareResourceSync {
    static final long ENTRY=0x2b260c, END=0x2b26ec, STATE=0x465120, SELECT=0x2b3340, MASK=0xffffffffL;
    static final long[] ACCOUNTS={0x920000,0x921000,0x922000};
    static final long PREV=0x930020, NEXT=0x930120;
    int cases, selectedCases;
    @Override boolean originalCode(long pc) { return within(pc,4,ENTRY,END); }
    class RegisterMachine extends SyncMachine {
        final Map<Long,byte[]> expected=new LinkedHashMap<>();
        final Set<Long> allowedStores=new HashSet<>();
        final List<String> trace=new ArrayList<>();
        long raw,user,account;
        int calls,effect,index0,index1;
        RegisterMachine(byte[] mapped,byte[] binary) { super(mapped,binary); }
        void region(long a,int n,Random rng) {
            byte[] bytes=new byte[n]; rng.nextBytes(bytes); expected.put(a,bytes); memory(a,bytes);
        }
        void set(long a,int n,long value) {
            for(var r:expected.entrySet()) if(within(a,n,r.getKey(),r.getKey()+r.getValue().length)) {
                for(int i=0;i<n;i++) r.getValue()[(int)(a-r.getKey())+i]=(byte)(value >>> (i*8));
                return;
            }
            throw new IllegalStateException("Oracle address");
        }
        long get(long a,int n) {
            for(var r:expected.entrySet()) if(within(a,n,r.getKey(),r.getKey()+r.getValue().length)) {
                long v=0; for(int i=0;i<n;i++) v|=(r.getValue()[(int)(a-r.getKey())+i]&255L)<<(i*8);
                return v;
            }
            throw new IllegalStateException("Oracle read");
        }
        void change(long a,int n,long value) {
            for(int i=0;i<n;i++) allowedStores.add(a+i);
            set(a,n,value);
        }
        void model(long a,int n,long value) {
            set(a,n,value); byte[] bytes=new byte[n];
            for(int i=0;i<n;i++) bytes[i]=(byte)(value >>> (i*8)); memory(a,bytes);
        }
        void check(String stage) {
            for(var r:expected.entrySet()) require(Arrays.equals(r.getValue(),memory(r.getKey(),r.getValue().length)),
                stage+" memory/guard mismatch "+Long.toHexString(r.getKey()));
        }
        @Override public void beforeStore(PcodeThread<byte[]> t,PcodeOp op,AddressSpace space,byte[] offset,int n,byte[] value) {
            long a=Utils.bytesToLong(offset,offset.length,false);
            if(within(a,n,STACK-64,STACK)) return;
            for(int i=0;i<n;i++) require(allowedStores.contains(a+i),"Unexpected registration store "+Long.toHexString(a));
        }
        @Override public void beforeLoad(PcodeThread<byte[]> t,PcodeOp op,AddressSpace space,byte[] offset,int n) {
            long a=Utils.bytesToLong(offset,offset.length,false);
            boolean ok=within(a,n,STACK-64,STACK) || within(a,n,ENTRY,END+4) || within(a,n,BUILD,BUILD+codeSize);
            for(var r:expected.entrySet()) ok|=within(a,n,r.getKey(),r.getKey()+r.getValue().length);
            require(ok,"Unexpected registration read "+Long.toHexString(a));
        }
        void appendOracle(int topology,boolean cursor) {
            // Project an abstract empty/singleton/two-member list with raw appended.
            long tail=topology==0 ? 0 : topology==1 ? PREV : NEXT;
            if(tail==0) change(account,4,raw+12); else change(tail+4,4,raw+12);
            change(account+4,4,raw+12);
            change(raw+12,4,tail); change(raw+16,4,0);
            change(raw+8,2,get(account+56,2));
        }
        void call(boolean rebuiltPath,int tag,int topology,boolean cursor,int effect,long rawAddress,
                  long size,int alignment,long counter,int first,int second) throws Exception {
            initialize(rebuiltPath,0,new byte[0x144]);
            expected.clear(); allowedStores.clear(); trace.clear();
            raw=rawAddress; user=((raw+60+127)/128)*128; account=ACCOUNTS[0];
            this.effect=effect; index0=first; index1=second; calls=0;
            Random rng=new Random(ENTRY+cases);
            region(STATE-16,0x60,rng); region(raw-32,512,rng);
            for(long a:ACCOUNTS) region(a-16,0xa0,rng);
            region(PREV-16,64,rng); region(NEXT-16,64,rng);
            set(STATE+8,4,account); set(raw,4,size);
            set(raw+4,2,alignment); set(raw+8,2,tag^0xffff);
            set(PREV,4,0); set(PREV+4,4,topology==2 ? NEXT : 0);
            set(NEXT,4,PREV); set(NEXT+4,4,0);
            for(long a:ACCOUNTS) {
                set(a,4,topology==0 ? 0 : PREV);
                // A stale tail in an empty list must be ignored: head controls the branch.
                set(a+4,4,topology==2 ? NEXT : PREV);
                set(a+8,4,cursor ? raw+12 : NEXT);
                set(a+56,2,tag);
                set(a+24,4,counter); set(a+28,4,counter);
                for(int i=0;i<8;i++) { set(a+60+i*4,4,counter); set(a+92+i*4,4,counter); }
            }
            for(var r:expected.entrySet()) memory(r.getKey(),r.getValue());
            change(account+24,4,(counter+1)&MASK);
            change(account+28,4,(counter+size)&MASK);
            boolean select=(tag&255)<8;
            if(!select) appendOracle(topology,cursor);
            register("r0",raw); register("s16",0x81234567L); register("s17",0xfedcba98L);
            thread.overrideCounter(toAddr(rebuiltPath ? entries[0] : ENTRY)); executing=true;
            int steps=0;
            while(thread.getCounter().getOffset()!=RETURN) {
                long pc=thread.getCounter().getOffset();
                if(pc==SELECT) {
                    require(select && calls<2 && register("r0")==raw,"Selector count/argument");
                    require((register("sp")&7)==0,"Selector stack alignment"); check("Before selector "+calls);
                    int index=calls==0 ? index0 : index1;
                    trace.add("select:"+raw+":"+index);
                    // Deliberate dependency changes: reload state, size and halfword after each call.
                    if(effect!=0) {
                        account=ACCOUNTS[calls+1]; model(STATE+8,4,account);
                        model(raw,4,(size+(calls+1)*0x87654321L)&MASK);
                        model(raw+4,2,(alignment+0x8101+calls)&65535);
                        model(account+56,2,0xff08+calls); // Initial tag decision is not repeated; final tag is reloaded.
                    }
                    long amount=get(raw,4);
                    if(calls==1) amount=amount-get(raw+4,2)-60;
                    long slot=account+(calls==0 ? 60 : 92)+index*4;
                    change(slot,4,(get(slot,4)+amount)&MASK);
                    if(calls==1) appendOracle(topology,cursor);
                    calls++; dependencyCalls++; externalReturn(index); continue;
                }
                step(rebuiltPath,++steps);
            }
            require(calls==(select ? 2 : 0),"Missing selector");
            check("Final"); // Caller consumes no return value.
            byte[] stack=memory(STACK-0x1000,0x1000);
            for(int i=0;i<stack.length-64;i++) require(stack[i]==(byte)0x96,"Stack guard");
            require(register("s16")==0x81234567L && register("s17")==0xfedcba98L,"d8 preservation");
            finish(steps);
        }
    }
    void compare(RegisterMachine a,RegisterMachine b,PrintWriter log,int tag,int topology,boolean cursor,int effect,
                 long raw,long size,int alignment,long counter,int first,int second) throws Exception {
        try {
            a.call(false,tag,topology,cursor,effect,raw,size,alignment,counter,first,second);
            b.call(true,tag,topology,cursor,effect,raw,size,alignment,counter,first,second);
            require(a.trace.equals(b.trace),"Selector trace");
        } catch(Exception ex) { throw new IllegalStateException("Registration case "+cases+" tag="+tag+" topology="+topology+" effect="+effect,ex); }
        if((tag&255)<8) selectedCases++;
        log.printf("%d\t%d\t%d\t%b\t%d\t%x\t%x\t%d\t%x\t%d\t%d%n",++cases,tag,topology,cursor,effect,raw,size,alignment,counter,first,second);
    }
    @Override public void run() throws Exception {
        Path out=Path.of(getScriptArgs()[0]); require(!Files.exists(out.resolve("comparison.json")),"Existing output");
        byte[] mapped=new byte[0x377000]; require(currentProgram.getMemory().getBytes(toAddr(0x100000),mapped)==mapped.length,"Map");
        require(HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(mapped)).equals(
            "834938d18d2b7c688311c46c27bed813d0d7a9f8e3cbb61da8a6a3f23d360ebd"),"Hash");
        byte[] binary=Files.readAllBytes(out.resolve("resource-allocate-register.bin")); codeSize=binary.length;
        require(codeSize>0 && codeSize<=0x1000,"Binary size");
        List<String> lines=Files.readAllLines(out.resolve("entries.txt")); require(lines.size()==1,"Entries");
        entries[0]=Long.parseLong(lines.get(0)); require(within(entries[0],4,BUILD,BUILD+codeSize),"Entry");
        RegisterMachine a=new RegisterMachine(mapped,binary),b=new RegisterMachine(mapped,binary);
        try(PrintWriter log=new PrintWriter(Files.newBufferedWriter(out.resolve("results.tsv")))) {
            log.println("case\ttag\ttopology\tcursor\teffect\traw\tsize\talignment\tcounter\tindex0\tindex1");
            for(int tag=0;tag<256;tag++) for(int high:new int[]{0,0x8100,0xff00})
            for(int topology=0;topology<3;topology++) for(boolean cursor:new boolean[]{false,true})
                compare(a,b,log,tag|high,topology,cursor,tag%2,0x900100+(tag%32)*4,128,128,0,tag%8,(tag+3)%8);
            long[] values={0,1,59,60,61,127,128,255,0x7fffffffL,0x80000000L,MASK};
            for(long size:values) for(int alignment:new int[]{0,1,128,0x8000,65535})
            for(int effect=0;effect<2;effect++) for(int topology=0;topology<3;topology++)
                compare(a,b,log,0x8107,topology,true,effect,0x8900017cL,size,alignment,size,0,7);
            Random rng=new Random(ENTRY);
            for(int i=0;i<1024;i++) compare(a,b,log,i%2==0 ? rng.nextInt(8)|0xff00 : rng.nextInt(65536),
                i%3,i%3==0,i%2,0x900100+rng.nextInt(32)*4,Integer.toUnsignedLong(rng.nextInt()),
                rng.nextInt(65536),Integer.toUnsignedLong(rng.nextInt()),rng.nextInt(8),rng.nextInt(8));
        }
        StringBuilder listing=new StringBuilder();
        for(long pc=ENTRY;pc<END;pc+=4) {
            require(visited.contains(pc),"Unvisited original "+Long.toHexString(pc));
            var ins=currentProgram.getListing().getInstructionAt(toAddr(pc)); require(ins!=null,"Missing listing");
            listing.append(String.format("%08x %s%n",pc,ins));
        }
        Files.writeString(out.resolve("original-ghidra.txt"),listing);
        Files.writeString(out.resolve("comparison.json"),String.format(Locale.ROOT,
            "{\"registration_cases\":%d,\"selected_cases\":%d,\"original_instruction_addresses\":%d,\"max_steps\":%d,\"selector_calls_both_paths\":%d,\"selector_modeled\":true,\"live_verified\":false}\n",
            cases,selectedCases,visited.size(),maxSteps,dependencyCalls));
        println("SMT4_ALLOCATE_REGISTER_COMPARE_OK");
    }
}
