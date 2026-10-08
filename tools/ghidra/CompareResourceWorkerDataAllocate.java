// Six-word variable-alignment allocation: bounded storage, services modeled.
// @category SMT4
import ghidra.pcode.emu.PcodeThread;
import ghidra.pcode.utils.Utils;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.lang.RegisterValue;
import java.math.BigInteger;
import java.nio.file.*;
import java.security.MessageDigest;
import java.util.*;
import java.io.*;

public class CompareResourceWorkerDataAllocate extends CompareResourceSync {
    static final long ENTRY=0x2bf7ec, END=0x2bf8ac, STATE=0x465120, RAWSTATE=0x465170;
    static final long RAW=0x2b26f0, ACCOUNT=0x2b260c, INDEX=0x2b3340, CONVERT=0x1245f0;
    static final long ACQUIRE=0x2c3afc, RELEASE=0x2c3a78, ZERO=0x2c3b9c;
    static final long HEAP=0x2c3a98, FIXED=0x144978, ACCOUNT_DATA=0x920000, TAIL=0x930000;
    static final long MASK=0xffffffffL;
    static final long[] STARTS={ENTRY,RAW,ACCOUNT,INDEX,CONVERT};
    static final long[] ENDS={END,0x2b285c,0x2b26ec,0x2b33cc,0x1246f0};
    int cases,directCases,integratedCases,zeroCases,wrapCases,lowZeroCases,nonPowerCases,conversions;
    int imageSize;
    boolean connected,recoverClear; long clearEntry; int executedClears,omittedLarge;
    @Override boolean originalCode(long pc) {
        for(int i=0;i<(connected?5:1);i++) if(within(pc,4,STARTS[i],ENDS[i])) return true;
        return false;
    }
    // Independent bit selection; power-of-two cases also checked by division below.
    long select(long value,long mask) {
        long result=0;
        for(int i=0;i<32;i++) if((mask/(1L<<i))%2!=0 && (value/(1L<<i))%2!=0) result+=1L<<i;
        return result;
    }
    class DataMachine extends SyncMachine {
        Map<Long,byte[]> expected=new TreeMap<>();
        List<String> trace=new ArrayList<>();
        boolean clearing; long clearCount;
        long raw,user,lock,rawSize,low,tag,initialCount,initialBytes,initialSelected,initialPayload;
        int selector;
        boolean nonempty,allocated;
        Random rng;
        DataMachine(byte[] mapped,byte[] binary) { super(mapped,binary); }
        @Override void initialize(boolean rebuiltPath,int kind,byte[] ignored) {
            // Reset only call state: preserve allocation bytes across conversion.
            executing=false;
            byte[] stack=new byte[0x1000]; Arrays.fill(stack,(byte)0x96); memory(STACK-0x1000,stack);
            for(var r:currentProgram.getLanguage().getRegisters())
                if(r.isBaseRegister() && !r.isProcessorContext()) register(r,0);
            for(int r=0;r<=12;r++) register("r"+r,0x12340000L+r);
            register("cpsr",0x10); register("sp",STACK); register("lr",RETURN);
            thread.overrideContext(new RegisterValue(currentProgram.getProgramContext().getBaseContextRegister(),BigInteger.ZERO));
        }
        void region(long start,int count) {
            long end=start+count;
            List<Long> merge=new ArrayList<>();
            for(var e:expected.entrySet()) if(start<=e.getKey()+e.getValue().length && end>=e.getKey()) {
                start=Math.min(start,e.getKey()); end=Math.max(end,e.getKey()+e.getValue().length); merge.add(e.getKey());
            }
            for(long key:merge) expected.remove(key);
            byte[] bytes=new byte[(int)(end-start)]; rng.nextBytes(bytes); expected.put(start,bytes);
        }
        void set(long a,int n,long v) {
            for(var e:expected.entrySet()) if(within(a,n,e.getKey(),e.getKey()+e.getValue().length)) {
                for(int i=0;i<n;i++) e.getValue()[(int)(a-e.getKey())+i]=(byte)(v >>> (8*i)); return;
            }
            throw new IllegalStateException("Oracle write "+Long.toHexString(a));
        }
        long get(long a,int n) {
            for(var e:expected.entrySet()) if(within(a,n,e.getKey(),e.getKey()+e.getValue().length)) {
                long v=0; for(int i=0;i<n;i++) v|=(e.getValue()[(int)(a-e.getKey())+i]&255L)<<(8*i); return v;
            }
            throw new IllegalStateException("Oracle read "+Long.toHexString(a));
        }
        void model(long a,int n,long v) {
            set(a,n,v); byte[] b=new byte[n]; for(int i=0;i<n;i++) b[i]=(byte)(v >>> (8*i)); memory(a,b);
        }
        void check(String stage) {
            for(var e:expected.entrySet()) {
                byte[] actual=memory(e.getKey(),e.getValue().length);
                int mismatch=Arrays.mismatch(e.getValue(),actual);
                require(mismatch<0,stage+" memory/guards "+Long.toHexString(e.getKey())+" offset="+mismatch+
                    (mismatch<0?"":" expected="+(e.getValue()[mismatch]&255)+" actual="+(actual[mismatch]&255)));
            }
        }
        @Override public void beforeStore(PcodeThread<byte[]> t,PcodeOp op,AddressSpace space,byte[] offset,int n,byte[] value) {
            long a=Utils.bytesToLong(offset,offset.length,false);
            if(within(a,n,STACK-256,STACK)) return;
            boolean ok=clearing && within(a,n,user,user+clearCount);
            ok|=allocated && (within(a,n,raw,raw+8) || within(a,n,(user-4)&MASK,((user-4)&MASK)+4));
            if(connected) ok|=within(a,n,raw+8,raw+20) || within(a,n,ACCOUNT_DATA,ACCOUNT_DATA+0x80) || within(a,n,TAIL,TAIL+8);
            require(ok,"Unexpected data store "+Long.toHexString(a));
        }
        @Override public void beforeLoad(PcodeThread<byte[]> t,PcodeOp op,AddressSpace space,byte[] offset,int n) {
            long a=Utils.bytesToLong(offset,offset.length,false);
            boolean ok=within(a,n,STACK-256,STACK+8) || within(a,n,BUILD,BUILD+imageSize);
            for(int i=0;i<STARTS.length;i++) ok|=within(a,n,STARTS[i],ENDS[i]+32);
            for(var e:expected.entrySet()) ok|=within(a,n,e.getKey(),e.getKey()+e.getValue().length);
            require(ok,"Unexpected data read "+Long.toHexString(a));
        }
        void headerOracle() {
            set(raw,4,rawSize); set(raw+4,2,low); set(raw+6,2,0); set((user-4)&MASK,4,raw);
        }
        void registrationOracle() {
            set(ACCOUNT_DATA+24,4,initialCount+1); set(ACCOUNT_DATA+28,4,initialBytes+rawSize);
            if((tag%256)<8) {
                set(ACCOUNT_DATA+60+selector*4,4,initialSelected+rawSize);
                set(ACCOUNT_DATA+92+selector*4,4,initialPayload+rawSize-low-60);
            }
            set(raw+12,4,nonempty?TAIL:0); set(raw+16,4,0); set(raw+8,2,tag);
            set(ACCOUNT_DATA+4,4,raw+12);
            if(nonempty) set(TAIL+4,4,raw+12); else set(ACCOUNT_DATA,4,raw+12);
        }
        void conversionOracle() {
            set(ACCOUNT_DATA+24,4,initialCount); set(ACCOUNT_DATA+28,4,initialBytes);
            if((tag%256)<8) {
                set(ACCOUNT_DATA+60+selector*4,4,initialSelected);
                set(ACCOUNT_DATA+92+selector*4,4,initialPayload);
            }
            set(ACCOUNT_DATA+4,4,nonempty?TAIL:0);
            if(nonempty) set(TAIL+4,4,0); else set(ACCOUNT_DATA,4,0);
            if(get(ACCOUNT_DATA+8,4)==raw+12) set(ACCOUNT_DATA+8,4,0);
            set(raw+8,2,0);
        }
        void effect(int effect,int stage) {
            if(effect==stage || effect==5) {
                lock=(lock ^ (0x87654321L+stage))&MASK; model(STATE+4,4,lock);
            }
        }
        void poison(long result) {
            for(int i=0;i<16;i++) register("s"+i,Integer.toUnsignedLong(rng.nextInt()));
            externalReturn(result); dependencyCalls++;
        }
        void call(boolean rebuiltPath,long[] args,long rawResult,int effect,boolean integrate,int topology,int index,long allocationTag,long seed) throws Exception {
            connected=integrate; initialize(rebuiltPath,0,new byte[0x144]); expected.clear(); trace.clear(); rng=new Random(seed);
            raw=rawResult; allocated=false; nonempty=topology!=0; selector=index; tag=allocationTag;
            long alignment=Math.max(args[4],128); low=alignment%65536;
            long sum=(args[3]+2*alignment+59)&MASK;
            rawSize=select(sum,(-alignment)&MASK);
            long start=(raw+60)&MASK;
            user=(start+select((low-select(start,(low-1)&MASK))&MASK,(low-1)&MASK))&MASK;
            if((alignment&(alignment-1))==0) require(rawSize==sum/alignment*alignment,"Division size oracle");
            if(low!=0 && (low&(low-1))==0) require(user==((start+low-1)/low*low&MASK),"Division user oracle");
            require((user&3)==0,"Corpus needs word-aligned backlink");
            region(raw-16,96);
            if(user==0) { region(0xffffffe0L,32); region(0,1088); }
            else region(user-16,1104);
            region(STATE-16,0x60); region(RAWSTATE-8,24);
            lock=0x87654320L; set(STATE+4,4,lock); set(RAWSTATE+4,4,0x940000);
            if(integrate) {
                require(rawSize!=0,"Connected raw router would return null");
                region(ACCOUNT_DATA-16,0x100); region(TAIL-16,48);
                set(STATE+8,4,ACCOUNT_DATA);
                for(int i=0;i<4;i++) { set(STATE+28+4*i,4,i==index?raw:0x800000+i*0x1000); set(STATE+44+4*i,4,i==index?0:32); }
                set(ACCOUNT_DATA,4,nonempty?TAIL:0); set(ACCOUNT_DATA+4,4,nonempty?TAIL:0);
                set(ACCOUNT_DATA+8,4,topology==2?raw+12:TAIL); set(ACCOUNT_DATA+56,2,tag);
                set(TAIL,4,0); set(TAIL+4,4,0);
                // Deliberately wrap the global and selected counters on some calls.
                initialCount=(seed%2==0)?MASK:17; initialBytes=(seed%2==0)?MASK-7:100;
                initialSelected=MASK-13; initialPayload=3;
                set(ACCOUNT_DATA+24,4,initialCount); set(ACCOUNT_DATA+28,4,initialBytes);
                set(ACCOUNT_DATA+60+index*4,4,initialSelected); set(ACCOUNT_DATA+92+index*4,4,initialPayload);
            }
            for(var e:expected.entrySet()) memory(e.getKey(),e.getValue());
            byte[] upper=new byte[64]; rng.nextBytes(upper); put(upper,0,args[4]); put(upper,4,args[5]); memory(STACK,upper);
            byte[] stack=memory(STACK-0x1000,0x1000);
            for(int i=0;i<4;i++) register("r"+i,args[i]);
            register("s16",0x81234567L); register("s17",0xfedcba98L);
            thread.overrideCounter(toAddr(rebuiltPath?entries[0]:ENTRY)); executing=true;
            long rawEntry=rebuiltPath?entries[1]:RAW, accountEntry=rebuiltPath?entries[2]:ACCOUNT;
            boolean heapRoute=args[0]==0x100 || args[0]==0x10000;
            long innerLock=0x940000+(args[0]==0x100?0x74:0xe0);
            List<Long> calls=new ArrayList<>(List.of(ACQUIRE,rawEntry));
            if(integrate) calls.addAll(heapRoute?List.of(ACQUIRE,HEAP,RELEASE):List.of(FIXED));
            calls.addAll(List.of(accountEntry,ZERO,RELEASE));
            int at=0,steps=0;
            while(thread.getCounter().getOffset()!=RETURN) {
                long pc=thread.getCounter().getOffset();
                if(recoverClear && rebuiltPath && pc==clearEntry)pc=ZERO;
                if(pc==rawEntry || pc==accountEntry || pc==ACQUIRE || pc==RELEASE || pc==HEAP || pc==FIXED || pc==ZERO) {
                    require(at<calls.size() && calls.get(at++)==pc,"Data dependency order");
                    require((register("sp")&7)==0,"Dependency stack alignment");
                    if(pc==accountEntry) headerOracle();
                    check("Dependency "+Long.toHexString(pc));
                    if(pc==rawEntry) {
                        for(int i=0;i<4;i++) require(register("r"+i)==(i==3?rawSize:args[i]),"Raw argument "+i);
                        require(word(memory(register("sp"),4),0)==args[5],"Raw direction/sixth forwarding");
                        trace.add("raw:"+Arrays.toString(args)+":"+rawSize);
                        if(integrate) { step(rebuiltPath,++steps); continue; }
                        allocated=true; effect(effect,2); poison(raw); continue;
                    }
                    if(pc==accountEntry) {
                        require(register("r0")==raw,"Registration address"); trace.add("register:"+raw);
                        if(integrate) { registrationOracle(); step(rebuiltPath,++steps); continue; }
                        for(int i=0;i<24;i++) model(raw+8+i,1,rng.nextInt(256));
                        effect(effect,3); poison(0xface8765L); continue;
                    }
                    if(pc==HEAP || pc==FIXED) {
                        require(register("r1")==rawSize,"Storage size");
                        if(pc==HEAP) {
                            require(register("r0")==0x940000+(args[0]==0x100?0x1c:0x88),"Heap object");
                            long align=args[1]==0x100?4:args[1]==0x101?128:args[1]==0x103?64:(args[1]==0x104||args[1]==0x105)?16:8;
                            if(args[5]==0) align=(-align)&MASK;
                            require(register("r2")==align && register("r3")==0,"Heap alignment/options");
                            require(word(memory(register("sp"),8),0)==0 && word(memory(register("sp"),8),4)==0,"Heap stacked options");
                        } else require(register("r0")== (args[0]==0x20000?0x4e4100:0x4e411c) && register("r2")==args[0] && register("r3")==RAWSTATE,"Fixed routing");
                        trace.add("storage:"+args[0]+":"+rawSize); allocated=true; effect(effect,2); poison(raw); continue;
                    }
                    if(pc==ZERO) {
                        require(register("r0")==user && register("r1")==args[3],"Zero arguments"); trace.add("zero:"+user+":"+args[3]);
                        if(recoverClear) {
                            require(args[3]<=1024,"Mapped clear domain");
                            for(int i=0;i<args[3];i++)set(user+i,1,0);
                            long ret=register("lr")&MASK,sp=register("sp");int clearSteps=0;
                            clearing=true;clearCount=args[3];
                            do {
                                long atPC=thread.getCounter().getOffset();
                                require(rebuiltPath?within(atPC,4,BUILD,BUILD+codeSize):within(atPC,4,ZERO,0x2c3bdc)||within(atPC,4,0x2c4b88,0x2c4bd8),"Zero PC");
                                if(!rebuiltPath)visited.add(atPC);
                                require(++clearSteps<4096,"Zero budget");thread.stepInstruction();
                            }while(thread.getCounter().getOffset()!=ret);
                            clearing=false;require(register("sp")==sp,"Zero SP");check("Executed zero");executedClears++;continue;
                        }
                        if(args[3]<=1024) for(int i=0;i<args[3];i++) model(user+i,1,0);
                        effect(effect,4); poison(0xdeadfaceL); continue;
                    }
                    boolean outer=at==1 || at==calls.size();
                    require(register("r0")== (outer?lock:innerLock),"Lock argument/reload");
                    trace.add((pc==ACQUIRE?"acquire:":"release:")+register("r0"));
                    if(at==1) effect(effect,1);
                    poison(0xbeefabcdL); continue;
                }
                step(rebuiltPath,++steps);
            }
            require(at==calls.size(),"Missing dependencies"); require(register("r0")==user,"User result"); check("Allocation final");
            require(Arrays.equals(upper,memory(STACK,64)),"Caller stack/six words");
            byte[] actualStack=memory(STACK-0x1000,0x1000);
            for(int i=0;i<stack.length-256;i++) require(stack[i]==actualStack[i],"Stack guard");
            require(register("s16")==0x81234567L && register("s17")==0xfedcba98L,"d8 preserved"); finish(steps);
            if(integrate) {
                // Consume the actual allocation-produced backlink, tag and list node.
                initialize(rebuiltPath,0,new byte[0x144]); register("r0",user);
                thread.overrideCounter(toAddr(rebuiltPath?entries[4]:CONVERT)); executing=true;
                conversionOracle(); steps=0;
                while(thread.getCounter().getOffset()!=RETURN) step(rebuiltPath,++steps);
                require(register("r0")==raw,"Conversion raw result"); check("Converted allocation"); finish(steps);
            }
        }
    }
    void compare(DataMachine a,DataMachine b,PrintWriter log,long[] args,long raw,int effect,boolean integrated,int topology,int index,long tag) throws Exception {
        if(recoverClear && args[3]>1024) {omittedLarge++;return;}
        try {
            a.call(false,args,raw,effect,integrated,topology,index,tag,ENTRY+cases);
            b.call(true,args,raw,effect,integrated,topology,index,tag,ENTRY+cases);
            require(a.trace.equals(b.trace),"Original/rebuilt call trace");
        } catch(Exception ex) { throw new IllegalStateException("Worker data case "+cases+" args="+Arrays.toString(args)+" raw="+raw+" integrated="+integrated,ex); }
        long align=Math.max(args[4],128);
        if(integrated) { integratedCases++; conversions++; } else directCases++;
        if(args[3]<=1024) zeroCases++;
        if(args[3]+align*2+59>MASK) wrapCases++;
        if(align%65536==0) lowZeroCases++;
        if((align&(align-1))!=0) nonPowerCases++;
        log.printf("%d\t%s\t%x\t%d\t%b\t%d\t%d\t%x%n",++cases,Arrays.toString(args),raw,effect,integrated,topology,index,tag);
    }
    @Override public void run() throws Exception {
        Path out=Path.of(getScriptArgs()[0]); require(!Files.exists(out.resolve("comparison.json")),"Existing output");
        recoverClear=Files.exists(out.resolve("clear-entry.txt"));
        if(recoverClear)clearEntry=Long.parseLong(Files.readString(out.resolve("clear-entry.txt")).trim());
        byte[] mapped=new byte[0x377000]; require(currentProgram.getMemory().getBytes(toAddr(0x100000),mapped)==mapped.length,"Map");
        require(HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(mapped)).equals("834938d18d2b7c688311c46c27bed813d0d7a9f8e3cbb61da8a6a3f23d360ebd"),"Hash");
        byte[] binary=Files.readAllBytes(out.resolve("resource-worker-data-allocate.bin")); imageSize=binary.length;
        codeSize=Integer.parseInt(Files.readString(out.resolve("text-size.txt")).trim());
        require(codeSize>0 && codeSize<=0x2000,"Build size");
        List<String> lines=Files.readAllLines(out.resolve("entries.txt")); require(lines.size()==5,"Entries");
        for(int i=0;i<5;i++) { entries[i]=Long.parseLong(lines.get(i)); require(within(entries[i],4,BUILD,BUILD+codeSize),"Entry"); }
        DataMachine a=new DataMachine(mapped,binary),b=new DataMachine(mapped,binary);
        long[] sizes={0,1,68,69,127,128,197,1024,0x7fffffffL,0x80000000L,0xfffffec4L,0xfffffec5L,0xfffffec6L,MASK};
        long[] alignments={0,1,127,128,129,132,192,256,384,512,4096,32768,65532,65536,65537,65538,65540,0x10080,0x80000000L,0x80000100L,0xfffffffcL,0xfffffffeL};
        try(PrintWriter log=new PrintWriter(Files.newBufferedWriter(out.resolve("results.tsv")))) {
            log.println("case\targuments\traw\teffect\tintegrated\ttopology\tindex\ttag");
            // Boundary arithmetic; sparse guarded storage also supports a zero user result.
            for(long alignment:alignments) for(long size:sizes) for(int effect=0;effect<6;effect++)
                compare(a,b,log,new long[]{0x100,0x100,0x89abcdefL,size,alignment,0xfedcba98L},0x90013c,effect,false,0,0,0);
            // Size addition wrap and rounding transitions for each effective alignment.
            for(long alignment:alignments) for(int delta=-1;delta<=1;delta++) {
                long effective=Math.max(alignment,128), boundary=(-2*effective-59)&MASK;
                compare(a,b,log,new long[]{0x100,0x100,0,(boundary+delta)&MASK,alignment,1},0x900100,5,false,0,0,0);
                compare(a,b,log,new long[]{0x100,0x100,0,(effective-59+delta)&MASK,alignment,0},0x900100,5,false,0,0,0);
            }
            // All raw residues modulo the worker's common 256-byte alignment, including exact alignment.
            for(int residue=0;residue<256;residue+=4) for(long base:new long[]{0x900100,0x89000100L})
                compare(a,b,log,new long[]{0x10000,0x100,0,24,256,residue%8==0?0:1},base+residue,residue%6,false,0,0,0);
            // Exact selectors and arbitrary six-word forwarding: no bypass at this entry.
            long[] values={0,1,0x100,0x101,0x104,0x20000,0x30000,0x80000000L,MASK};
            for(int slot:new int[]{0,1,2,5}) for(long value:values) {
                long[] args={0x100,0x100,0,24,256,1}; args[slot]=value;
                compare(a,b,log,args,0x89000100L,5,false,0,0,0);
            }
            // Actual router/registration/selector/conversion code; storage provisioning remains modeled.
            for(long route:new long[]{0x100,0x10000,0x20000,0x30000}) for(long alignment:new long[]{128,256,4096})
            for(long tag:new long[]{0,7,8,0x100,0xff08}) for(int topology=0;topology<3;topology++) for(int index=0;index<4;index++) {
                long[] options={0x100,0x101,0x103,0x104,0x105,0};
                compare(a,b,log,new long[]{route,options[cases%options.length],0x76543210,topology==0?0:197,alignment,index%2},
                    (index%2==0?0x900100:0x89000100L)+index*4,5,true,topology,index,tag);
            }
        }
        StringBuilder listing=new StringBuilder(); int newInstructions=0;
        for(long pc=ENTRY;pc<END;pc+=4) {
            require(visited.contains(pc),"Unvisited new instruction "+Long.toHexString(pc)); newInstructions++;
            var inst=currentProgram.getListing().getInstructionAt(toAddr(pc)); require(inst!=null,"Missing instruction");
            listing.append(String.format("%08x %s%n",pc,inst));
        }
        Files.writeString(out.resolve("original-ghidra.txt"),listing);
        Files.writeString(out.resolve("visited.txt"),String.join("\n",visited.stream().map(v->String.format("%08x",v)).toList())+"\n");
        Files.writeString(out.resolve("comparison.json"),String.format(Locale.ROOT,
            "{\"cases\":%d,\"direct_cases\":%d,\"integrated_cases\":%d,\"conversion_calls\":%d,\"materialized_zero_cases\":%d,\"wrapping_size_cases\":%d,\"low16_zero_cases\":%d,\"non_power_of_two_cases\":%d,\"new_instruction_addresses\":%d,\"all_visited_addresses\":%d,\"dependency_calls_both_paths\":%d,\"max_steps\":%d,\"storage_locks_zero_modeled\":true,\"live_verified\":false}\n",
            cases,directCases,integratedCases,conversions,zeroCases,wrapCases,lowZeroCases,nonPowerCases,newInstructions,visited.size(),dependencyCalls,maxSteps));
        if(recoverClear)Files.writeString(out.resolve("clear.json"),"{\"executed_calls_both\":"+executedClears+",\"omitted_unmapped_large_cases\":"+omittedLarge+",\"clear_model_removed\":true,\"clear_callback_effect_removed\":true,\"max_materialized_bytes\":1024,\"storage_locks_modeled\":true}\n");
        println("SMT4_WORKER_DATA_ALLOCATE_COMPARE_OK");
    }
}
