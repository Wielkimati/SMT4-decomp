// Locale category query, ordinary configuration and unchecked encoded restoration.
// @category SMT4
import ghidra.pcode.emu.PcodeThread;
import ghidra.pcode.utils.Utils;
import ghidra.program.model.address.*;
import ghidra.program.model.pcode.PcodeOp;
import java.nio.file.*;
import java.util.*;
import java.io.*;

public class CompareResourceWorkerLocaleConfig extends CompareResourceWorkerLocaleBootstrap {
    static final long[] CONFIG={0x2c6aa8,0x2c6b46,0x2c6baa}, CONFIG_END={0x2c6b46,0x2c6baa,0x2c6c3e};
    static final long OUT=0x911000, POINTER=0x910040, FIXED=0x42a184;
    long[] configEntries=new long[3];
    int configCases,connectedConfig,roundTrips;
    @Override boolean pathCode(long pc) { return within(pc,2,CONFIG[0],CONFIG_END[2]) || super.pathCode(pc); }
    @Override IoMachine makeMachine(byte[] mapped,byte[] binary) { return new ConfigMachine(mapped,binary); }
    class ConfigMachine extends BootstrapMachine {
        boolean preparing,configActive;
        List<String> publications=new ArrayList<>();
        Set<Long> inputReads=new TreeSet<>();
        ConfigMachine(byte[] mapped,byte[] binary) { super(mapped,binary); }
        @Override void bind(boolean rebuilt) {
            if(preparing) { privateTable(rebuilt); return; }
            super.bind(rebuilt);
            long pc=thread.getCounter().getOffset(),flags=register("cpsr");
            long[] saved=new long[15]; for(int r=0;r<15;r++) saved[r]=register(r==13 ? "sp" : r==14 ? "lr" : "r"+r);
            boolean oldExecuting=executing;
            try {
                memory(POINTER-64,new byte[192]);
                byte[] name=connectedConfig%4<2 ? new byte[]{0} : encode(new long[]{FIXED,REAL_LOCALE,FIXED,0x42a168,FIXED});
                step(rebuilt,1,31,name,0); connectedConfig++;
            } catch(Exception e) { throw new IllegalStateException("Worker I/O case connected configuration",e); }
            finally {
                executing=oldExecuting;
                for(int r=0;r<15;r++) register(r==13 ? "sp" : r==14 ? "lr" : "r"+r,saved[r]);
                select(pc,(flags&32)!=0); register("cpsr",flags);
            }
        }
        @Override public void beforeLoad(PcodeThread<byte[]> t,PcodeOp op,AddressSpace space,byte[] offset,int size) {
            long a=Utils.bytesToLong(offset,offset.length,false);
            if(configActive && within(a,size,LEFT,LEFT+128)) for(int i=0;i<size;i++) inputReads.add(a+i);
            if(within(a,size,POINTER-64,POINTER+128) || within(a,size,OUT-16,OUT+64)) return;
            super.beforeLoad(t,op,space,offset,size);
        }
        @Override public void beforeStore(PcodeThread<byte[]> t,PcodeOp op,AddressSpace space,byte[] offset,int size,byte[] value) {
            long a=Utils.bytesToLong(offset,offset.length,false);
            if(configActive && size==4 && within(a,size,CONTEXT,CONTEXT+20) && a%4==0) {
                publications.add((a-CONTEXT)/4+":"+Utils.bytesToLong(value,4,false)); return;
            }
            if(configActive && size==1 && within(a,size,OUT,OUT+42)) return;
            super.beforeStore(t,op,space,offset,size,value);
        }
        void reset(boolean rebuilt,long[] words) {
            preparing=true; releasedObject=false; initialize(rebuilt,0,new byte[0x144]); preparing=false;
            destroyed=false; active=false; trace.clear(); connected=false; pathFixtures(0,false,false,0); privateTable(rebuilt);
            for(int i=0;i<5;i++) writeWord(CONTEXT+i*4,words[i]);
            byte[] synthetic=new byte[192]; Arrays.fill(synthetic,(byte)0x8e); memory(POINTER-64,synthetic);
            writeWord(POINTER-4,32); writeWord(POINTER+12,0xffffffe0L);
        }
        long step(boolean rebuilt,int kind,long mask,byte[] name,int alignment) throws Exception {
            byte[] input=new byte[144]; Arrays.fill(input,(byte)0xe1);
            if(name!=null) System.arraycopy(name,0,input,16+alignment,name.length);
            memory(LEFT-16,input);
            byte[] output=new byte[80]; Arrays.fill(output,(byte)0xa7); memory(OUT-16,output);
            byte[] bank=memory(BANK,192),data=memory(0x42a040,0x150),synthetic=memory(POINTER-64,192);
            long[] words=new long[5]; for(int i=0;i<5;i++) words[i]=get(CONTEXT+i*4);
            List<String> expectedStores=new ArrayList<>();
            boolean valid=kind!=1 || mask>0 && mask<32,failed=false;
            boolean encoded=kind==1 && name!=null && name[0]=='*';
            if(valid && kind!=0 && (kind==2 || name!=null)) {
                if(encoded) {
                    for(int i=0;i<5;i++) {
                        long v=0;
                        for(int j=0;j<8;j++) { int c=name[1+8*i+j]&255; v=((v*16)|((c-(c<=57 ? 48 : 87))&MASK))&MASK; }
                        if((mask&(1<<i))!=0) { words[i]=v; expectedStores.add(i+":"+v); }
                    }
                } else {
                    String text=name==null ? "" : new String(name,java.nio.charset.StandardCharsets.ISO_8859_1).split("\0",-1)[0];
                    for(int i:new int[]{1,0,2,3,4}) if((mask&(1<<i))!=0) {
                        if(i==1 && !text.isEmpty() && !text.equals("SJIS") || i==3 && !text.isEmpty() && !text.equals("C")) { failed=true; break; }
                        words[i]=i==1 ? REAL_LOCALE : i==3 ? 0x42a168 : FIXED;
                        expectedStores.add(i+":"+words[i]);
                    }
                }
            }
            for(int i=0;i<5;i++) put(bank,(int)(CONTEXT-BANK)+4*i,words[i]);
            long expected=0;
            if(valid && !failed) {
                if(Long.bitCount(mask)>1) { byte[] serialized=encode(words); System.arraycopy(serialized,0,output,16,41); output[57]=0; expected=OUT; }
                else if(mask==1 || mask==2 || mask==4 || mask==8 || mask==16) {
                    long value=words[Long.numberOfTrailingZeros(mask)];
                    expected=value==0 ? 0x2c6c40 : ((value&~3L)+get((value&~3L)-4))&MASK;
                }
            }
            publications.clear(); inputReads.clear(); configActive=true;
            register("r0",OUT); register("r1",mask); register("r2",name==null ? 0 : LEFT+alignment); register("lr",RETURN);
            select(rebuilt ? configEntries[kind] : CONFIG[kind],!rebuilt); executing=true;
            long result=executePath(rebuilt); configActive=false;
            require(result==expected,"Configuration return expected="+expected+" actual="+result);
            require(publications.equals(expectedStores),"Configuration ordered publication expected="+expectedStores+" actual="+publications);
            require(Arrays.equals(bank,memory(BANK,192)),"Configuration guarded bank");
            require(Arrays.equals(output,memory(OUT-16,80)),"Configuration guarded serialization");
            require(Arrays.equals(input,memory(LEFT-16,144)),"Configuration input immutable");
            require(Arrays.equals(data,memory(0x42a040,0x150)) && Arrays.equals(synthetic,memory(POINTER-64,192)),"Configuration relative data immutable");
            if(valid && encoded) {
                Set<Long> expectedReads=new TreeSet<>(); for(int i=0;i<41;i++) expectedReads.add(LEFT+alignment+i);
                require(inputReads.equals(expectedReads),"Restore exact 41-byte readable footprint");
            }
            if(kind==1 && !valid) require(inputReads.isEmpty(),"Invalid mask must not read name");
            for(byte v:memory(STACK-0x1000,0xe00)) require(v==(byte)0x96,"Configuration stack guard");
            return result;
        }
    }
    byte[] encode(long[] words) {
        StringBuilder s=new StringBuilder("*"); for(long value:words) s.append(String.format(Locale.ROOT,"%08x",value));
        return s.toString().getBytes(java.nio.charset.StandardCharsets.US_ASCII);
    }
    void probe(ConfigMachine a,ConfigMachine b,int kind,long mask,byte[] name,int alignment,long[] words,PrintWriter log) throws Exception {
        try {
            a.reset(false,words); b.reset(true,words);
            long x=a.step(false,kind,mask,name,alignment),y=b.step(true,kind,mask,name,alignment);
            require(x==y && Arrays.equals(a.memory(BANK,192),b.memory(BANK,192)) && Arrays.equals(a.memory(OUT-16,80),b.memory(OUT-16,80)),"Original/rebuilt configuration agreement");
        } catch(Exception e) { throw new IllegalStateException("Worker I/O case configuration kind="+kind+" mask="+mask+" alignment="+alignment+" name="+(name==null ? "null" : HexFormat.of().formatHex(name)),e); }
        configCases++; log.printf("%d\t%d\t%d\t%s%n",kind,mask,alignment,name==null ? "null" : HexFormat.of().formatHex(name));
    }
    @Override void preChecks(byte[] mapped,byte[] binary,Path out) throws Exception {
        ConfigMachine a=new ConfigMachine(mapped,binary),b=new ConfigMachine(mapped,binary);
        try(PrintWriter log=new PrintWriter(Files.newBufferedWriter(out.resolve("config-results.tsv")))) {
            log.println("kind\tmask\talignment\tname_hex");
            long[] defaults={FIXED,REAL_LOCALE,FIXED,0x42a168,FIXED};
            List<Long> masks=new ArrayList<>(); for(long m=0;m<=33;m++) masks.add(m); masks.addAll(List.of(0x80000000L,0x80000001L,MASK));
            for(long mask:masks) {
                for(long pointer:new long[]{0,POINTER,POINTER+1,POINTER+2,POINTER+3,POINTER+16,POINTER+19}) {
                    long[] words={pointer,pointer,pointer,pointer,pointer};
                    probe(a,b,0,mask,null,0,words,log); probe(a,b,1,mask,null,0,words,log);
                }
                for(int align=0;align<4;align++) for(String name:new String[]{"","SJIS","C","sjis","SJI","SJISx","Cx","X","\u00ff"}) {
                    byte[] input=(name+"\0").getBytes(java.nio.charset.StandardCharsets.ISO_8859_1);
                    probe(a,b,1,mask,input,align,defaults,log);
                    probe(a,b,2,mask,input,align,defaults,log);
                }
                probe(a,b,2,mask,null,0,defaults,log);
                probe(a,b,1,mask,encode(defaults),0,new long[5],log);
            }
            // All byte values, at early and final positions, expose unvalidated arithmetic.
            for(int value=0;value<256;value++) for(int position:new int[]{1,8,40}) {
                byte[] input=encode(new long[]{0x01234567L,0x89abcdefL,MASK,0,0x76543210}); input[position]=(byte)value;
                probe(a,b,1,position==1 ? 3 : position==8 ? 10 : 31,input,value%4,defaults,log);
            }
            for(boolean rebuilt:new boolean[]{false,true}) {
                ConfigMachine machine=rebuilt ? b : a;
                machine.reset(rebuilt,new long[]{POINTER+3,REAL_LOCALE,0,POINTER+19,FIXED});
                machine.step(rebuilt,0,31,null,0); byte[] saved=machine.memory(OUT,41);
                machine.step(rebuilt,1,31,new byte[]{0},0);
                machine.step(rebuilt,1,31,saved,0);
                require(Arrays.equals(saved,machine.memory(OUT,41)),"Persistent configuration round trip"); roundTrips++;
            }
        }
        super.preChecks(mapped,binary,out);
    }
    @Override String extraChecks(byte[] mapped,byte[] binary,Path out) throws Exception {
        String inherited=super.extraChecks(mapped,binary,out); StringBuilder listing=new StringBuilder(); int count=0;
        for(int i=0;i<3;i++) for(var ins:currentProgram.getListing().getInstructions(new AddressSet(toAddr(CONFIG[i]),toAddr(CONFIG_END[i]-1)),true)) {
            long pc=ins.getAddress().getOffset(); require(visited.contains(pc),"Unvisited configuration instruction "+Long.toHexString(pc)); count++;
            listing.append(String.format("%08x %s %s visited=true%n",pc,HexFormat.of().formatHex(ins.getBytes()),ins));
        }
        Files.writeString(out.resolve("original-config-ghidra.txt"),listing);
        return inherited+String.format(Locale.ROOT,",\"direct_config_cases\":%d,\"persistent_config_roundtrips_both\":%d,\"connected_configuration_calls_both\":%d,\"new_config_instruction_addresses\":%d,\"locale_configuration_recovered\":true,\"restore_exact_read_footprints_checked\":true",configCases,roundTrips,connectedConfig,count);
    }
    @Override public void run() throws Exception {
        var lines=Files.readAllLines(Path.of(getScriptArgs()[0]).resolve("entries.txt"));
        for(int i=0;i<3;i++) configEntries[i]=Long.parseLong(lines.get(33+i));
        super.run();
    }
}
