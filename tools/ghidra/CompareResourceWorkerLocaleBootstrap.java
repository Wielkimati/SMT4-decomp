// Locale bootstrap/selectors and exact alignment-dependent name comparison.
// @category SMT4
import ghidra.pcode.emu.PcodeThread;
import ghidra.pcode.utils.Utils;
import ghidra.program.model.address.*;
import ghidra.program.model.pcode.PcodeOp;
import java.nio.file.*;
import java.util.*;
import java.io.*;

public class CompareResourceWorkerLocaleBootstrap extends CompareResourceWorkerLocale {
    static final long[] BOOT={0x10236c,0x138208,0x14d908,0x2aa858};
    static final long[] ENDS={0x1023b8,0x138248,0x14d948,0x2aa910};
    static final long LEFT=0x90e000, RIGHT=0x90f000;
    long[] bootEntries=new long[4];
    int compareCases,selectorCases,bootstrapCases,connectedBootstraps;
    @Override boolean pathCode(long pc) {
        for(int i=0;i<4;i++) if(within(pc,4,BOOT[i],ENDS[i])) return true;
        return super.pathCode(pc);
    }
    @Override IoMachine makeMachine(byte[] mapped,byte[] binary) { return new BootstrapMachine(mapped,binary); }
    class BootstrapMachine extends LocaleMachine {
        boolean bootActive;
        List<String> stores=new ArrayList<>();
        Set<Long> nameReads=new TreeSet<>();
        BootstrapMachine(byte[] mapped,byte[] binary) { super(mapped,binary); }
        void privateTable(boolean rebuilt) {
            byte[] table=localeBytes.clone();
            if(rebuilt) put(table,0x103,(decodeEntry-(REAL_LOCALE+0x103))&MASK);
            memory(REAL_LOCALE,table); callbackTarget=0;
        }
        @Override void bind(boolean rebuilt) {
            privateTable(rebuilt);
            // Discard the inherited setup's table pointer; execution must publish both slots.
            writeWord(CONTEXT+4,0xdeadbeefL); writeWord(CONTEXT+12,0xfedcba98L);
            long pc=thread.getCounter().getOffset(),flags=register("cpsr");
            long[] saved=new long[15]; for(int r=0;r<15;r++) saved[r]=register(r==13 ? "sp" : r==14 ? "lr" : "r"+r);
            boolean oldExecuting=executing;
            try { bootstrap(rebuilt); connectedBootstraps++; }
            catch(Exception e) { throw new IllegalStateException("Worker I/O case connected bootstrap",e); }
            finally {
                executing=oldExecuting;
                for(int r=0;r<15;r++) register(r==13 ? "sp" : r==14 ? "lr" : "r"+r,saved[r]);
                select(pc,(flags&32)!=0); register("cpsr",flags);
            }
        }
        @Override public void beforeLoad(PcodeThread<byte[]> t,PcodeOp op,AddressSpace space,byte[] offset,int size) {
            long a=Utils.bytesToLong(offset,offset.length,false);
            if(within(a,size,LEFT-16,LEFT+128) || within(a,size,RIGHT-16,RIGHT+128)) {
                for(int i=0;i<size;i++) nameReads.add(a+i); return;
            }
            super.beforeLoad(t,op,space,offset,size);
        }
        @Override public void beforeStore(PcodeThread<byte[]> t,PcodeOp op,AddressSpace space,byte[] offset,int size,byte[] value) {
            long a=Utils.bytesToLong(offset,offset.length,false);
            if(bootActive && size==4 && (a==CONTEXT+4 || a==CONTEXT+12)) {
                stores.add(Long.toHexString(a)+":"+Utils.bytesToLong(value,4,false)); return;
            }
            super.beforeStore(t,op,space,offset,size,value);
        }
        void bootstrap(boolean rebuilt) throws Exception {
            byte[] bank=memory(BANK,192),data=memory(0x42a040,0x150);
            put(bank,(int)(CONTEXT+4-BANK),REAL_LOCALE); put(bank,(int)(CONTEXT+12-BANK),0x42a168);
            stores.clear(); bootActive=true; executing=true;
            register("lr",RETURN); select(rebuilt ? bootEntries[0] : BOOT[0],false);
            executePath(rebuilt); bootActive=false;
            require(Arrays.equals(bank,memory(BANK,192)),"Bootstrap guarded publication");
            require(stores.equals(List.of("4efca4:4366413","4efcac:4366696")),"Bootstrap store order/value "+stores);
            require(Arrays.equals(data,memory(0x42a040,0x150)),"Bootstrap private data immutable");
        }
        long direct(boolean rebuilt,int kind,byte[] left,byte[] right,int la,int ra,boolean nullName,long ignored) throws Exception {
            releasedObject=false; initialize(rebuilt,0,new byte[0x144]); destroyed=false; active=false; trace.clear(); connected=false;
            pathFixtures(0,false,false,0); privateTable(rebuilt);
            byte[] l=new byte[144],r=new byte[144]; Arrays.fill(l,(byte)0x81); Arrays.fill(r,(byte)0xfe);
            System.arraycopy(left,0,l,16+la,left.length); System.arraycopy(right,0,r,16+ra,right.length);
            memory(LEFT-16,l); memory(RIGHT-16,r);
            byte[] bank=memory(BANK,192),data=memory(0x42a040,0x150);
            if(kind==0) {
                writeWord(CONTEXT+4,ignored); writeWord(CONTEXT+12,ignored^MASK);
                bootstrap(rebuilt); bootstrap(rebuilt); // Same storage: publication is idempotent.
                return 0;
            }
            nameReads.clear();
            register("r0",kind==3 ? LEFT+la : ignored); register("r1",nullName ? 0 : RIGHT+ra);
            register("lr",RETURN); select(rebuilt ? bootEntries[kind] : BOOT[kind],false); executing=true;
            long result=executePath(rebuilt);
            if(kind==3) {
                int stop=0;
                while(left[stop]!=0 && left[stop]==right[stop]) stop++;
                int extent=la==0 && ra==0 ? (stop/4+1)*4 : stop+1;
                Set<Long> expectedReads=new TreeSet<>();
                for(int i=0;i<extent;i++) { expectedReads.add(LEFT+la+i); expectedReads.add(RIGHT+ra+i); }
                require(nameReads.equals(expectedReads),"Comparison exact readable footprint");
            }
            require(Arrays.equals(bank,memory(BANK,192)),"Selector/compare bank immutable");
            require(Arrays.equals(l,memory(LEFT-16,144)) && Arrays.equals(r,memory(RIGHT-16,144)),"Name inputs/guards immutable");
            require(Arrays.equals(data,memory(0x42a040,0x150)),"Selector private data immutable");
            for(byte v:memory(STACK-0x1000,0xe00)) require(v==(byte)0x96,"Name stack guard");
            return result;
        }
    }
    long oracle(byte[] a,byte[] b,boolean aligned) {
        for(int i=0;;i++) {
            int x=a[i]&255,y=b[i]&255;
            if(x!=y) {
                if(!aligned) return (x-y)&MASK;
                // Equivalent exact scale/sign derived independently from byte ordering.
                return x>y ? (256L-x+y)*0x800000L : 0x80000000L+(y-x)*0x800000L;
            }
            if(x==0) return 0;
        }
    }
    void probe(BootstrapMachine a,BootstrapMachine b,int kind,byte[] left,byte[] right,int la,int ra,boolean nil,long ignored,PrintWriter log) throws Exception {
        long expected=0;
        if(kind==3) expected=oracle(left,right,la==0 && ra==0);
        else if(kind!=0) {
            byte[] name=(kind==1 ? "SJIS\0" : "C\0").getBytes(java.nio.charset.StandardCharsets.US_ASCII);
            boolean matches=nil || right[0]==0 || Arrays.equals(Arrays.copyOf(right,name.length),name);
            expected=matches ? kind==1 ? 0x42a04c : 0x42a168 : 0;
        }
        try {
            long x=a.direct(false,kind,left,right,la,ra,nil,ignored),y=b.direct(true,kind,left,right,la,ra,nil,ignored);
            require(x==expected && y==expected,"Name return expected="+expected+" original="+x+" rebuilt="+y);
        } catch(Exception e) { throw new IllegalStateException("Worker I/O case bootstrap kind="+kind+" align="+la+","+ra+" left="+HexFormat.of().formatHex(left)+" right="+HexFormat.of().formatHex(right),e); }
        if(kind==3) compareCases++; else if(kind==0) bootstrapCases++; else selectorCases++;
        log.printf("%d\t%d\t%d\t%s\t%d\t%s\t%s\t%d%n",kind,la,ra,nil,ignored,HexFormat.of().formatHex(left),HexFormat.of().formatHex(right),expected);
    }
    @Override void preChecks(byte[] mapped,byte[] binary,Path out) throws Exception {
        BootstrapMachine a=new BootstrapMachine(mapped,binary),b=new BootstrapMachine(mapped,binary);
        try(PrintWriter log=new PrintWriter(Files.newBufferedWriter(out.resolve("bootstrap-results.tsv")))) {
            log.println("kind\tleft_alignment\tright_alignment\tnull_name\tignored\tleft_hex\tright_hex\treturn");
            for(long initial:new long[]{0,REAL_LOCALE,MASK}) probe(a,b,0,new byte[]{0},new byte[]{0},0,0,false,initial,log);
            for(int kind:new int[]{1,2}) for(int ra=0;ra<4;ra++) for(long ignored:new long[]{0,1,0x80000000L,MASK}) {
                probe(a,b,kind,new byte[]{0},new byte[]{0},0,ra,true,ignored,log);
                for(String s:new String[]{"","SJIS","C","sjis","c","SJI","SJISx","Cx","X","\u0080","\u00ff"})
                    probe(a,b,kind,new byte[]{0},(s+"\0").getBytes(java.nio.charset.StandardCharsets.ISO_8859_1),0,ra,false,ignored,log);
            }
            for(int la=0;la<4;la++) for(int ra=0;ra<4;ra++) for(int pos=0;pos<18;pos++) {
                byte[] x=new byte[24],y=new byte[24]; Arrays.fill(x,(byte)'a'); Arrays.fill(y,(byte)'a');
                x[pos]=0; y[pos]=0; x[23]=0; y[23]=0;
                // Different bytes beyond the first zero must not affect the result.
                x[pos+1]=1; y[pos+1]=(byte)255;
                probe(a,b,3,x,y,la,ra,false,0,log);
                for(int[] pair:new int[][]{{0,1},{1,0},{1,2},{2,1},{127,128},{128,127},{1,255},{255,1},{0,255},{255,0}}) {
                    x[pos]=(byte)pair[0]; y[pos]=(byte)pair[1];
                    probe(a,b,3,x,y,la,ra,false,0,log);
                }
            }
            // Each byte value against sign/wrap boundaries on both instruction paths.
            for(int value=0;value<256;value++) for(int other:new int[]{0,1,127,128,255}) for(int align:new int[]{0,1})
                probe(a,b,3,new byte[]{(byte)value,0},new byte[]{(byte)other,0},align,align,false,0,log);
        }
        super.preChecks(mapped,binary,out);
    }
    @Override String extraChecks(byte[] mapped,byte[] binary,Path out) throws Exception {
        String inherited=super.extraChecks(mapped,binary,out); StringBuilder listing=new StringBuilder(); int count=0;
        for(int i=0;i<4;i++) for(var ins:currentProgram.getListing().getInstructions(new AddressSet(toAddr(BOOT[i]),toAddr(ENDS[i]-1)),true)) {
            long pc=ins.getAddress().getOffset(); require(visited.contains(pc),"Unvisited bootstrap instruction "+Long.toHexString(pc)); count++;
            listing.append(String.format("%08x %s %s visited=true%n",pc,HexFormat.of().formatHex(ins.getBytes()),ins));
        }
        require(count==97,"Bootstrap instruction extent");
        Files.writeString(out.resolve("original-bootstrap-ghidra.txt"),listing);
        inherited=inherited.replace("\"locale_initialization_recovered\":false", "\"locale_initialization_recovered\":true")
            .replace("\"locale_binding_is_fixture\":true", "\"locale_binding_is_fixture\":false");
        return inherited+String.format(Locale.ROOT,",\"direct_name_compare_cases\":%d,\"direct_selector_cases\":%d,\"direct_bootstrap_cases\":%d,\"connected_bootstrap_calls_both\":%d,\"new_bootstrap_instruction_addresses\":%d,\"connected_bootstrap_executed\":true,\"inherited_direct_locale_initialization_fixture\":true,\"private_callback_relocation_fixture\":true,\"exact_compare_read_footprints_checked\":true,\"bootstrap_repeated_on_same_storage\":true",compareCases,selectorCases,bootstrapCases,connectedBootstraps,count);
    }
    @Override public void run() throws Exception {
        var lines=Files.readAllLines(Path.of(getScriptArgs()[0]).resolve("entries.txt"));
        for(int i=0;i<4;i++) bootEntries[i]=Long.parseLong(lines.get(29+i));
        super.run();
    }
}
