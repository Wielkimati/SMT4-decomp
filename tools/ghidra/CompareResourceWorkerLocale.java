// Default locale callback/map with private hash-bound data; initialization is fixture-bound.
// @category SMT4
import ghidra.pcode.emu.PcodeThread;
import ghidra.pcode.utils.Utils;
import ghidra.program.model.address.*;
import ghidra.program.model.pcode.PcodeOp;
import java.math.BigInteger;
import java.nio.file.*;
import java.security.MessageDigest;
import java.util.*;
import java.io.*;

public class CompareResourceWorkerLocale extends CompareResourceWorkerPath {
    static final long MAP=0x100f9c, DECODE=0x100fc8, MAP_DATA=0x41caa0, REAL_LOCALE=0x42a04d;
    static final String MAP_HASH="49c21ead0aaa288dd04a9eaaf0e424dd2fd49300602a6a0ec7ca30df4392bcae";
    long mapEntry,decodeEntry;
    byte[] mapping,localeBytes;
    int mapCases,localeCases,sequenceCases,connectedLocale,connectedMaps;
    int mapOracle(long raw) {
        int index=(int)raw;
        if(index>=752 && index<1410) return 65535;
        if(index>=1410) index=(short)(index-658);
        return index<0 || index>=7150 ? 65535 : (mapping[2*index]&255)|((mapping[2*index+1]&255)<<8);
    }
    // status, resulting state word, output (-1 means untouched)
    long[] byteOracle(long lead,long value) {
        if(lead==0) {
            if(value>=129 && value<=159 || value>=224 && value<=239) return new long[]{MASK-1,value,-1};
            if(value>=240 || value==128 || value==160) return new long[]{MASK,lead,-1};
            long unit=value==92 ? 165 : value==126 ? 8254 : value>=161 && value<=223 ? value+65216 : value;
            return new long[]{1,lead,unit};
        }
        if(!(value>=64 && value<=126 || value>=128 && value<=252)) return new long[]{MASK,lead,-1};
        int row=(int)(lead-(lead>=224 ? 193 : 129));
        int index=(short)(row*188+(int)value-(value>=128 ? 65 : 64));
        int unit=mapOracle(index);
        return unit==65535 ? new long[]{MASK,lead,-1} : new long[]{1,0,unit};
    }
    @Override boolean pathCode(long pc) { return within(pc,2,MAP,0x101064) || super.pathCode(pc); }
    @Override IoMachine makeMachine(byte[] mapped,byte[] binary) { return new LocaleMachine(mapped,binary); }
    class LocaleMachine extends PathMachine {
        boolean rebuiltFixture,connected;
        LocaleMachine(byte[] mapped,byte[] binary) { super(mapped,binary); }
        void bind(boolean rebuilt) {
            byte[] table=localeBytes.clone();
            if(rebuilt) put(table,0x103,(decodeEntry-(REAL_LOCALE+0x103))&MASK);
            memory(REAL_LOCALE,table); writeWord(CONTEXT+4,REAL_LOCALE); callbackTarget=0;
        }
        @Override void setupAllocation(byte[] initial,long length,long allocation) {
            super.setupAllocation(initial,length,allocation); bind(rebuiltFixture);
        }
        @Override void call(boolean rebuilt,byte[] initial,long open,long read,long handle,long length,long allocation,int profile,int effect) throws Exception {
            rebuiltFixture=rebuilt; connected=true;
            super.call(rebuilt,initial,open,read,handle,length,allocation,profile,effect);
            require(Arrays.equals(mapping,memory(MAP_DATA,mapping.length)),"Connected map immutable");
            byte[] table=localeBytes.clone(); if(rebuilt) put(table,0x103,(decodeEntry-(REAL_LOCALE+0x103))&MASK);
            require(Arrays.equals(table,memory(REAL_LOCALE,table.length)),"Connected locale immutable");
            connected=false;
        }
        int[] character(int index) {
            if(index==0) return new int[]{'r'};
            if(index==1) return new int[]{':'};
            switch(index%7) {
                case 0: return new int[]{0x81,0x40};
                case 1: return new int[]{0x82,0xa0};
                case 2: return new int[]{0x5c};
                case 3: return new int[]{0x7e};
                case 4: return new int[]{0xa1};
                case 5: return new int[]{0xdf};
                default: return new int[]{'z'};
            }
        }
        @Override int pathStride(int index) { return character(index).length; }
        @Override int convertedUnit(int index) {
            int[] bytes=character(index); long lead=0,unit=-1;
            for(int value:bytes) { long[] r=byteOracle(lead,value); lead=r[1]; unit=r[2]; }
            require(unit>0 && lead==0,"Valid connected character"); return (int)unit;
        }
        @Override void fillPath(byte[] descriptor,int count) {
            int cursor=0x2c;
            for(int i=0;i<count;i++) for(int value:character(i)) descriptor[cursor++]=(byte)value;
            require(cursor<0x12c,"Bounded encoded path"); descriptor[cursor]=0;
        }
        @Override long convertPath(boolean rebuilt,long ignored,int ch) throws Exception {
            long out=register("r0"),limit=register("r2"),result=executePath(rebuilt); byte[] unit=memory(out,2);
            require(result==limit && ((unit[0]&255)|((unit[1]&255)<<8))==ch,"Connected locale conversion");
            connectedPaths++; return result;
        }
        @Override void pathInstruction(long pc,boolean rebuilt) {
            if(connected && pc==(rebuilt ? decodeEntry : DECODE)) connectedLocale++;
            if(connected && pc==(rebuilt ? mapEntry : MAP)) connectedMaps++;
        }
        @Override public void beforeStore(PcodeThread<byte[]> t,PcodeOp op,AddressSpace space,byte[] offset,int size,byte[] value) {
            long a=Utils.bytesToLong(offset,offset.length,false);
            if(size==4 && (a==STATE || a==SLOTS+32 || a==SLOTS+40)) return;
            super.beforeStore(t,op,space,offset,size,value);
        }
        void fixture(boolean rebuilt,long first,long second) {
            releasedObject=false; initialize(rebuilt,0,new byte[0x144]); destroyed=false; active=false; trace.clear(); connected=false;
            pathFixtures(0,false,false,0); bind(rebuilt);
            byte[] state=new byte[40]; Arrays.fill(state,(byte)0x97); put(state,16,first); put(state,20,second); memory(STATE-16,state);
            for(int slot:new int[]{4,5}) { writeWord(SLOTS+slot*8,first); writeWord(SLOTS+slot*8+4,second); }
        }
        void step(boolean rebuilt,int kind,long value,int[] input,long limit,int stateKind,boolean nullInput,boolean nullOutput) throws Exception {
            byte[] in=new byte[2048]; Arrays.fill(in,(byte)0x69); for(int i=0;i<input.length;i++) in[i]=(byte)input[i]; memory(PATH,in);
            byte[] output=new byte[40]; Arrays.fill(output,(byte)0x5a); memory(SIZE-16,output);
            byte[] state=memory(STATE-16,40),bank=memory(BANK,192),table=memory(REAL_LOCALE,localeBytes.length);
            long statePtr=stateKind==0 ? 0 : STATE,actualState=statePtr!=0 ? statePtr : SLOTS+(kind==3 ? 32 : 40);
            long result,lead=get(actualState); int unit=-1;
            if(kind==0) result=mapOracle(value);
            else if(kind==1) { long[] r=byteOracle(lead,value); result=r[0]; lead=r[1]; unit=(int)r[2]; }
            else {
                result=MASK-1;
                int[] bytes=nullInput ? new int[]{0} : input;
                long cap=nullInput ? 1 : limit;
                for(int i=0;i<cap;i++) {
                    require(i<bytes.length,"Oracle input bounded"); long[] r=byteOracle(lead,bytes[i]); lead=r[1];
                    if(r[0]==MASK) { result=MASK; put(bank,(int)(ERROR-BANK),4); break; }
                    if(r[0]==MASK-1) continue;
                    result=r[2]==0 ? 0 : i+1;
                    if(kind==2 && !nullInput && !nullOutput) unit=(int)r[2]; break;
                }
            }
            if(kind!=0) { if(statePtr!=0) put(state,16,lead); else put(bank,(int)(actualState-BANK),lead); }
            if(unit>=0) { output[16]=(byte)unit; output[17]=(byte)(unit>>8); }
            long target=kind==0 ? mapEntry : kind==1 ? decodeEntry : pathEntries[kind==2 ? 2 : 1];
            long original=kind==0 ? MAP : kind==1 ? DECODE : PATH_START[kind==2 ? 2 : 1];
            register("r0",kind==0 ? value : kind==3 ? nullInput ? 0 : PATH : nullOutput ? 0 : SIZE);
            register("r1",kind==0 ? 0 : kind==1 ? value : kind==3 ? limit : nullInput ? 0 : PATH);
            register("r2",kind==1 || kind==3 ? statePtr : limit); register("r3",statePtr);
            register("lr",RETURN); select(rebuilt ? target : original,!rebuilt); executing=true;
            long actual=executePath(rebuilt);
            require(actual==result,"Locale result kind="+kind+" value="+value+" expected="+result+" actual="+actual);
            require(Arrays.equals(output,memory(SIZE-16,40)),"Locale guarded output");
            require(Arrays.equals(state,memory(STATE-16,40)),"Locale guarded state");
            require(Arrays.equals(bank,memory(BANK,192)),"Locale bank/error/state");
            require(Arrays.equals(table,memory(REAL_LOCALE,table.length)) && Arrays.equals(mapping,memory(MAP_DATA,mapping.length)),"Private data immutable");
            require(Arrays.equals(in,memory(PATH,2048)),"Locale input immutable");
            for(byte b:memory(STACK-0x1000,0xe00)) require(b==(byte)0x96,"Locale stack guard");
            trace.add("locale-result:"+actual+":"+HexFormat.of().formatHex(output)+":"+HexFormat.of().formatHex(state)+":"+HexFormat.of().formatHex(bank));
        }
    }
    void probe(LocaleMachine a,LocaleMachine b,int kind,long value,long first,int[] input,long limit,int stateKind,boolean nullInput,boolean nullOutput,boolean fresh,PrintWriter log) throws Exception {
        try {
            if(fresh) { a.fixture(false,first,MASK); b.fixture(true,first,MASK); }
            a.step(false,kind,value,input,limit,stateKind,nullInput,nullOutput);
            b.step(true,kind,value,input,limit,stateKind,nullInput,nullOutput);
            require(a.trace.equals(b.trace),"Locale original/rebuilt transcript");
        } catch(Exception e) { throw new IllegalStateException("Worker I/O case locale="+localeCases+" kind="+kind+" value="+value+" lead="+first+" input="+Arrays.toString(input),e); }
        if(kind==0) mapCases++; else localeCases++;
        log.printf("%d\t%d\t%d\t%s\t%d\t%d\t%s\t%s\t%s%n",kind,value,first,Arrays.toString(input),limit,stateKind,nullInput,nullOutput,fresh);
    }
    @Override void preChecks(byte[] mapped,byte[] binary,Path out) throws Exception {
        super.preChecks(mapped,binary,out); // Retain all existing scripted path probes.
        LocaleMachine a=new LocaleMachine(mapped,binary),b=new LocaleMachine(mapped,binary);
        try(PrintWriter log=new PrintWriter(Files.newBufferedWriter(out.resolve("locale-results.tsv")))) {
            log.println("kind\tvalue\tinitial_state\tinput\tlimit\tstate_kind\tnull_input\tnull_output\tfresh");
            // Every private mapping entry, the complete hole and its immediate boundaries.
            for(long i=-1;i<=7810;i++) probe(a,b,0,i&MASK,0,new int[]{0},0,1,false,false,true,log);
            for(long i:new long[]{0x7fff,0x8000,0xffff,0x10000,0x10291,0x10292,0x10293,0x11e7f,0x11e80,0x7fffffffL,0x80000000L,MASK})
                probe(a,b,0,i,0,new int[]{0},0,1,false,false,true,log);
            // Full single-byte space; full trail space at lead and mapping-gap boundaries.
            for(long lead:new long[]{0,0x81,0x84,0x85,0x88,0x89,0x9f,0xe0,0xe9,0xea,0xef}) for(int value=0;value<256;value++)
                probe(a,b,1,value,lead,new int[]{0},0,1,false,false,true,log);
            for(long lead:new long[]{1,0x80,0xa0,0xdf,0xf0,0x100,0x80000000L,MASK}) for(long value:new long[]{0,0x3f,0x40,0x7e,0x7f,0x80,0xfc,0xfd,0xff,0x100,MASK})
                probe(a,b,1,value,lead,new int[]{0},0,1,false,false,true,log);
            for(int lead=0x81;lead<=0xef;lead++) if(lead<=0x9f || lead>=0xe0)
                for(int value:new int[]{0x40,0x7e,0x80,0xfc}) probe(a,b,1,value,lead,new int[]{0},0,1,false,false,true,log);
            int[][] inputs={{0},{0x5c},{0x7e},{0xa1},{0xdf},{0x80},{0xa0},{0xff},{0x81},{0x81,0x40},{0x81,0x7f},{0x85,0x40},{0xef,0xfc}};
            for(int kind:new int[]{2,3}) for(int stateKind=0;stateKind<2;stateKind++) for(boolean nullOut:new boolean[]{false,true})
            for(int[] input:inputs) for(long limit:new long[]{0,1,input.length})
                probe(a,b,kind,0,0,input,limit,stateKind,false,nullOut,true,log);
            for(int kind:new int[]{2,3}) for(int stateKind=0;stateKind<2;stateKind++) for(long first:new long[]{0,0x81})
                probe(a,b,kind,0,first,new int[]{0xff},0,stateKind,true,false,true,log);
            // Retained lead, invalid trail, then successful retry on the SAME state and error storage.
            for(int kind:new int[]{1,2,3}) for(int stateKind:kind==1 ? new int[]{1} : new int[]{0,1}) {
                probe(a,b,kind,0x81,0,new int[]{0x81},1,stateKind,false,false,true,log);
                probe(a,b,kind,0x7f,0,new int[]{0x7f},1,stateKind,false,false,false,log);
                probe(a,b,kind,0x40,0,new int[]{0x40},1,stateKind,false,false,false,log);
                probe(a,b,kind,0,0,new int[]{0},1,stateKind,false,false,false,log); sequenceCases++;
            }
        }
    }
    @Override String extraChecks(byte[] mapped,byte[] binary,Path out) throws Exception {
        String inherited=super.extraChecks(mapped,binary,out); StringBuilder listing=new StringBuilder(); int count=0;
        for(var instruction:currentProgram.getListing().getInstructions(new AddressSet(toAddr(MAP),toAddr(0x101063)),true)) {
            long pc=instruction.getAddress().getOffset(); require(visited.contains(pc),"Unvisited locale instruction "+Long.toHexString(pc)); count++;
            listing.append(String.format("%08x %s %s visited=true%n",pc,HexFormat.of().formatHex(instruction.getBytes()),instruction));
        }
        require(count==99,"Locale instruction extent");
        Files.writeString(out.resolve("original-locale-ghidra.txt"),listing);
        return inherited+String.format(Locale.ROOT,",\"direct_mapping_cases\":%d,\"direct_locale_cases\":%d,\"persistent_locale_sequences\":%d,\"connected_locale_calls_both\":%d,\"connected_mapping_calls_both\":%d,\"new_locale_instruction_addresses\":%d,\"default_locale_callback_recovered\":true,\"connected_locale_callback_modeled\":false,\"mapping_sha256\":\"%s\",\"locale_binding_is_fixture\":true",mapCases,localeCases,sequenceCases,connectedLocale,connectedMaps,count,MAP_HASH);
    }
    @Override public void run() throws Exception {
        Path out=Path.of(getScriptArgs()[0]); var lines=Files.readAllLines(out.resolve("entries.txt"));
        mapEntry=Long.parseLong(lines.get(27)); decodeEntry=Long.parseLong(lines.get(28));
        mapping=new byte[14300]; currentProgram.getMemory().getBytes(toAddr(MAP_DATA),mapping);
        require(HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(mapping)).equals(MAP_HASH),"Private mapping identity");
        localeBytes=new byte[0x107]; currentProgram.getMemory().getBytes(toAddr(REAL_LOCALE),localeBytes);
        require(localeBytes[0x101]==1 && ((REAL_LOCALE+0x103+word(localeBytes,0x103))&MASK)==DECODE+1,"Reference locale binding");
        // These two absent function objects are established locally in the read-only job.
        clearListing(toAddr(MAP),toAddr(0x101063));
        currentProgram.getProgramContext().setValue(currentProgram.getRegister("TMode"),toAddr(MAP),toAddr(0x101063),BigInteger.ONE);
        require(disassemble(toAddr(MAP)) && disassemble(toAddr(DECODE)),"Establish Thumb bodies");
        long cursor=MAP;
        for(var ins:currentProgram.getListing().getInstructions(new AddressSet(toAddr(MAP),toAddr(0x101063)),true)) {
            require(ins.getAddress().getOffset()==cursor,"Contiguous Thumb body"); cursor+=ins.getLength();
        }
        require(cursor==0x101064,"Exact Thumb end before literals");
        super.run();
    }
}
