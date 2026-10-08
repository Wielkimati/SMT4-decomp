// Exact-width original/rebuilt clearing, with guarded sparse wrap fixtures.
// @category SMT4
import ghidra.pcode.emu.PcodeThread;
import ghidra.pcode.utils.Utils;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.pcode.PcodeOp;
import java.nio.file.*;
import java.security.MessageDigest;
import java.util.*;
import java.io.*;

public class CompareResourceClear extends CompareResourceSync {
    static final long MASK=0xffffffffL;
    static final long[] BEGIN={0x139f54,0x2c3b9c,0x2c4b88}, LIMIT={0x139f84,0x2c3bdc,0x2c4bd8};
    int cases; int[] kinds=new int[3];
    @Override boolean originalCode(long pc) {
        for(int i=0;i<3;i++) if(within(pc,4,BEGIN[i],LIMIT[i]))return true;
        return false;
    }
    class ClearMachine extends SyncMachine {
        TreeMap<Long,byte[]> expected=new TreeMap<>();
        List<String> actualWrites=new ArrayList<>(),expectedWrites=new ArrayList<>();
        ClearMachine(byte[] map,byte[] bin){super(map,bin);}
        @Override public void beforeStore(PcodeThread<byte[]> t,PcodeOp op,AddressSpace space,byte[] offset,int n,byte[] value){
            long a=Utils.bytesToLong(offset,offset.length,false);
            if(within(a,n,STACK-256,STACK))return;
            actualWrites.add(a+":"+n+":"+Utils.bytesToLong(value,n,false));
            require(actualWrites.size()<=expectedWrites.size(),"Excess write");
            require(actualWrites.get(actualWrites.size()-1).equals(expectedWrites.get(actualWrites.size()-1)),"Write address/width/value");
        }
        @Override public void beforeLoad(PcodeThread<byte[]> t,PcodeOp op,AddressSpace space,byte[] offset,int n){
            long a=Utils.bytesToLong(offset,offset.length,false);
            require(within(a,n,STACK-256,STACK) || within(a,n,BUILD,BUILD+codeSize) || within(a,n,0x100000,0x477000),"Unexpected load");
        }
        void region(long a,int n){byte[] b=new byte[n];new Random(a+cases).nextBytes(b);expected.put(a,b);memory(a,b);}
        void store(long a,int n,long v){
            v&=n==4?MASK:(1L<<(8*n))-1;
            expectedWrites.add(a+":"+n+":"+v);
            for(int i=0;i<n;i++){long p=(a+i)&MASK;var e=expected.floorEntry(p);require(e!=null && p-e.getKey()<e.getValue().length,"Oracle map");e.getValue()[(int)(p-e.getKey())]=(byte)(v>>>(8*i));}
        }
        void call(boolean rebuiltPath,int kind,long address,int count,long value)throws Exception{
            initialize(rebuiltPath,0,new byte[0x144]);expected.clear();actualWrites.clear();expectedWrites.clear();
            if(address>=0xffffffe0L){region(0xffffffc0L,64);region(0,2048);}else region(address-16,count+32);
            long p=address;int left=count;
            if(kind==0){while(left>0){store(p,4,value);p=(p+4)&MASK;left-=4;}}
            else if(kind==1 && count<4){while(left-->0){store(p,1,0);p=(p+1)&MASK;}}
            else {
                if(kind==1 && (p%4)!=0){int prefix=(int)(4-p%4);if(prefix!=2){store(p,1,0);p=(p+1)&MASK;}if(prefix>=2){store(p,2,0);p=(p+2)&MASK;}left-=prefix;}
                while(left>=4){store(p,4,kind==1?0:value);p=(p+4)&MASK;left-=4;}
                if(left>=2){store(p,2,kind==1?0:value);p=(p+2)&MASK;left-=2;}
                if(left==1)store(p,1,kind==1?0:value);
            }
            register("r0",address);register("r1",kind==0?(address+count)&MASK:count);register("r2",value);
            thread.overrideCounter(toAddr(rebuiltPath?entries[kind]:BEGIN[kind]));executing=true;
            int steps=0;
            while(thread.getCounter().getOffset()!=RETURN){long pc=thread.getCounter().getOffset();require(rebuiltPath?within(pc,4,BUILD,BUILD+codeSize):originalCode(pc),"PC");if(!rebuiltPath)visited.add(pc);require(++steps<20000,"Budget");thread.stepInstruction();}
            require(actualWrites.equals(expectedWrites),"Missing writes");
            for(var e:expected.entrySet())require(Arrays.equals(e.getValue(),memory(e.getKey(),e.getValue().length)),"Destination/guards");
            for(byte b:memory(STACK-0x1000,0xf00))require(b==(byte)0x96,"Stack guard");
            finish(steps);executing=false;
        }
    }
    void pair(ClearMachine a,ClearMachine b,PrintWriter log,int kind,long p,int n,long value)throws Exception{
        try{a.call(false,kind,p,n,value);b.call(true,kind,p,n,value);require(a.actualWrites.equals(b.actualWrites),"Write agreement");}
        catch(Exception e){throw new IllegalStateException("Clear case "+cases+" kind="+kind+" address="+Long.toHexString(p)+" count="+n,e);}
        log.printf("%d\t%d\t%x\t%d\t%x\t%d%n",cases++,kind,p,n,value,a.actualWrites.size());kinds[kind]++;
    }
    public void run()throws Exception{
        Path out=Path.of(getScriptArgs()[0]);byte[] map=new byte[0x377000];require(currentProgram.getMemory().getBytes(toAddr(0x100000),map)==map.length,"Map");
        require(HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(map)).equals("834938d18d2b7c688311c46c27bed813d0d7a9f8e3cbb61da8a6a3f23d360ebd"),"Hash");
        byte[] bin=Files.readAllBytes(out.resolve("resource-clear.bin"));codeSize=bin.length;
        var lines=Files.readAllLines(out.resolve("entries.txt"));for(int i=0;i<3;i++)entries[i]=Long.parseLong(lines.get(i));
        StringBuilder listing=new StringBuilder();
        for(int i=0;i<3;i++){var f=getFunctionAt(toAddr(BEGIN[i]));require(i==2?f==null:f!=null && f.getBody().getMinAddress().getOffset()==BEGIN[i] && f.getBody().getMaxAddress().getOffset()==LIMIT[i]-1,"Saved membership");listing.append(Long.toHexString(BEGIN[i])+" "+(f==null?"shared body; no saved function":f.getBody())+"\n");for(long pc=BEGIN[i];pc<LIMIT[i];pc+=4)listing.append(String.format("%08x %s%n",pc,getInstructionAt(toAddr(pc))));}
        Files.writeString(out.resolve("original-ghidra.txt"),listing);
        ClearMachine a=new ClearMachine(map,bin),b=new ClearMachine(map,bin);
        try(PrintWriter log=new PrintWriter(Files.newBufferedWriter(out.resolve("results.tsv")))){
            log.println("case\tkind\taddress\tcount\tvalue\twrites");
            for(long value:new long[]{0,1,0x12345678,0x80000000L,MASK})for(int n:new int[]{0,4,8,12,16,28,32,36,60,64,68,128,1024})pair(a,b,log,0,0x900020,n,value);
            for(long value:new long[]{0,0x12345678,MASK})for(int n:new int[]{0,4,8,16,32,64})pair(a,b,log,0,0xfffffff0L,n,value);
            for(long base:new long[]{0x900020,0x89000020L})for(int residue=0;residue<4;residue++)for(int n=0;n<=68;n++)pair(a,b,log,1,base+residue,n,0xdeadbeefL);
            for(int residue=0;residue<4;residue++)for(int n:new int[]{127,128,129,255,256,257,1023,1024})pair(a,b,log,1,0x900020+residue,n,1);
            for(long value:new long[]{0,0x12345678,MASK})for(int n=0;n<=68;n++)pair(a,b,log,2,0x900020,n,value);
        }
        for(int i=0;i<3;i++)for(long pc=BEGIN[i];pc<LIMIT[i];pc+=4)require(visited.contains(pc),"Unvisited instruction "+Long.toHexString(pc));
        Files.writeString(out.resolve("visited.txt"),String.join("\n",visited.stream().map(v->String.format("%08x",v)).toList())+"\n");
        Files.writeString(out.resolve("comparison.json"),String.format(Locale.ROOT,"{\"cases\":%d,\"cases_by_kind\":%s,\"new_instruction_sites\":%d,\"max_steps\":%d,\"exact_destination_write_trace\":true,\"dependencies_modeled\":false,\"live_verified\":false}\n",cases,Arrays.toString(kinds),visited.size(),maxSteps));
        println("SMT4_CLEAR_COMPARE_OK");
    }
}
