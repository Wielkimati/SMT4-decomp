// Prefix registry, UTF-16 suffix length and open dispatch; backend is modeled.
// @category SMT4
import ghidra.pcode.emu.PcodeThread;
import ghidra.pcode.utils.Utils;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.lang.RegisterValue;
import java.math.BigInteger;
import java.nio.file.*;
import java.util.*;
import java.io.*;

public class CompareResourceWorkerFileOpen extends CompareResourceWorkerFileRead {
    static final long OPEN=0x2bb944, PREFIX=0x2b5ca0, UTF16=0x2b5c8c;
    static final long PREFIX_TABLE=0x4d43e0, BACKEND=0x90a000, BACKEND_VT=0x90a100, SERVICE=0x740000;
    static final long NO_BACKEND=0xc8804465L;
    long openEntry,prefixEntry,lengthEntry;
    int openCases,prefixCases,lengthCases,connectedOpens,backendCalls,openSteps;
    @Override boolean originalCode(long pc) {
        return within(pc,4,OPEN,0x2bb9d4) || within(pc,4,PREFIX,0x2b5d68) ||
            within(pc,2,UTF16,0x2b5c9e) || super.originalCode(pc);
    }
    @Override IoMachine makeMachine(byte[] mapped,byte[] binary) { return new OpenMachine(mapped,binary); }
    // Oracle uses signed byte -> Java long promotion and a single 64-bit shift.
    long key(int[] units) {
        long key=0;
        for(int i=0;i<8;i++) {
            if(units[i]==':') return key;
            key=(key<<8)|(byte)units[i];
        }
        return 0;
    }
    long lookup(int[] units,byte[] table) {
        long key=key(units); if(key==0) return 0;
        for(int i=0;i<32;i++) if(pair(table,16*i)==key) return word(table,16*i+8);
        return 0;
    }
    int[] path(int[] prefix,int suffix) {
        int[] units=new int[Math.max(16,prefix.length+suffix+2)];
        System.arraycopy(prefix,0,units,0,prefix.length); units[prefix.length]=':';
        for(int i=0;i<suffix;i++) units[prefix.length+1+i]=new int[]{'/',0x1234,0xd800,0xdc00,0xffff,':'}[i%6];
        return units;
    }
    byte[] table(int[] units,int slot,int variant) {
        byte[] table=new byte[512]; new Random(OPEN).nextBytes(table);
        if(slot>=0) {
            pair(table,slot*16,key(units)); put(table,slot*16+8,variant==1 ? 0 : BACKEND);
            if(variant>=1 && slot<31) { pair(table,(slot+1)*16,key(units)); put(table,(slot+1)*16+8,BACKEND+32); }
        }
        return table;
    }
    class OpenMachine extends ReadMachine {
        long backendStatus,backendHandle;
        OpenMachine(byte[] mapped,byte[] binary) { super(mapped,binary); }
        @Override int convertedUnit(int index) { return index==0 ? 'r' : index==1 ? ':' : 0x8100+index; }
        @Override long openTarget(boolean path) { return path ? openEntry : OPEN; }
        @Override public void beforeLoad(PcodeThread<byte[]> t,PcodeOp op,AddressSpace space,byte[] offset,int size) {
            long a=Utils.bytesToLong(offset,offset.length,false);
            if(within(a,size,PREFIX_TABLE,PREFIX_TABLE+512) || within(a,size,BACKEND,BACKEND+512) ||
                within(a,size,PATH,PATH+2048)) return;
            super.beforeLoad(t,op,space,offset,size);
        }
        void fixtures(byte[] table) {
            byte[] guard=new byte[544]; new Random(PREFIX).nextBytes(guard); memory(PREFIX_TABLE-16,guard);
            memory(PREFIX_TABLE,table);
            byte[] backend=new byte[512]; new Random(UTF16).nextBytes(backend); memory(BACKEND,backend);
            writeWord(BACKEND,BACKEND_VT); writeWord(BACKEND+32,BACKEND_VT); writeWord(BACKEND_VT,SERVICE);
        }
        @Override void call(boolean path,byte[] initial,long open,long read,long handle,
                long length,long allocation,int profile,int effect) throws Exception {
            backendStatus=open; backendHandle=handle;
            boolean found=profile==2 || profile==4 || profile==5;
            long status=found ? open : NO_BACKEND;
            super.call(path,initial,status,read,(status&0x80000000L)==0 ? handle : 0,length,allocation,profile,effect);
        }
        @Override void setupAllocation(byte[] initial,long length,long allocation) {
            super.setupAllocation(initial,length,allocation);
            int[] units=path(new int[]{'r'},0);
            fixtures(table(units,(cases/6)%32,0));
        }
        long execute(boolean rebuilt,int kind,long pathPointer,int[] units,byte[] table,long status,long handle,long mode) throws Exception {
            long returnPc=register("lr"),savedSp=register("sp"),out=register("r0");
            long old=kind==0 ? get(out) : 0;
            long[] saved=new long[8]; for(int r=4;r<=11;r++) saved[r-4]=register("r"+r);
            byte[] tableBefore=memory(PREFIX_TABLE-16,544),backendBefore=memory(BACKEND,512);
            byte[] pathBefore=memory(pathPointer,units.length*2);
            long backend=kind==2 ? 0 : lookup(units,table),expected=kind==1 ? backend : backend==0 ? NO_BACKEND : status;
            if(kind==2) { expected=0; while(units[(int)expected]!=0) expected++; }
            int colon=0,suffix=0;
            if(backend!=0) { while(units[colon]!=':') colon++; while(units[colon+1+suffix]!=0) suffix++; }
            int calls=0,steps=0;
            while(thread.getCounter().getOffset()!=returnPc) {
                long pc=thread.getCounter().getOffset();
                if(pc==SERVICE) {
                    require(kind==0 && backend!=0 && ++calls==1,"Backend invocation predicate");
                    long sp=register("sp"),local=register("r1"),desc=register("r2");
                    require(register("r0")==backend && register("r3")==mode,"Backend receiver/mode");
                    require((sp&7)==0 && (local&3)==0 && (desc&3)==0 && within(local,4,sp,savedSp) &&
                        within(desc,12,sp,savedSp) && (local+4<=desc || desc+12<=local),"Backend stack descriptor/output ABI");
                    require(get(desc)==4 && get(desc+4)==pathPointer+2*(colon+1) && get(desc+8)==2*(suffix+1),"Type-4 suffix pointer/byte length");
                    if((status&0x80000000L)==0 || (status&1)!=0) writeWord(local,handle);
                    trace.add("backend-open:"+backend+":"+mode+":"+suffix+":"+status+":"+handle);
                    backendCalls++; dependencyCalls++; externalReturn(status); continue;
                }
                require(rebuilt ? within(pc,4,BUILD,BUILD+codeSize) :
                    within(pc,4,OPEN,0x2bb9d4) || within(pc,4,PREFIX,0x2b5d68) || within(pc,2,UTF16,0x2b5c9e),"Open PC "+Long.toHexString(pc));
                if(!rebuilt) visited.add(pc);
                require(++steps<5000,"Open instruction budget"); monitor.checkCancelled(); thread.stepInstruction();
            }
            require(calls==(kind==0 && backend!=0 ? 1 : 0),"Backend call count");
            require(register("r0")==expected,"Open/prefix exact result");
            if(kind==0) require(get(out)==((expected&0x80000000L)==0 ? handle : old),"Conditional open handle write");
            require(Arrays.equals(tableBefore,memory(PREFIX_TABLE-16,544)),"Prefix table guards/immutability");
            require(Arrays.equals(backendBefore,memory(BACKEND,512)),"Backend guards/immutability");
            require(Arrays.equals(pathBefore,memory(pathPointer,units.length*2)),"Path immutability");
            require(register("sp")==savedSp,"Open stack restoration");
            for(int r=4;r<=11;r++) require(register("r"+r)==saved[r-4],"Open saved register");
            openSteps=Math.max(openSteps,steps);
            trace.add("open-end:"+kind+":"+expected+":"+(kind==0 ? get(out) : 0));
            return expected;
        }
        @Override long executeOpen(boolean rebuilt,long result,long handle,long pathPointer,int count) throws Exception {
            int[] units=new int[Math.max(8,count+1)]; byte[] bytes=memory(pathPointer,units.length*2);
            for(int i=0;i<units.length;i++) units[i]=(bytes[2*i]&255)|((bytes[2*i+1]&255)<<8);
            long caller=register("lr");
            long actual=execute(rebuilt,0,pathPointer,units,memory(PREFIX_TABLE,512),backendStatus,backendHandle,1);
            register("lr",caller); // Outer fixture completes the recorded call boundary.
            require(actual==result && get(OBJ+4)==handle,"Connected open oracle"); connectedOpens++;
            return actual;
        }
        void direct(boolean rebuilt,int kind,int[] units,byte[] table,long status,long handle,long mode) throws Exception {
            initialize(rebuilt,0,new byte[0x144]); destroyed=false; trace.clear(); fixtures(table);
            byte[] pathBytes=new byte[2048]; new Random(OPEN).nextBytes(pathBytes);
            for(int i=0;i<units.length;i++) { pathBytes[2*i]=(byte)units[i]; pathBytes[2*i+1]=(byte)(units[i]>>8); }
            memory(PATH,pathBytes);
            byte[] outBytes=new byte[40]; Arrays.fill(outBytes,(byte)0x5a); memory(SIZE-16,outBytes);
            register("r0",kind==0 ? SIZE : PATH); register("r1",PATH); register("r2",mode);
            thread.overrideCounter(toAddr(rebuilt ? kind==0 ? openEntry : kind==1 ? prefixEntry : lengthEntry : kind==0 ? OPEN : kind==1 ? PREFIX : UTF16));
            if(kind==2 && !rebuilt) {
                register("cpsr",0x30);
                thread.overrideContext(new RegisterValue(currentProgram.getRegister("TMode"),BigInteger.ONE));
            }
            executing=true;
            execute(rebuilt,kind,PATH,units,table,status,handle,mode);
            put(outBytes,16,get(SIZE)); require(Arrays.equals(outBytes,memory(SIZE-16,40)),"Open output guards");
            require(Arrays.equals(pathBytes,memory(PATH,2048)),"Whole direct path guard");
            for(byte value:memory(STACK-0x1000,0xf00)) require(value==(byte)0x96,"Open stack guard");
        }
    }
    void compare(OpenMachine a,OpenMachine b,int kind,int[] units,byte[] table,long status,long handle,long mode,PrintWriter log) throws Exception {
        try {
            a.direct(false,kind,units,table,status,handle,mode); b.direct(true,kind,units,table,status,handle,mode);
            require(a.trace.equals(b.trace),"Open original/rebuilt trace");
        } catch(Exception e) { throw new IllegalStateException("Worker I/O case open="+openCases+" prefix="+prefixCases+" units="+Arrays.toString(units)+" status="+status,e); }
        if(kind==0) openCases++; else if(kind==1) prefixCases++; else lengthCases++;
        log.printf("%d\t%d\t%s\t%d\t%d\t%d%n",kind,openCases+prefixCases,Arrays.toString(units),status,handle,mode);
    }
    @Override String extraChecks(byte[] mapped,byte[] binary,Path out) throws Exception {
        String inherited=super.extraChecks(mapped,binary,out);
        OpenMachine a=new OpenMachine(mapped,binary),b=new OpenMachine(mapped,binary);
        try(PrintWriter log=new PrintWriter(Files.newBufferedWriter(out.resolve("open-results.tsv")))) {
            log.println("kind\tcase\tunits\tstatus\thandle\tmode");
            int[][] prefixes={{},{'r'},{'r','o','m'},{1,2,3,4,5,6,7},{1,2,3,4,5,6,7,8},
                {0x7f},{0x80},{0xff},{0x180},{0x100},{0,0},{0,'r'},{'r',0,'x'},{0x13a,'a'},
                {'a',0x80,'b'},{0x80,1,2,3,4,5,6},{0xff,0xff,0xff,0xff,0xff,0xff,0xff}};
            // Every table position, pair parity, duplicate/null-first and absent keys.
            for(int[] prefix:prefixes) {
                int[] units=path(prefix,0);
                for(int slot:new int[]{-1,0,1,2,15,16,30,31}) for(int variant=0;variant<3;variant++)
                    compare(a,b,1,units,table(units,slot,variant),0,0,0,log);
            }
            for(int slot=0;slot<32;slot++) {
                int[] units=path(new int[]{'r','o','m'},1);
                compare(a,b,1,units,table(units,slot,0),0,0,0,log);
            }
            // A missing colon is scanned for exactly eight readable code units.
            int[] missing=new int[16]; Arrays.fill(missing,'x');
            for(int kind=0;kind<2;kind++) compare(a,b,kind,missing,table(missing,0,0),0,7,3,log);
            for(int[] prefix:prefixes) for(int suffix:new int[]{0,1,7,260}) {
                int[] units=path(prefix,suffix);
                for(long status:new long[]{0,1,0x7fffffffL,0x80000000L,MASK}) {
                    int index=openCases; int slot=new int[]{-1,0,1,30,31}[index%5];
                    int variant=(index/5)%3;
                    compare(a,b,0,units,table(units,slot,variant),status,
                        new long[]{0,1,0x4561,0x80000000L,MASK}[index%5],
                        new long[]{0,1,3,0x80000000L,MASK}[(index/5)%5],log);
                }
            }
            // A table entry for an overlong key must not make an eighth-unit prefix valid.
            int[] overlong=path(new int[]{1,2,3,4,5,6,7,8},0);
            byte[] overTable=table(overlong,0,0); pair(overTable,0,0x0102030405060708L);
            for(int kind=0;kind<2;kind++) compare(a,b,kind,overlong,overTable,0,7,3,log);
            // Standalone Thumb entry versus the exported ARM C entry (not just inlining).
            for(int size:new int[]{0,1,2,7,127,260,511}) {
                int[] units=new int[size+1];
                for(int i=0;i<size;i++) units[i]=new int[]{1,0x100,0xd800,0xdc00,0xffff,':'}[i%6];
                compare(a,b,2,units,new byte[512],0,0,0,log);
            }
            // Ensure all statuses reach a real modeled backend, independently of key/miss cycling.
            for(long status:new long[]{0,1,0x7fffffffL,0x80000000L,MASK}) for(long handle:new long[]{0,1,0x80000000L,MASK}) {
                int[] units=path(new int[]{0x80,'a'},3);
                compare(a,b,0,units,table(units,31,0),status,handle,MASK,log);
            }
        }
        StringBuilder listing=new StringBuilder(); int count=0;
        for(long[] range:new long[][]{{OPEN,0x2bb9d4,4},{PREFIX,0x2b5d68,4},{UTF16,0x2b5c9e,2}}) {
            var f=getFunctionAt(toAddr(range[0])); require(f!=null && f.getBody().getMaxAddress().getOffset()==range[1]-1,"Open Ghidra extent");
            for(long pc=range[0];pc<range[1];pc+=range[2]) {
                var ins=currentProgram.getListing().getInstructionAt(toAddr(pc)); require(ins!=null,"Open instruction boundary");
                if(pc!=0x2b5d4c) { require(visited.contains(pc),"Unvisited open instruction "+Long.toHexString(pc)); count++; }
                listing.append(String.format("%08x %s visited=%s%n",pc,ins,visited.contains(pc)));
            }
        }
        require(currentProgram.getMemory().getInt(toAddr(0x2b5d68))==PREFIX_TABLE,"Prefix table literal");
        require(currentProgram.getMemory().getInt(toAddr(0x2bb9d4))==(int)NO_BACKEND,"Missing backend error literal");
        Files.writeString(out.resolve("original-open-ghidra.txt"),listing);
        return inherited+String.format(Locale.ROOT,",\"direct_open_cases\":%d,\"direct_prefix_cases\":%d,\"direct_utf16_cases\":%d,\"connected_open_calls_both_paths\":%d,\"backend_open_calls_both_paths\":%d,\"open_max_steps\":%d,\"new_open_instruction_addresses\":%d,\"open_prefix_length_recovered\":true,\"backend_virtual_open_modeled\":true",
            openCases,prefixCases,lengthCases,connectedOpens,backendCalls,openSteps,count);
    }
    @Override public void run() throws Exception {
        var lines=Files.readAllLines(Path.of(getScriptArgs()[0]).resolve("entries.txt"));
        openEntry=Long.parseLong(lines.get(11)); prefixEntry=Long.parseLong(lines.get(12)); lengthEntry=Long.parseLong(lines.get(13));
        super.run();
    }
}
