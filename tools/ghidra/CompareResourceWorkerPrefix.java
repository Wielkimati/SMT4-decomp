// Prefix mutation with modeled disposal/diagnostics and persistent open sequences.
// @category SMT4
import ghidra.pcode.emu.PcodeThread;
import ghidra.pcode.utils.Utils;
import ghidra.program.model.address.*;
import ghidra.program.model.pcode.PcodeOp;
import java.nio.file.*;
import java.util.*;
import java.io.*;

public class CompareResourceWorkerPrefix extends CompareResourceWorkerLocaleConfig {
    static final long REGISTER=0x2b5e70, REMOVE=0x2c4054, BACKEND_STATE=0x44e650;
    static final long NAME=0x912000, DISPOSE=0x780000, FALLBACK=0x407fbc;
    long registerEntry,removeEntry;
    int registryCases,connectedRegistrations,persistentRegistries,disposals,terminalNames,returningNames;
    @Override IoMachine makeMachine(byte[] mapped,byte[] binary) { return new RegistryMachine(mapped,binary); }
    boolean registryCode(long pc) { return within(pc,4,REGISTER,0x2b5fb8) || within(pc,4,REMOVE,0x2c41a4); }
    long nameKey(byte[] name) {
        long key=0;
        for(int i=0;i<8;i++) {
            if(name[i]==0 || name[i]==':') return key;
            key=(key<<8)|name[i];
        }
        return 0; // The pinned post-diagnostic fallback has no colon in eight bytes.
    }
    byte[] occupied() {
        byte[] table=new byte[512]; new Random(REGISTER).nextBytes(table);
        for(int i=0;i<32;i++) { pair(table,i*16,0x1122334400000000L+i); put(table,i*16+8,BACKEND); }
        return table;
    }
    byte[] name(int... bytes) {
        byte[] result=new byte[12]; Arrays.fill(result,(byte)'z');
        for(int i=0;i<bytes.length;i++) result[i]=(byte)bytes[i];
        return result;
    }
    class RegistryMachine extends ConfigMachine {
        boolean registryActive;
        Set<Long> registryReads=new TreeSet<>();
        RegistryMachine(byte[] mapped,byte[] binary) { super(mapped,binary); }
        @Override public void beforeLoad(PcodeThread<byte[]> t,PcodeOp op,AddressSpace space,byte[] offset,int size) {
            long a=Utils.bytesToLong(offset,offset.length,false);
            if(registryActive && (within(a,size,NAME,NAME+32) || within(a,size,FALLBACK,FALLBACK+8)))
                for(int i=0;i<size;i++) registryReads.add(a+i);
            if(within(a,size,NAME-16,NAME+48)) return;
            super.beforeLoad(t,op,space,offset,size);
        }
        @Override public void beforeStore(PcodeThread<byte[]> t,PcodeOp op,AddressSpace space,byte[] offset,int size,byte[] value) {
            long a=Utils.bytesToLong(offset,offset.length,false);
            if(registryActive && (within(a,size,PREFIX_TABLE,PREFIX_TABLE+512) || a==BACKEND_STATE+8 && size==4)) return;
            super.beforeStore(t,op,space,offset,size,value);
        }
        void registryFixtures(byte[] table,long global) {
            fixtures(table); writeWord(BACKEND_VT+0x30,DISPOSE);
            byte[] state=new byte[48]; Arrays.fill(state,(byte)0xa4); memory(BACKEND_STATE-16,state);
            writeWord(BACKEND_STATE+8,global);
        }
        void resetRegistry(boolean rebuilt,byte[] table,long global) {
            initialize(rebuilt,0,new byte[0x144]); destroyed=false; active=false; trace.clear();
            registryFixtures(table,global);
        }
        void initializeConnectedRegistry(boolean rebuilt) throws Exception {}
        @Override void setupAllocation(byte[] initial,long length,long allocation) {
            super.setupAllocation(initial,length,allocation);
            byte[] table=occupied(); int slot=(cases/6)%32; put(table,slot*16+8,0);
            registryFixtures(table,BACKEND);
            long pc=thread.getCounter().getOffset(),flags=register("cpsr");
            long[] saved=new long[15]; for(int r=0;r<15;r++) saved[r]=register(r==13 ? "sp" : r==14 ? "lr" : "r"+r);
            boolean old=executing;
            try { initializeConnectedRegistry(rebuiltFixture); mutate(rebuiltFixture,0,name('r',0),0,BACKEND,0x123456ffL,1,false,0); connectedRegistrations++; }
            catch(Exception e) { throw new IllegalStateException("Worker I/O case connected registry",e); }
            finally {
                executing=old;
                for(int r=0;r<15;r++) register(r==13 ? "sp" : r==14 ? "lr" : "r"+r,saved[r]);
                select(pc,(flags&32)!=0); register("cpsr",flags);
            }
        }
        long mutate(boolean rebuilt,int kind,byte[] name,int alignment,long backend,long flag,long retain,boolean terminal,int effect) throws Exception {
            byte[] input=new byte[64]; Arrays.fill(input,(byte)0xdb); System.arraycopy(name,0,input,16+alignment,name.length); memory(NAME-16,input);
            byte[] expectedTable=memory(PREFIX_TABLE-16,544),expectedState=memory(BACKEND_STATE-16,48),backendBytes=memory(BACKEND,512);
            byte[] initialTable=expectedTable.clone(),initialState=expectedState.clone();
            long key=nameKey(name),expected=kind==0 ? 0xe0e046bcL : NO_BACKEND;
            int stop=0; while(stop<8 && name[stop]!=0 && name[stop]!=':') stop++;
            boolean overlong=stop==8,willDispose=false; int match=-1; long removed=0;
            if(!(overlong && terminal)) {
                if(kind==0 && key!=0) {
                    expected=0xd8604659L;
                    for(int i=0;i<32;i++) {
                        int at=16+i*16;
                        if(word(expectedTable,at+8)==0) {
                            pair(expectedTable,at,key); put(expectedTable,at+8,backend);
                            expectedTable[at+12]=(byte)flag; expectedTable[at+13]=(byte)retain; expected=0; break;
                        }
                        if(pair(expectedTable,at)==key) { expected=0xc82044b4L; break; }
                    }
                } else if(kind==1) {
                    for(int i=0;i<32;i++) if(pair(expectedTable,16+i*16)==key) {
                        match=i; int at=16+i*16; removed=word(expectedTable,at+8);
                        put(expectedTable,at+8,0); pair(expectedTable,at,0);
                        expected=removed==0 ? NO_BACKEND : 0;
                        willDispose=removed!=0 && expectedTable[at+13]==0; break;
                    }
                }
            }
            registryReads.clear(); registryActive=true; executing=true;
            long sp=register("sp"); long[] saved=new long[8]; for(int r=4;r<=11;r++) saved[r-4]=register("r"+r);
            register("r0",NAME+alignment); register("r1",backend); register("r2",flag); register("r3",retain); register("lr",RETURN);
            select(rebuilt ? kind==0 ? registerEntry : removeEntry : kind==0 ? REGISTER : REMOVE,false);
            int steps=0,diagnostics=0,disposeCalls=0; boolean returned=true;
            while(thread.getCounter().getOffset()!=RETURN) {
                long pc=thread.getCounter().getOffset();
                if(pc==precloseTarget(rebuilt)) {
                    require(overlong && ++diagnostics==1,"Overlong diagnostic predicate");
                    require(Arrays.equals(memory(PREFIX_TABLE-16,544),initialTable) && Arrays.equals(memory(BACKEND_STATE-16,48),initialState),"Diagnostic precedes publication");
                    require((register("sp")&7)==0,"Diagnostic stack alignment");
                    if(recoverBreak) {
                        long payload=kind==0 ? ((long)name[7])&MASK : 8;
                        require(register("r2")==payload,"Prefix caller r2 provenance");
                        if(!breakCall(this,rebuilt,0,payload,terminal,0,0)) { returned=false; terminalNames++; break; }
                        returningNames++; continue;
                    }
                    if(terminal) { returned=false; terminalNames++; break; }
                    returningNames++; externalReturn(0xfedcba98L); continue;
                }
                if(pc==DISPOSE) {
                    require(willDispose && ++disposeCalls==1 && register("r0")==removed,"Disposal predicate/receiver");
                    require((register("sp")&7)==0,"Disposal stack alignment");
                    require(Arrays.equals(expectedTable,memory(PREFIX_TABLE-16,544)),"Clear pointer/key before disposal; preserve flags");
                    require(Arrays.equals(expectedState,memory(BACKEND_STATE-16,48)),"Global unchanged before disposal");
                    // Model may replace the global, and repopulate the just-cleared record.
                    long global=effect==1 ? BACKEND+32 : effect==2 ? removed : effect==3 ? 0 : word(expectedState,24);
                    writeWord(BACKEND_STATE+8,global); put(expectedState,24,global);
                    if(effect==4) {
                        int at=16+match*16; pair(expectedTable,at,0x9988776655443322L); put(expectedTable,at+8,BACKEND+32);
                        expectedTable[at+13]=(byte)0xfe; memory(PREFIX_TABLE+match*16,Arrays.copyOfRange(expectedTable,at,at+16));
                    }
                    if(global==removed) put(expectedState,24,0);
                    disposals++; externalReturn(0x80000001L); continue;
                }
                require(rebuilt ? within(pc,4,BUILD,BUILD+codeSize) : registryCode(pc),"Registry PC "+Long.toHexString(pc));
                if(!rebuilt) visited.add(pc);
                require(++steps<2000,"Registry instruction budget"); monitor.checkCancelled(); thread.stepInstruction();
            }
            registryActive=false;
            require(diagnostics==(overlong ? 1 : 0),"Diagnostic count");
            require(disposeCalls==(willDispose ? 1 : 0),"Disposal count");
            Set<Long> expectedReads=new TreeSet<>(); for(int i=0;i<(overlong ? 8 : stop+1);i++) expectedReads.add(NAME+alignment+i);
            if(overlong && !terminal) for(int i=0;i<8;i++) expectedReads.add(FALLBACK+i);
            require(registryReads.equals(expectedReads),"Exact name/fallback readable footprint");
            require(Arrays.equals(expectedTable,memory(PREFIX_TABLE-16,544)),"Registry guarded publication/removal");
            require(Arrays.equals(expectedState,memory(BACKEND_STATE-16,48)),"Post-disposal global reload/guards");
            require(Arrays.equals(input,memory(NAME-16,64)) && Arrays.equals(backendBytes,memory(BACKEND,512)),"Name/backend immutability");
            if(returned) {
                require(register("r0")==expected,"Registry exact status expected="+expected+" actual="+register("r0"));
                require(register("sp")==sp,"Registry stack restoration");
                for(int r=4;r<=11;r++) require(register("r"+r)==saved[r-4],"Registry saved register");
            }
            for(byte b:memory(STACK-0x1000,0xe00)) require(b==(byte)0x96,"Registry stack guard");
            return returned ? expected : -1;
        }
        void persistentOpen(boolean rebuilt,int[] prefix,boolean found) throws Exception {
            int[] units=path(prefix,7); byte[] bytes=new byte[2048];
            for(int i=0;i<units.length;i++) { bytes[i*2]=(byte)units[i]; bytes[i*2+1]=(byte)(units[i]>>8); }
            memory(PATH,bytes); register("r0",SIZE); register("r1",PATH); register("r2",3); register("lr",RETURN); writeWord(SIZE,0xa5a5a5a5L);
            select(rebuilt ? openEntry : OPEN,false);
            long result=execute(rebuilt,0,PATH,units,memory(PREFIX_TABLE,512),1,0x34567890,3);
            require(result==(found ? 1 : NO_BACKEND),"Persistent registration-to-open result");
        }
    }
    void registryProbe(RegistryMachine a,RegistryMachine b,int kind,byte[] name,int alignment,byte[] table,long backend,long flag,long retain,long global,boolean terminal,int effect,PrintWriter log) throws Exception {
        try {
            a.resetRegistry(false,table,global); b.resetRegistry(true,table,global);
            long x=a.mutate(false,kind,name,alignment,backend,flag,retain,terminal,effect),y=b.mutate(true,kind,name,alignment,backend,flag,retain,terminal,effect);
            require(x==y && Arrays.equals(a.memory(PREFIX_TABLE-16,544),b.memory(PREFIX_TABLE-16,544)) && Arrays.equals(a.memory(BACKEND_STATE-16,48),b.memory(BACKEND_STATE-16,48)),"Registry original/rebuilt agreement");
        } catch(Exception e) { throw new IllegalStateException("Worker I/O case registry="+registryCases+" kind="+kind+" name="+HexFormat.of().formatHex(name)+" effect="+effect,e); }
        log.printf("%d\t%d\t%s\t%d\t%d\t%d%n",++registryCases,kind,HexFormat.of().formatHex(name),alignment,terminal ? 1 : 0,effect);
    }
    @Override void preChecks(byte[] mapped,byte[] binary,Path out) throws Exception {
        RegistryMachine a=new RegistryMachine(mapped,binary),b=new RegistryMachine(mapped,binary);
        try(PrintWriter log=new PrintWriter(Files.newBufferedWriter(out.resolve("registry-results.tsv")))) {
            log.println("case\tkind\tname_hex\talignment\tterminal\teffect");
            // Positions, stale matching vacant entries, earlier/later duplicates, full and null publication.
            for(int slot=0;slot<32;slot++) for(int variant=0;variant<5;variant++) {
                byte[] name=name('r','o','m',variant%2==0 ? 0 : ':','x'),table=occupied();
                long key=nameKey(name); pair(table,slot*16,key);
                if(variant!=1) put(table,slot*16+8,0);
                if(variant==2 && slot>0) pair(table,(slot-1)*16,key);
                if(variant==3 && slot<31) pair(table,(slot+1)*16,key);
                registryProbe(a,b,0,name,slot%4,table,variant==4 ? 0 : BACKEND,0x123456ffL,0x87654380L,BACKEND,false,0,log);
                registryProbe(a,b,1,name,slot%4,table,0,0,0,BACKEND,false,0,log);
            }
            // Signed packing at every possible key byte and high-word carry boundaries.
            for(int length=1;length<=7;length++) for(int position=0;position<length;position++) for(int value:new int[]{1,0x7f,0x80,0xff}) {
                byte[] name=new byte[12]; Arrays.fill(name,0,length,(byte)'a'); name[position]=(byte)value;
                byte[] table=occupied(); put(table,31*16+8,0);
                registryProbe(a,b,0,name,position%4,table,BACKEND,0x100,0x100,0,false,0,log);
                pair(table,31*16,nameKey(name)); put(table,31*16+8,BACKEND); table[31*16+13]=0;
                registryProbe(a,b,1,name,position%4,table,0,0,0,0,false,2,log);
            }
            for(byte[] name:new byte[][]{name(0),name(':'),name('r',0,'x'),name('r',':','x'),name(1,2,3,4,5,6,7,0),name(1,2,3,4,5,6,7,8,0)}) {
                for(int kind=0;kind<2;kind++) for(int variant=0;variant<3;variant++) for(boolean terminal:new boolean[]{false,true}) {
                    byte[] table=variant==0 ? new byte[512] : occupied();
                    if(variant==2) { pair(table,0,nameKey(name)); table[13]=0; }
                    registryProbe(a,b,kind,name,variant,table,BACKEND,0xfe,0xff,BACKEND,terminal,0,log);
                }
            }
            // Removal uses the first equal key even with null pointer; flag truncation and callback effects.
            for(int retain:new int[]{0,1,0x7f,0x80,0xff}) for(int effect=0;effect<5;effect++) for(long global:new long[]{0,BACKEND,BACKEND+32}) {
                byte[] name=name('r',0),table=occupied(); pair(table,16,nameKey(name)); pair(table,32,nameKey(name)); table[16+13]=(byte)retain;
                registryProbe(a,b,1,name,effect%4,table,0,0,0,global,false,effect,log);
            }
            // No vacancy and no duplicate exercises exact full status.
            registryProbe(a,b,0,name('r',0),0,occupied(),BACKEND,0,0,0,false,0,log);
            for(boolean rebuilt:new boolean[]{false,true}) for(int[] prefix:new int[][]{{'r'},{'a',0x80,'b'},{1,2,3,4,5,6,7}}) {
                RegistryMachine m=rebuilt ? b : a; m.resetRegistry(rebuilt,new byte[512],BACKEND);
                byte[] name=new byte[12]; for(int i=0;i<prefix.length;i++) name[i]=(byte)prefix[i];
                m.mutate(rebuilt,0,name,0,BACKEND,0xff,0,false,0); m.persistentOpen(rebuilt,prefix,true);
                m.mutate(rebuilt,0,name,0,BACKEND+32,0,1,false,0); // Duplicate preserves owner.
                m.mutate(rebuilt,1,name,0,0,0,0,false,1); m.persistentOpen(rebuilt,prefix,false);
                m.mutate(rebuilt,0,name,0,BACKEND+32,0x123,0x100,false,0); m.persistentOpen(rebuilt,prefix,true);
                m.mutate(rebuilt,1,name,0,0,0,0,false,2); m.persistentOpen(rebuilt,prefix,false); persistentRegistries++;
            }
        }
        super.preChecks(mapped,binary,out);
    }
    @Override String extraChecks(byte[] mapped,byte[] binary,Path out) throws Exception {
        String inherited=super.extraChecks(mapped,binary,out); StringBuilder listing=new StringBuilder(); int count=0,total=0;
        for(long[] range:new long[][]{{REGISTER,0x2b5fb8},{REMOVE,0x2c41a4}})
            for(var ins:currentProgram.getListing().getInstructions(new AddressSet(toAddr(range[0]),toAddr(range[1]-1)),true)) {
                long pc=ins.getAddress().getOffset(); boolean seen=visited.contains(pc); if(seen) count++; total++;
                listing.append(String.format("%08x %s %s visited=%s%n",pc,HexFormat.of().formatHex(ins.getBytes()),ins,seen));
            }
        Files.writeString(out.resolve("original-registry-ghidra.txt"),listing);
        return inherited+String.format(Locale.ROOT,",\"direct_registry_cases\":%d,\"connected_registrations_both\":%d,\"persistent_registry_sequences_both\":%d,\"new_registry_instruction_addresses\":%d,\"registry_instruction_total\":%d,\"disposal_calls_both\":%d,\"terminal_name_diagnostics_both\":%d,\"returning_name_diagnostics_both\":%d,\"prefix_mutation_recovered\":true,\"backend_disposal_modeled\":true",registryCases,connectedRegistrations,persistentRegistries,count,total,disposals,terminalNames,returningNames);
    }
    @Override public void run() throws Exception {
        var lines=Files.readAllLines(Path.of(getScriptArgs()[0]).resolve("entries.txt"));
        registerEntry=Long.parseLong(lines.get(36)); removeEntry=Long.parseLong(lines.get(37)); super.run();
    }
}
