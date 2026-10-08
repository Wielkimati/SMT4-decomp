// Concrete ownership, guarded state oracle, service-boundary observations.
// @category SMT4
import ghidra.pcode.emu.PcodeThread;
import ghidra.pcode.exec.*;
import ghidra.pcode.exec.PcodeExecutorStatePiece.Reason;
import ghidra.program.model.listing.Instruction;
import ghidra.pcode.utils.Utils;
import ghidra.program.model.address.*;
import ghidra.program.model.pcode.PcodeOp;
import java.nio.file.*;
import java.security.MessageDigest;
import java.util.*;
import java.io.*;

public class CompareResourceWorkerBackend extends CompareResourceSync {
    static final long POOL=0x4d431c, STATE=0x44e650, VT=0x4209f8, TABLE=0x4d43e0;
    static final long NODE=0x910000, OUT=0x912000, NAME=0x913000, WPATH=0x914000;
    static final long OPEN=0x2adbe8, CLOSE=0x2adbb8, ACQUIRE=0x2c3afc, RELEASE=0x2c3a78;
    static final long CLEAR=0x139f54, DIAG=0x2bbd70, FILE_OPEN=0x780000, ALT=0x780004, ALT_VT=0x915000;
    static final long MASK=0xffffffffL, EMPTY=0xd8604659L;
    static final long[] BEGIN={0x2b5d6c,0x3568c8,0x23a004,0x35674c,0x3562d0,0x354dec,0x2b5e70,0x2c4054,0x2bb944,0x2b5ca0,0x2b5c8c};
    static final long[] LIMIT={0x2b5dd0,0x356974,0x23a028,0x3567a0,0x35631c,0x354e60,0x2b5fb8,0x2c41a4,0x2bb9d4,0x2b5d68,0x2b5c9e};
    long[] entry=new long[11];
    boolean recoverClear; long clearEntry; int executedClears;
    boolean recoverLocks; long[] lockEntry=new long[2]; int executedLocks,lockTlsReads,lockExclusives,nestedSequences;
    static final long LOCK_TLS=0x919000;
    void loadLocks(Path out) throws Exception {
        recoverLocks=Files.exists(out.resolve("lock-entries.txt"));
        if(recoverLocks) {var lines=Files.readAllLines(out.resolve("lock-entries.txt"));require(lines.size()==2,"Lock entries");for(int i=0;i<2;i++)lockEntry[i]=Long.parseLong(lines.get(i));}
    }
    void saveLocks(Path out) throws Exception {
        if(recoverLocks)Files.writeString(out.resolve("locks.json"),String.format(Locale.ROOT,
            "{\"executed_wrapper_calls_both\":%d,\"tls_reads_both\":%d,\"exclusive_stores_both\":%d,\"nested_pool_sequences\":%d,\"wrapper_and_base_models_removed\":true,\"tls_exclusives_scheduled\":true,\"arbitration_reached\":false,\"initial_lock_storage_synthetic\":true}\n",executedLocks,lockTlsReads,lockExclusives,nestedSequences));
    }
    void loadClear(Path out) throws Exception {
        recoverClear=Files.exists(out.resolve("clear-entry.txt"));
        if(recoverClear) clearEntry=Long.parseLong(Files.readString(out.resolve("clear-entry.txt")).trim());
    }
    void saveClear(Path out) throws Exception {
        if(recoverClear) Files.writeString(out.resolve("clear.json"),"{\"executed_calls_both\":"+executedClears+",\"clear_model_removed\":true,\"other_models_unchanged\":true}\n");
    }
    int cases,sequences,terminals,returningDiagnostics,closeCalls,openCalls,clearCalls,altCalls;
    int[] kinds=new int[9];
    class State {
        TreeMap<Long,byte[]> blocks=new TreeMap<>();
        State() {
            add(POOL-16,0x90,0x81); add(STATE-16,64,0x82); add(TABLE-16,544,0x83);
            add(NODE-16,0x100,0x84); add(OUT-16,48,0x85); add(NAME,64,0x86); add(WPATH,64,0x87);
            Arrays.fill(blocks.get(TABLE-16),16,528,(byte)0);
            set(POOL+0x24,NODE); set(POOL+0x2c,0); set(POOL+0x14,0); set(POOL+0x18,16);
            set(NODE,NODE+0x40); set(NODE+0x40,0); set(STATE+8,0); set(STATE+16,0x11223344);
            if(recoverLocks) {set(POOL+0x30,1);set(POOL+0x34,0);set(POOL+0x38,0);}
            byte[] n=blocks.get(NAME); n[0]='r'; n[1]='o'; n[2]='m'; n[3]=0;
            byte[] p=blocks.get(WPATH); int[] units={'r','o','m',':','/','a',0};
            for(int i=0;i<units.length;i++) { p[2*i]=(byte)units[i]; p[2*i+1]=(byte)(units[i]>>8); }
        }
        State(State other) { for(var e:other.blocks.entrySet()) blocks.put(e.getKey(),e.getValue().clone()); }
        void add(long at,int n,int fill) { byte[] b=new byte[n]; Arrays.fill(b,(byte)fill); blocks.put(at,b); }
        long get(long at) { var e=blocks.floorEntry(at); return word(e.getValue(),(int)(at-e.getKey())); }
        void set(long at,long value) { var e=blocks.floorEntry(at); put(e.getValue(),(int)(at-e.getKey()),value); }
        void clear(long at,int size) { var e=blocks.floorEntry(at); Arrays.fill(e.getValue(),(int)(at-e.getKey()),(int)(at-e.getKey())+size,(byte)0); }
        void object(long low,long high,long service) { set(NODE,VT); set(NODE+4,service); set(NODE+8,low); set(NODE+12,high); }
    }
    class Config {
        long status=0,low=0x87654321L,high=0xfedcba98L,archive=4,closeStatus=0x80000001L;
        int effect; boolean terminal,alternate;
    }
    class Event {
        long pc,result; long[] args; State before,after; boolean terminal;
        Event(long p,long r,State s,long... a) { pc=p; result=r; args=a; before=new State(s); }
    }
    class Oracle {
        State s; Config c; List<Event> events=new ArrayList<>(); boolean stopped;
        Oracle(State initial,Config config) { s=new State(initial); c=config; }
        Event begin(long pc,long result,long... args) { Event e=new Event(pc,result,s,args); events.add(e); return e; }
        void end(Event e) { e.after=new State(s); }
        void lock(boolean acquire) {
            Event e=begin(acquire ? ACQUIRE : RELEASE,0xaabbccddL,POOL+0x30);
            if(recoverLocks) {
                if(acquire) {
                    if(s.get(POOL+0x34)!=LOCK_TLS) {require(s.get(POOL+0x30)==1,"Uncontended pool base");s.set(POOL+0x30,MASK);s.set(POOL+0x34,LOCK_TLS);}
                    s.set(POOL+0x38,(s.get(POOL+0x38)+1)&MASK);
                } else {
                    long count=(s.get(POOL+0x38)-1)&MASK;s.set(POOL+0x38,count);
                    if(count==0) {s.set(POOL+0x34,0);require(s.get(POOL+0x30)==MASK,"Release base");s.set(POOL+0x30,1);}
                }
            } else if(c.effect>=2) s.set(STATE+16,acquire ? 0x55667788L : 0x99aabbccL);
            end(e);
        }
        long take() {
            lock(true); long node=s.get(POOL+0x24);
            if(node!=0) {
                s.set(POOL+0x24,s.get(node)); s.set(POOL+0x2c,s.get(POOL+0x2c)+1);
                if((s.get(POOL+0x14)&1)!=0) {
                    int size=(int)s.get(POOL+0x18); Event e=begin(CLEAR,0x12345678,node,node+size,0);
                    s.clear(node,size); end(e);
                }
            }
            lock(false); return node;
        }
        void close(long service,long low,long high) {
            Event e=begin(CLOSE,c.closeStatus,service,low,high);
            if(c.effect>=3) { s.set(NODE+4,0xabcdef01L); s.set(NODE+8,0x22222222); s.set(NODE+12,0x33333333); s.set(STATE+8,NODE+0x40); }
            end(e);
        }
        long create(boolean externalOutput) {
            Event e=begin(OPEN,c.status,s.get(STATE+16),c.archive);
            if(c.effect>=1) s.set(STATE+16,0x22334455);
            end(e);
            if((c.status&0x80000000L)!=0) return c.status;
            long service=s.get(STATE+16),node=take();
            if(node!=0) { s.set(node,VT); s.set(node+4,service); s.set(node+8,c.low); s.set(node+12,c.high); }
            if(externalOutput) s.set(OUT,node);
            created=node;
            if(node==0) { close(s.get(STATE+16),c.low,c.high); return EMPTY; }
            return 0;
        }
        long created;
        long service(long node) {
            if(s.get(node+4)==0) {
                Event e=begin(DIAG,0x1234,0xe0a046daL,0x23a020); e.terminal=c.terminal;
                if(c.terminal) stopped=true;
                else if(c.effect!=0) { s.set(node+4,0x66778899); s.set(node+8,0xaabbccddL); s.set(node+12,0x55667788); }
                end(e);
            }
            return s.get(node+4);
        }
        void teardown(long node) {
            s.set(node,VT); long low=s.get(node+8),high=s.get(node+12);
            if((low|high)!=0) {
                long service=service(node); if(stopped) return;
                close(service,low,high); s.set(node+8,0); s.set(node+12,0);
            }
            s.set(node+4,0);
        }
        void dispose(long node) {
            if(c.alternate) { Event e=begin(ALT,0,node); s.set(node+4,0); s.set(node+8,0); s.set(node+12,0); end(e); }
            else teardown(node);
            if(stopped) return;
            lock(true); s.set(node,s.get(POOL+0x24)); s.set(POOL+0x24,node); s.set(POOL+0x2c,s.get(POOL+0x2c)-1); lock(false);
        }
        long key() { byte[] n=s.blocks.get(NAME); long k=0; for(int i=0;i<8;i++) { if(n[i]==0 || n[i]==':') return k; k=(k<<8)|n[i]; } throw new IllegalStateException("Only bounded names in lifetime corpus"); }
        long register(long node) {
            long k=key(); if(k==0) return 0xe0e046bcL;
            for(int i=0;i<32;i++) {
                long at=TABLE+16*i;
                if(s.get(at+8)==0) { s.set(at,k); s.set(at+4,k>>>32); s.set(at+8,node); var b=s.blocks.get(TABLE-16); b[16+16*i+12]=0; b[16+16*i+13]=0; return 0; }
                if(s.get(at)==(k&MASK) && s.get(at+4)==(k>>>32)) return 0xc82044b4L;
            }
            return EMPTY;
        }
        long singleton() {
            if(s.get(STATE+8)!=0) return 0xc92044e7L;
            long r=create(false); if((r&0x80000000L)!=0) return r;
            r=register(created); if((r&0x80000000L)==0) s.set(STATE+8,created); else dispose(created); return r;
        }
        long remove() {
            long k=key();
            for(int i=0;i<32;i++) {
                long at=TABLE+16*i;
                if(s.get(at)!=(k&MASK) || s.get(at+4)!=(k>>>32)) continue;
                long node=s.get(at+8); int retain=s.blocks.get(TABLE-16)[16+16*i+13]&255;
                s.set(at,0); s.set(at+4,0); s.set(at+8,0);
                if(node==0) return 0xc8804465L;
                if(retain==0) { dispose(node); if(!stopped && s.get(STATE+8)==node) s.set(STATE+8,0); }
                return 0;
            }
            return 0xc8804465L;
        }
        long fileOpen() {
            long node=0,k=key();
            for(int i=0;i<32;i++) if(s.get(TABLE+16*i)==(k&MASK) && s.get(TABLE+16*i+4)==(k>>>32)) { node=s.get(TABLE+16*i+8); break; }
            if(node==0) return 0xc8804465L;
            Event e=begin(FILE_OPEN,c.status,node,3,WPATH+8,6); end(e);
            if((c.status&0x80000000L)==0) s.set(OUT,0x76543210); return c.status;
        }
        long call(int kind) {
            switch(kind) {
                case 0:return take(); case 1:return create(true); case 2:return service(NODE);
                case 3:teardown(NODE);return NODE; case 4:dispose(NODE);return -1;
                case 5:return singleton(); case 6:return register(NODE); case 7:return remove(); case 8:return fileOpen();
            }
            throw new IllegalStateException("kind");
        }
    }
    class BackendMachine extends SyncMachine {
        State layout; boolean isRebuilt; List<String> trace=new ArrayList<>();
        boolean insideLock,exclusiveRead,reservation,storePending,storeAllowed;
        BackendMachine(byte[] map,byte[] binary) { super(map,binary); }
        @Override public void beforeExecuteInstruction(PcodeThread<byte[]> t,Instruction instruction,PcodeProgram program) {
            if(!insideLock)return;
            String name=instruction.getMnemonicString().toLowerCase(Locale.ROOT);
            exclusiveRead=name.equals("ldrex");
            if(name.equals("strex")) {require(reservation && !storePending,"Pool STREX reservation");storePending=true;}
        }
        @Override public boolean handleMissingUserop(PcodeThread<byte[]> t,PcodeOp op,PcodeFrame frame,String name,PcodeUseropLibrary<byte[]> library) {
            require(insideLock && name.equals("hasExclusiveAccess") && reservation && storePending,"Pool exclusive operation");
            byte[] arg=t.getState().getVar(op.getInput(1),Reason.INSPECT);
            require(Utils.bytesToLong(arg,arg.length,false)==POOL+0x30,"Pool exclusive address");
            reservation=storePending=false;storeAllowed=true;lockExclusives++;
            t.getState().setVar(op.getOutput(),machine.getArithmetic().fromConst(1,op.getOutput().getSize()));return true;
        }
        void executeLock() throws Exception {
            long ret=register("lr")&~1L,sp=register("sp");int steps=0;
            insideLock=true;exclusiveRead=reservation=storePending=storeAllowed=false;
            do {
                long pc=thread.getCounter().getOffset();
                require(isRebuilt?within(pc,4,BUILD,BUILD+codeSize):within(pc,4,ACQUIRE,0x2c3b34)||within(pc,4,RELEASE,0x2c3a98)||within(pc,4,0x1464f8,0x1465d4)||within(pc,4,0x138fc0,0x139010),"Pool lock PC");
                require(++steps<512,"Pool lock budget");if(!isRebuilt)visited.add(pc);
                long bits=get(pc);
                if((bits&0xffff0fffL)==0xee1d0f70L) {register("r"+((bits>>>12)&15),LOCK_TLS);lockTlsReads++;thread.overrideCounter(toAddr(pc+4));continue;}
                thread.stepInstruction();
            } while(thread.getCounter().getOffset()!=ret);
            require(register("sp")==sp && !reservation && !storePending && !storeAllowed,"Pool lock return");
            insideLock=false;executedLocks++;
        }
        void executeClear() throws Exception {
            long ret=register("lr")&~1L, sp=register("sp"); int steps=0;
            do {
                long pc=thread.getCounter().getOffset();
                require(isRebuilt?within(pc,4,BUILD,BUILD+codeSize):within(pc,4,CLEAR,0x139f84),"Clear PC");
                if(!isRebuilt)visited.add(pc);
                require(++steps<2048,"Clear budget");thread.stepInstruction();
            } while(thread.getCounter().getOffset()!=ret);
            require(register("sp")==sp,"Clear stack restoration");executedClears++;
        }
        long get(long at) { return word(memory(at,4),0); }
        @Override public void beforeStore(PcodeThread<byte[]> t,PcodeOp op,AddressSpace sp,byte[] offset,int size,byte[] value) {
            long a=Utils.bytesToLong(offset,offset.length,false);
            if(insideLock && a==POOL+0x30) {require(size==4 && storeAllowed,"Pool exclusive write");storeAllowed=false;}
            boolean valid=within(a,size,STACK-0x1000,STACK) || within(a,size,POOL,POOL+0x40) || within(a,size,STATE,STATE+20) || within(a,size,TABLE,TABLE+512) || within(a,size,OUT,OUT+4);
            for(int i=0;i<2;i++) valid|=within(a,size,NODE+0x40*i,NODE+0x40*i+16);
            require(valid,"Store outside lifetime fields "+Long.toHexString(a));
        }
        @Override public void beforeLoad(PcodeThread<byte[]> t,PcodeOp op,AddressSpace sp,byte[] offset,int size) {
            long a=Utils.bytesToLong(offset,offset.length,false);
            if(insideLock && a==POOL+0x30) {require(size==4 && exclusiveRead && !reservation,"Pool exclusive load");reservation=true;}
            boolean valid=within(a,size,STACK-0x1000,STACK) || within(a,size,0x100000,0x477000) || within(a,size,BUILD,BUILD+codeSize) || within(a,size,ALT_VT,ALT_VT+56);
            for(var e:layout.blocks.entrySet()) valid|=within(a,size,e.getKey(),e.getKey()+e.getValue().length);
            require(valid,"Load outside lifetime fixtures "+Long.toHexString(a));
        }
        void seed(State s,boolean rebuilt) {
            executing=false; layout=s; isRebuilt=rebuilt;
            for(var e:s.blocks.entrySet()) memory(e.getKey(),e.getValue());
            writeWord(VT,FILE_OPEN); writeWord(VT+0x30,rebuilt ? entry[4] : BEGIN[4]); writeWord(VT+0x34,rebuilt ? entry[3] : BEGIN[3]);
            memory(ALT_VT,new byte[56]); writeWord(ALT_VT+0x34,ALT);
        }
        void check(State s,String label) {
            for(var e:s.blocks.entrySet()) require(Arrays.equals(memory(e.getKey(),e.getValue().length),e.getValue()),label+" block "+Long.toHexString(e.getKey()));
        }
        void apply(Event e) {
            for(var b:e.after.blocks.entrySet()) if(!Arrays.equals(b.getValue(),e.before.blocks.get(b.getKey()))) memory(b.getKey(),b.getValue());
        }
        void call(int kind,Oracle oracle,long expected) throws Exception {
            initialize(isRebuilt,0,new byte[0x144]); trace.clear();
            register("r0",kind==0 ? POOL : kind==1 || kind==8 ? OUT : kind>=5 ? NAME : NODE);
            register("r1",kind==1 ? oracle.c.archive : kind==8 ? WPATH : NODE); register("r2",kind==8 ? 3 : 0); register("r3",0);
            thread.overrideCounter(toAddr(isRebuilt ? entry[kind] : BEGIN[kind])); executing=true;
            int steps=0,event=0; boolean stopped=false;
            while(thread.getCounter().getOffset()!=RETURN) {
                long pc=thread.getCounter().getOffset();
                if(recoverClear && isRebuilt && pc==clearEntry)pc=CLEAR;
                if(recoverLocks && isRebuilt) {if(pc==lockEntry[0])pc=ACQUIRE;else if(pc==lockEntry[1])pc=RELEASE;}
                if(pc==OPEN || pc==CLOSE || pc==ACQUIRE || pc==RELEASE || pc==CLEAR || pc==DIAG || pc==FILE_OPEN || pc==ALT) {
                    require(event<oracle.events.size(),"Unexpected boundary "+Long.toHexString(pc)); Event e=oracle.events.get(event++);
                    require(pc==e.pc,"Boundary order"); check(e.before,"Before "+Long.toHexString(pc));
                    require((register("sp")&7)==0,"Boundary stack alignment");
                    long r0=register("r0"),r1=register("r1"),r2=register("r2"),r3=register("r3"),sp=register("sp");
                    if(pc==OPEN) {
                        require(get(r0)==e.args[0] && r2==e.args[1] && r3==1,"Archive open values");
                        require(within(r0,4,sp,STACK) && within(r1,8,sp,STACK) && (r1&7)==0,"Open locals");
                        long data=get(sp); require(get(sp+4)==1 && within(data,8,sp,STACK) && get(data)==data && get(data+4)==1,"Self-referential type-1 descriptor");
                        if((e.result&0x80000000L)==0 || (e.result&1)!=0) { writeWord(r1,oracle.c.low); writeWord(r1+4,oracle.c.high); }
                        openCalls++;
                    } else if(pc==CLOSE) {
                        require(within(r0,4,sp,STACK) && get(r0)==e.args[0] && r2==e.args[1] && r3==e.args[2],"Archive close captured values"); closeCalls++;
                    } else if(pc==FILE_OPEN) {
                        require(r0==e.args[0] && r3==e.args[1] && get(r2)==4 && get(r2+4)==e.args[2] && get(r2+8)==e.args[3],"File-open descriptor");
                        require(within(r1,4,sp,STACK) && within(r2,12,sp,STACK),"File-open scratch"); writeWord(r1,0x76543210);
                    } else {
                        require(r0==e.args[0],"Boundary r0");
                        if(pc==DIAG) { require(r1==e.args[1],"Diagnostic original site"); if(!e.terminal) returningDiagnostics++; }
                        if(pc==CLEAR) { require(r1==e.args[1] && r2==0,"Clear end/value"); clearCalls++; }
                        if(pc==ALT) altCalls++;
                    }
                    if(recoverClear && pc==CLEAR) {
                        executeClear(); check(e.after,"Executed clear");
                        trace.add(Long.toHexString(pc)+":"+Arrays.toString(e.args)); continue;
                    }
                    if(recoverLocks && (pc==ACQUIRE || pc==RELEASE)) {
                        executeLock();check(e.after,"Executed lock");trace.add(Long.toHexString(pc)+":"+Arrays.toString(e.args));continue;
                    }
                    apply(e); trace.add(Long.toHexString(pc)+":"+Arrays.toString(e.args));
                    if(e.terminal) { stopped=true; terminals++; break; }
                    externalReturn(e.result); continue;
                }
                boolean valid=isRebuilt && within(pc,4,BUILD,BUILD+codeSize);
                if(!isRebuilt) for(int i=0;i<BEGIN.length;i++) valid|=within(pc,i==10 ? 2 : 4,BEGIN[i],LIMIT[i]);
                require(valid,"Lifetime PC "+Long.toHexString(pc)); if(!isRebuilt) visited.add(pc);
                require(++steps<6000,"Lifetime instruction budget"); monitor.checkCancelled(); thread.stepInstruction();
            }
            require(event==oracle.events.size() && stopped==oracle.stopped,"Missing boundary/terminal");
            check(oracle.s,"Final");
            if(!stopped) { if(kind!=4) require(register("r0")==expected,"Result expected="+Long.toHexString(expected)+" actual="+Long.toHexString(register("r0"))); finish(steps); }
            for(byte b:memory(STACK-0x1000,0xd00)) require(b==(byte)0x96,"Stack guard");
            executing=false;
        }
    }
    State compare(BackendMachine a,BackendMachine b,State state,Config c,int kind,boolean seed,PrintWriter log) throws Exception {
        try {
            Oracle oracle=new Oracle(state,c); long expected=oracle.call(kind);
            if(seed) { a.seed(state,false); b.seed(state,true); }
            a.call(kind,oracle,expected); b.call(kind,oracle,expected); require(a.trace.equals(b.trace),"Boundary agreement");
            log.printf("%d\t%d\t%d\t%x\t%d\t%d%n",cases++,kind,c.effect,expected,oracle.events.size(),oracle.stopped ? 1 : 0); kinds[kind]++;
            return oracle.s;
        } catch(Exception e) { throw new IllegalStateException("Backend case "+cases+" kind="+kind+" effect="+c.effect,e); }
    }
    @Override public void run() throws Exception {
        Path out=Path.of(getScriptArgs()[0]); require(!Files.exists(out.resolve("comparison.json")),"Existing output");
        loadClear(out);
        loadLocks(out);
        byte[] map=new byte[0x377000]; require(currentProgram.getMemory().getBytes(toAddr(0x100000),map)==map.length,"Map");
        require(HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(map)).equals("834938d18d2b7c688311c46c27bed813d0d7a9f8e3cbb61da8a6a3f23d360ebd"),"Hash");
        require(word(map,(int)(VT-0x100000+0x30))==BEGIN[4] && word(map,(int)(VT-0x100000+0x34))==BEGIN[3],"Original vtable lifetime linkage");
        byte[] binary=Files.readAllBytes(out.resolve("resource-worker-backend.bin")); codeSize=binary.length;
        var lines=Files.readAllLines(out.resolve("entries.txt")); require(lines.size()==11,"Entries"); for(int i=0;i<11;i++) entry[i]=Long.parseLong(lines.get(i));
        StringBuilder boundaries=new StringBuilder();
        for(int i=0;i<6;i++) {
            var f=getFunctionAt(toAddr(BEGIN[i]));
            boundaries.append(Long.toHexString(BEGIN[i])+" "+(f==null ? "no saved function; bounded ARM decode" : f.getBody().toString())+"\n");
            if(f==null) { require(i==4,"Unexpected missing function"); require(disassemble(toAddr(BEGIN[i])),"Decode disposal"); }
            else require(f.getBody().getMinAddress().getOffset()==BEGIN[i] && f.getBody().getMaxAddress().getOffset()==LIMIT[i]-1,"Saved function boundary "+i);
        }
        Files.writeString(out.resolve("function-boundaries.txt"),boundaries);

        BackendMachine a=new BackendMachine(map,binary),b=new BackendMachine(map,binary);
        try(PrintWriter log=new PrintWriter(Files.newBufferedWriter(out.resolve("results.tsv")))) {
            log.println("case\tkind\teffect\tresult\tboundaries\tterminal");
            for(int empty=0;empty<2;empty++) for(long flags:new long[]{0,1,2,0xffffffffL}) for(long count:new long[]{0,1,0x7fffffffL,0xffffffffL}) for(int bytes:new int[]{0,4,16}) {
                State s=new State(); s.set(POOL+0x24,empty==1 ? 0 : NODE); s.set(POOL+0x14,flags); s.set(POOL+0x2c,count); s.set(POOL+0x18,bytes);
                compare(a,b,s,new Config(),0,true,log);
            }
            for(long status:new long[]{0,1,0x7fffffffL,0x80000000L,0xffffffffL}) for(int empty=0;empty<2;empty++) for(int effect=0;effect<4;effect++) for(long handle:new long[]{0,1,0x8000000000000000L,-1L}) {
                State s=new State(); s.set(POOL+0x24,empty==1 ? 0 : NODE); s.set(POOL+0x14,effect&1);
                Config c=new Config(); c.status=status; c.effect=effect; c.closeStatus=new long[]{0,1,0x80000000L,MASK}[effect]; c.archive=new long[]{0,4,0x80000000L,MASK}[effect]; c.low=handle&MASK;c.high=handle>>>32;
                compare(a,b,s,c,1,true,log);
            }
            for(int kind=2;kind<=4;kind++) for(long handle:new long[]{0,1,0x8000000000000000L,-1L}) for(long service:new long[]{0,1,0xffffffffL}) for(int effect=0;effect<4;effect++) for(boolean terminal:new boolean[]{false,true}) {
                State s=new State();s.object(handle&MASK,handle>>>32,service);s.set(POOL+0x24,NODE+0x40);s.set(POOL+0x2c,effect==0 ? 0 : effect==1 ? MASK : 1);
                Config c=new Config();c.effect=effect;c.closeStatus=new long[]{0,1,0x80000000L,MASK}[effect];c.terminal=terminal;compare(a,b,s,c,kind,true,log);
            }
            for(int count=0;count<2;count++) {
                State s=new State();s.object(1,2,3);s.set(NODE,ALT_VT);s.set(POOL+0x24,count==0 ? 0 : NODE+0x40);s.set(POOL+0x2c,count);
                Config c=new Config();c.alternate=true;compare(a,b,s,c,4,true,log);
            }
            for(int scenario=0;scenario<7;scenario++) for(int effect=0;effect<4;effect++) {
                State s=new State();Config c=new Config();c.effect=effect;
                if(scenario==1) s.set(STATE+8,NODE+0x40);
                if(scenario==2) c.status=0x80000001L;
                if(scenario==3) s.set(POOL+0x24,0);
                if(scenario==4) s.blocks.get(NAME)[0]=0;
                if(scenario==5) { s.set(TABLE,0x726f6d);s.set(TABLE+8,NODE+0x40); }
                if(scenario==6) for(int i=0;i<32;i++) {s.set(TABLE+16*i,0x100+i);s.set(TABLE+16*i+8,NODE+0x40);}
                compare(a,b,s,c,5,true,log);
            }
            // Persistent calls preserve actual emulator storage between calls.
            for(int flags=0;flags<2;flags++) {
                State s=new State();s.set(POOL+0x14,flags);Config c=new Config();
                a.seed(s,false);b.seed(s,true);
                for(int round=0;round<3;round++) {
                    s=compare(a,b,s,c,5,false,log); // create + register + publish
                    s=compare(a,b,s,c,5,false,log); // singleton already present
                    c.status=1;s=compare(a,b,s,c,8,false,log);c.status=0;
                    s=compare(a,b,s,c,7,false,log); // concrete disposal, pool return, global clear
                    s=compare(a,b,s,c,8,false,log); // removed prefix cannot open
                    require(s.get(POOL+0x24)==NODE && s.get(POOL+0x2c)==0 && s.get(STATE+8)==0,"Persistent owner returned");
                }
                sequences++;
            }
            // A close callback replaces the singleton during concrete removal.
            State s=new State(); Config c=new Config(); a.seed(s,false); b.seed(s,true);
            s=compare(a,b,s,c,5,false,log); c.effect=3;
            s=compare(a,b,s,c,7,false,log);
            require(s.get(STATE+8)==NODE+0x40 && s.get(POOL+0x24)==NODE && s.get(POOL+0x2c)==0,"Replacement singleton survives concrete disposal");
            s=compare(a,b,s,c,5,false,log); sequences++;
            if(recoverLocks)for(long count:new long[]{1,0x7fffffffL,0xfffffffeL}) {
                State nested=new State();nested.set(POOL+0x30,MASK);nested.set(POOL+0x34,LOCK_TLS);nested.set(POOL+0x38,count);nested.set(POOL+0x14,1);
                Config nc=new Config();a.seed(nested,false);b.seed(nested,true);
                for(int round=0;round<2;round++) {
                    nested=compare(a,b,nested,nc,5,false,log);nested=compare(a,b,nested,nc,7,false,log);
                    require(nested.get(POOL+0x30)==MASK && nested.get(POOL+0x34)==LOCK_TLS && nested.get(POOL+0x38)==count,"Nested pool preserves outer ownership");
                }
                nestedSequences++;sequences++;
            }
        }
        int count=0,seen=0;StringBuilder listing=new StringBuilder();
        for(int i=0;i<6;i++) for(long pc=BEGIN[i];pc<LIMIT[i];pc+=4) {
            var ins=currentProgram.getListing().getInstructionAt(toAddr(pc));require(ins!=null,"Instruction");count++;if(visited.contains(pc))seen++;
            listing.append(String.format("%08x %s %s visited=%s%n",pc,HexFormat.of().formatHex(ins.getBytes()),ins,visited.contains(pc)));
        }
        require(seen==count,"Unvisited lifetime instructions");Files.writeString(out.resolve("original-ghidra.txt"),listing);
        Files.writeString(out.resolve("comparison.json"),String.format(Locale.ROOT,"{\"cases\":%d,\"cases_by_kind\":%s,\"persistent_sequences\":%d,\"new_instruction_addresses\":%d,\"visited_new_instructions\":%d,\"open_calls_both\":%d,\"close_calls_both\":%d,\"clear_calls_both\":%d,\"alternate_teardown_calls_both\":%d,\"terminal_diagnostics_both\":%d,\"returning_diagnostics_both\":%d,\"max_steps\":%d,\"concrete_disposal_recovered\":true,\"services_locks_clear_diagnostics_modeled\":true,\"registry_startup_fixture\":true,\"live_verified\":false}\n",cases,Arrays.toString(kinds),sequences,count,seen,openCalls,closeCalls,clearCalls,altCalls,terminals,returningDiagnostics,maxSteps));
        saveClear(out);
        saveLocks(out);
        println("SMT4_BACKEND_COMPARE_OK");
    }
}
