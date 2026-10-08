// Concrete file ownership; reuse archive/prefix oracle and guarded emulator.
// @category SMT4
import ghidra.pcode.emu.PcodeThread;
import ghidra.pcode.utils.Utils;
import ghidra.program.model.address.*;
import ghidra.program.model.pcode.PcodeOp;
import java.nio.file.*;
import java.security.MessageDigest;
import java.util.*;
import java.io.*;

public class CompareResourceWorkerFileOwner extends CompareResourceWorkerBackend {
    static final long FPOOL=0x4d4358,FVT=0x420998,FNODE=0x916000,FDESC=0x917000;
    static final long FILE_SERVICE_OPEN=0x356c28,FILE_SERVICE_CLOSE=0x356d5c,SVC=0x780010,FILE_ALT=0x780014,FALT_VT=0x918000;
    static final long[] ALL_BEGIN=Arrays.copyOf(BEGIN,16),ALL_LIMIT=Arrays.copyOf(LIMIT,16);
    static { long[] a={0x3565a0,0x239cd0,0x356578,0x356438,0x2b9450},b={0x356660,0x239cf4,0x3565a0,0x3564a4,0x2b9468};
        System.arraycopy(a,0,ALL_BEGIN,11,5);System.arraycopy(b,0,ALL_LIMIT,11,5); }
    int fileOpens,fileCloses,svcCalls,fileAlts;
    int[] fileKinds=new int[16];
    boolean recoverServices,recoverArchives;
    static final long ARCHIVE_OUTPUT=0x91a008, STACK_PATH=0x91b000;
    static final long TLS=0x919000, CMD=TLS+0x80, IPC_HANDLE=0x91a000, IPC_OUTPUT=IPC_HANDLE+4, REQUEST=0x780018;
    int tlsReads,requests;
    long[] targetBegin=ALL_BEGIN,targetLimit=ALL_LIMIT;
    State initial() {
        State s=new State();s.add(FNODE-16,0x100,0x91);s.add(FDESC-16,48,0x92);
        s.set(FPOOL+0x24,FNODE);s.set(FPOOL+0x2c,0);s.set(FPOOL+0x14,0);s.set(FPOOL+0x18,8);
        s.set(FNODE,FNODE+0x40);s.set(FNODE+0x40,0);
        s.set(FDESC,4);s.set(FDESC+4,WPATH);s.set(FDESC+8,512);
        if(recoverServices) {
            s.add(TLS-16,0x140,0x93);s.add(IPC_HANDLE-16,48,0x94);
            for(int i=0;i<0x140/4;i++) s.set(TLS-16+4*i,0xa5010000L+0x101*i);
            s.set(IPC_HANDLE,0xabcdef01L);
        }
        return s;
    }
    class FileConfig extends Config {
        long fileStatus,handle=0xaabbccddL,flags=3,svcStatus=0x80000001L;
        boolean writeHandle=true,nullClose;
        int fileEffect;
        long kernelStatus,transaction=0xfedcba98L,attributes=0x13579bdfL;
        long archiveLow=0x12345678,archiveHigh=0x9abcdef0L;
        boolean response=true,archiveResponse=true;
        long archiveKernel;
    }
    class FileOracle extends Oracle {
        FileConfig f;
        FileOracle(State s,FileConfig c) { super(s,c);f=c; }
        Event serviceEvent(boolean open,long service,long transaction,long low,long high,long type,long data,long bytes,long flags,long attributes) {
            if(!recoverServices) return open ? begin(FILE_SERVICE_OPEN,f.fileStatus,service,low,high,type,data,bytes,flags,attributes) : begin(FILE_SERVICE_CLOSE,f.closeStatus,service);
            long[] words=open ? new long[]{0x080201c2,transaction,low,high,type,bytes,flags,attributes,((bytes<<14)|2)&MASK,data} : new long[]{0x08080000};
            for(int i=0;i<words.length;i++) s.set(CMD+4*i,words[i]);
            Event e=begin(REQUEST,f.kernelStatus,service,open ? 1 : 0);
            if(f.response) {s.set(CMD+4,open ? f.fileStatus : f.closeStatus);s.set(CMD+12,f.handle);s.set(CMD+60,0x5a5a1234);}
            return e;
        }
        long serviceResult(boolean open) {return recoverServices ? ((f.kernelStatus&0x80000000L)!=0 ? f.kernelStatus : s.get(CMD+4)) : open ? f.fileStatus : f.closeStatus;}
        Event archiveEvent(boolean open,long service,long archive,long type,long data,long bytes,long low,long high) {
            long[] words=open ? new long[]{0x080c00c2,archive,type,bytes,((bytes<<14)|2)&MASK,data} : new long[]{0x080e0080,low,high};
            for(int i=0;i<words.length;i++) s.set(CMD+4*i,words[i]);
            Event e=begin(REQUEST,f.archiveKernel,service,open ? 2 : 3);
            if(f.archiveResponse) {s.set(CMD+4,open ? f.status : f.closeStatus);s.set(CMD+8,f.low);s.set(CMD+12,f.high);s.set(CMD+60,0x8765abcdL);}
            return e;
        }
        long archiveResult() {return (f.archiveKernel&0x80000000L)!=0 ? f.archiveKernel : s.get(CMD+4);}
        @Override void close(long service,long low,long high) {
            if(!recoverArchives) {super.close(service,low,high);return;}
            Event e=archiveEvent(false,service,0,0,0,0,low,high);
            if(c.effect>=3) {s.set(NODE+4,0xabcdef01L);s.set(NODE+8,0x22222222);s.set(NODE+12,0x33333333);s.set(STATE+8,NODE+0x40);}
            end(e);
        }
        @Override long create(boolean externalOutput) {
            if(!recoverArchives) return super.create(externalOutput);
            Event e=archiveEvent(true,s.get(STATE+16),c.archive,1,STACK_PATH,1,0,0);
            if(c.effect>=1) s.set(STATE+16,0x22334455);
            end(e);
            long result=archiveResult();if((result&0x80000000L)!=0) return result;
            long low=s.get(CMD+8),high=s.get(CMD+12),service=s.get(STATE+16),node=take();
            if(node!=0) {s.set(node,VT);s.set(node+4,service);s.set(node+8,low);s.set(node+12,high);}
            if(externalOutput) s.set(OUT,node);
            created=node;
            if(node==0) {close(s.get(STATE+16),low,high);return EMPTY;}
            return 0;
        }
        @Override long service(long node) {
            boolean diagnostic=s.get(node+4)==0;
            long result=super.service(node);
            if(diagnostic && !stopped && f.fileEffect==5) {
                // A returning diagnostic may change the descriptor after the
                // one-time limit check. Original code reloads, without recheck.
                s.set(FDESC,MASK);s.set(FDESC+4,0);s.set(FDESC+8,1024);
                events.get(events.size()-1).after=new State(s);
            }
            return result;
        }
        void fileLock(boolean acquire) {
            Event e=begin(acquire ? ACQUIRE : RELEASE,0xcafef00dL,FPOOL+0x30);
            if(f.fileEffect==4 && acquire) { s.set(FPOOL+0x24,FNODE+0x40);s.set(FPOOL+0x2c,MASK); }
            end(e);
        }
        long fileTake() {
            fileLock(true);long node=s.get(FPOOL+0x24);
            if(node!=0) {
                s.set(FPOOL+0x24,s.get(node));s.set(FPOOL+0x2c,s.get(FPOOL+0x2c)+1);
                if((s.get(FPOOL+0x14)&1)!=0) { int n=(int)s.get(FPOOL+0x18);Event e=begin(CLEAR,0xabc,node,node+n,0);s.clear(node,n);end(e); }
            }
            fileLock(false);return node;
        }
        void svc(long handle) {
            Event e=begin(SVC,f.svcStatus,handle);
            if(f.fileEffect>=2) s.set(FNODE+4,0x12345678);
            end(e);
        }
        long ownerOpen(boolean external,long type,long data,long bytes) {
            if(bytes>512) return 0xe0e046bfL;
            long service=service(NODE);if(stopped) return 0;
            if(external) {type=s.get(FDESC);data=s.get(FDESC+4);bytes=s.get(FDESC+8);}
            Event e=serviceEvent(true,service,0,s.get(NODE+8),s.get(NODE+12),type,data,bytes,f.flags,0);
            if(f.fileEffect>=1) { s.set(NODE+4,0x11110000);s.set(NODE+8,0x22220000);s.set(NODE+12,0x33330000); }
            end(e);
            long result=serviceResult(true);
            if((result&0x80000000L)!=0) return result;
            long node=fileTake(),handle=recoverServices ? s.get(CMD+12) : f.writeHandle ? f.handle : 0;
            if(node!=0) {s.set(node+4,handle);s.set(node,FVT);}
            if(external) s.set(OUT,node);
            opened=node;
            if(node==0) {svc(handle);return EMPTY;}
            return 0;
        }
        long opened;
        @Override long fileOpen() {
            long k=key(),node=0;
            for(int i=0;i<32;i++) if(s.get(TABLE+16*i)==(k&MASK) && s.get(TABLE+16*i+4)==(k>>>32)) {node=s.get(TABLE+16*i+8);break;}
            if(node==0) return 0xc8804465L;
            require(node==NODE,"Bounded archive receiver");
            long r=ownerOpen(false,4,WPATH+8,6);
            if(!stopped && (r&0x80000000L)==0) s.set(OUT,opened);
            return r;
        }
        long handle() {
            if(s.get(FNODE+4)==0) {
                Event e=begin(DIAG,0x9876,0xe0a046daL,0x239cec);e.terminal=f.terminal;
                if(f.terminal) stopped=true;
                else if(f.fileEffect!=0) s.set(FNODE+4,f.handle);
                end(e);
            }
            return s.get(FNODE+4);
        }
        void fileTeardown() {
            long h=s.get(FNODE+4);
            if(h!=0) {svc(h);s.set(FNODE+4,0);}
        }
        void fileDispose() {
            if(s.get(FNODE+4)!=0) {
                Event e=serviceEvent(false,s.get(FNODE+4),0,0,0,0,0,0,0,0);
                if(f.fileEffect==1) s.set(FNODE+4,0);
                if(f.fileEffect>=2) s.set(FNODE+4,0x24681357);
                if(f.fileEffect==3) s.set(FNODE,FALT_VT);
                end(e);
            }
            if(s.get(FNODE)==FALT_VT) {Event e=begin(FILE_ALT,0x998877,FNODE);s.set(FNODE+4,0xabcdef01L);end(e);}
            else fileTeardown();
            fileLock(true);s.set(FNODE,s.get(FPOOL+0x24));s.set(FPOOL+0x24,FNODE);s.set(FPOOL+0x2c,s.get(FPOOL+0x2c)-1);fileLock(false);
        }
        @Override long call(int kind) {
            switch(kind) {
                case 11:return ownerOpen(true,s.get(FDESC),s.get(FDESC+4),s.get(FDESC+8));
                case 12:return handle();
                case 13:fileTeardown();return FNODE;
                case 14:fileDispose();return -1;
                case 15:if(!f.nullClose) fileDispose();return -1;
                case 16: {
                    Event e=serviceEvent(true,s.get(IPC_HANDLE),f.transaction,f.archiveLow,f.archiveHigh,s.get(FDESC),s.get(FDESC+4),s.get(FDESC+8),f.flags,f.attributes);end(e);
                    if((f.kernelStatus&0x80000000L)==0) s.set(IPC_OUTPUT,s.get(CMD+12));
                    return serviceResult(true);
                }
                case 17: {Event e=serviceEvent(false,s.get(IPC_HANDLE),0,0,0,0,0,0,0,0);end(e);return serviceResult(false);}
                case 18: {
                    Event e=archiveEvent(true,s.get(IPC_HANDLE),f.archive,s.get(FDESC),s.get(FDESC+4),s.get(FDESC+8),0,0);end(e);
                    if((f.archiveKernel&0x80000000L)==0) {s.set(ARCHIVE_OUTPUT,s.get(CMD+8));s.set(ARCHIVE_OUTPUT+4,s.get(CMD+12));}
                    return archiveResult();
                }
                case 19: {Event e=archiveEvent(false,s.get(IPC_HANDLE),0,0,0,0,f.archiveLow,f.archiveHigh);end(e);return archiveResult();}
                default:return super.call(kind);
            }
        }
    }
    class FileMachine extends BackendMachine {
        long archiveData;
        FileMachine(byte[] map,byte[] binary) {super(map,binary);}
        State relocated(State s) {
            if(!recoverArchives || s.get(CMD+20)!=STACK_PATH) return s;
            State result=new State(s);result.set(CMD+20,archiveData);return result;
        }
        @Override void check(State s,String label) {super.check(relocated(s),label);}
        @Override void apply(Event e) {
            Event translated=new Event(e.pc,e.result,relocated(e.before),e.args);
            translated.after=relocated(e.after);super.apply(translated);
        }
        @Override public void beforeStore(PcodeThread<byte[]> t,PcodeOp op,AddressSpace sp,byte[] offset,int size,byte[] value) {
            long a=Utils.bytesToLong(offset,offset.length,false);
            if(recoverServices && (within(a,size,CMD,CMD+40) || within(a,size,IPC_OUTPUT,IPC_OUTPUT+4))) return;
            if(recoverArchives && within(a,size,ARCHIVE_OUTPUT,ARCHIVE_OUTPUT+8)) return;
            if(within(a,size,FPOOL,FPOOL+0x3c) || within(a,size,FNODE,FNODE+8) || within(a,size,FNODE+0x40,FNODE+0x48)) return;
            super.beforeStore(t,op,sp,offset,size,value);
        }
        @Override public void beforeLoad(PcodeThread<byte[]> t,PcodeOp op,AddressSpace sp,byte[] offset,int size) {
            long a=Utils.bytesToLong(offset,offset.length,false);
            if(within(a,size,FALT_VT,FALT_VT+52)) return;
            super.beforeLoad(t,op,sp,offset,size);
        }
        @Override void seed(State s,boolean rebuilt) {
            super.seed(s,rebuilt);writeWord(VT,rebuilt ? entry[11] : ALL_BEGIN[11]);
            writeWord(FVT+0x2c,rebuilt ? entry[14] : ALL_BEGIN[14]);writeWord(FVT+0x30,rebuilt ? entry[13] : ALL_BEGIN[13]);
            memory(FALT_VT,new byte[52]);writeWord(FALT_VT+0x30,FILE_ALT);
        }
        void call(int kind,Oracle oracle,long expected) throws Exception {
            initialize(isRebuilt,0,new byte[0x144]); trace.clear(); FileOracle fo=(FileOracle)oracle;
            register("r0",kind==0 ? POOL : kind==1 || kind==8 ? OUT : kind>=5 ? NAME : NODE);
            register("r1",kind==1 ? oracle.c.archive : kind==8 ? WPATH : NODE); register("r2",kind==8 ? 3 : 0); register("r3",0);
            if(kind>=11) {
                register("r0",kind==11 ? NODE : fo.f.nullClose ? 0 : FNODE);
                register("r1",OUT); register("r2",FDESC); register("r3",fo.f.flags);
            }
            if(kind>=16) {
                register("r0",IPC_HANDLE);register("r1",IPC_OUTPUT);register("r2",fo.f.transaction);register("r3",0xdead1234L);
                if(kind==16) {
                    register("sp",STACK-32);
                    long[] args={fo.f.archiveLow,fo.f.archiveHigh,fo.s.get(FDESC),fo.s.get(FDESC+4),fo.s.get(FDESC+8),fo.f.flags,fo.f.attributes};
                    for(int i=0;i<args.length;i++) writeWord(STACK-32+4*i,args[i]);
                }
            }
            if(kind==18) {
                register("r1",ARCHIVE_OUTPUT);register("r2",fo.f.archive);register("r3",fo.s.get(FDESC));register("sp",STACK-8);
                writeWord(STACK-8,fo.s.get(FDESC+4));writeWord(STACK-4,fo.s.get(FDESC+8));
            } else if(kind==19) {register("r1",0xdead1234L);register("r2",fo.f.archiveLow);register("r3",fo.f.archiveHigh);}
            thread.overrideCounter(toAddr(isRebuilt ? entry[kind] : targetBegin[kind])); executing=true;
            int steps=0,event=0; boolean stopped=false;
            while(thread.getCounter().getOffset()!=RETURN) {
                long actualPC=thread.getCounter().getOffset(),pc=actualPC;
                if(recoverClear && isRebuilt && pc==clearEntry)pc=CLEAR;
                if(recoverServices && (pc==(isRebuilt ? entry[16] : FILE_SERVICE_OPEN) || pc==(isRebuilt ? entry[17] : FILE_SERVICE_CLOSE)))
                    require((register("sp")&7)==0,"IPC public boundary stack alignment");
                if(recoverArchives && (pc==(isRebuilt ? entry[18] : OPEN) || pc==(isRebuilt ? entry[19] : CLOSE))) {
                    require((register("sp")&7)==0,"Archive public stack alignment");
                    if(pc==(isRebuilt ? entry[18] : OPEN) && kind!=18) {
                        long sp=register("sp"),data=get(sp),output=register("r1"),service=register("r0");
                        require(within(service,4,sp,STACK) && within(output,8,sp,STACK) && (output&7)==0,"Archive caller locals");
                        require(within(data,8,sp,STACK) && get(data)==data && get(data+4)==1 && get(sp+4)==1,"Archive self descriptor");
                        archiveData=data;
                    }
                }
                boolean code=within(pc,4,0x100000,0x477000) || within(pc,4,BUILD,BUILD+codeSize);
                if(recoverServices && code && (get(pc)&0xffff0fffL)==0xee1d0f70L) {
                    require(isRebuilt || pc==0x356c40 || pc==0x356d60 || (recoverArchives && (pc==0x2adbf8 || pc==0x2adbbc)),"Named TLS sites");
                    register("r"+((get(pc)>>>12)&15),TLS);tlsReads++;if(!isRebuilt)visited.add(pc);
                    thread.overrideCounter(toAddr(pc+4));continue;
                }
                boolean request=recoverServices && code && get(pc)==0xef000032L;
                if(request) {pc=REQUEST;if(!isRebuilt)visited.add(actualPC);}
                boolean svc=(within(pc,4,0x100000,0x477000) || within(pc,4,BUILD,BUILD+codeSize)) && get(pc)==0xef000023L;
                if(svc) { pc=SVC; if(!isRebuilt) visited.add(actualPC); }
                if((!recoverArchives && (pc==OPEN || pc==CLOSE)) || pc==ACQUIRE || pc==RELEASE || pc==CLEAR || pc==DIAG || (!recoverServices && (pc==FILE_SERVICE_OPEN || pc==FILE_SERVICE_CLOSE)) || pc==REQUEST || pc==SVC || pc==FILE_ALT || pc==ALT) {
                    require(event<oracle.events.size(),"Unexpected boundary "+Long.toHexString(pc)); Event e=oracle.events.get(event++);
                    require(pc==e.pc,"Boundary order"); check(e.before,"Before "+Long.toHexString(pc));
                    // SVC is an instruction, not an AAPCS public call. GCC's
                    // leaf teardown may retain only word alignment at this site.
                    require((register("sp")&(svc || request ? 3 : 7))==0,"Boundary stack alignment");
                    long r0=register("r0"),r1=register("r1"),r2=register("r2"),r3=register("r3"),sp=register("sp");
                    if(pc==OPEN) {
                        require(get(r0)==e.args[0] && r2==e.args[1] && r3==1,"Archive open values");
                        require(within(r0,4,sp,STACK) && within(r1,8,sp,STACK) && (r1&7)==0,"Open locals");
                        long data=get(sp); require(get(sp+4)==1 && within(data,8,sp,STACK) && get(data)==data && get(data+4)==1,"Self-referential type-1 descriptor");
                        if((e.result&0x80000000L)==0 || (e.result&1)!=0) { writeWord(r1,oracle.c.low); writeWord(r1+4,oracle.c.high); }
                        openCalls++;
                    } else if(pc==CLOSE) {
                        require(within(r0,4,sp,STACK) && get(r0)==e.args[0] && r2==e.args[1] && r3==e.args[2],"Archive close captured values"); closeCalls++;
                    } else if(pc==FILE_SERVICE_OPEN) {
                        require(within(r0,4,sp,STACK) && within(r1,4,sp,STACK),"File open locals");
                        require(get(r0)==e.args[0] && r2==0,"File service/transaction");
                        for(int i=0;i<7;i++) require(get(sp+4*i)==e.args[i+1],"File stack argument "+i);
                        require(get(r1)==0,"File handle initialized");
                        if(fo.f.writeHandle) writeWord(r1,fo.f.handle);
                        fileOpens++;
                    } else if(pc==FILE_SERVICE_CLOSE) {
                        require(within(r0,4,sp,STACK) && get(r0)==e.args[0],"File close local handle");
                        writeWord(r0,0xf0f0f0f0L); fileCloses++;
                    } else if(pc==REQUEST) {
                        require(r0==e.args[0],"IPC request handle");requests++;
                        if(e.args[1]==1)fileOpens++;else if(e.args[1]==0)fileCloses++;else if(e.args[1]==2)openCalls++;else closeCalls++;
                    } else if(pc==SVC) {
                        require(r0==e.args[0],"SVC close handle"); svcCalls++;
                    } else if(pc==FILE_ALT) {
                        require(r0==FNODE,"Alternate file teardown receiver"); fileAlts++;
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
                    apply(e); trace.add(Long.toHexString(pc)+":"+Arrays.toString(e.args));
                    if(e.terminal) { stopped=true; terminals++; break; }
                    externalReturn(e.result); if(svc || request) thread.overrideCounter(toAddr(actualPC+4)); continue;
                }
                boolean valid=isRebuilt && within(pc,4,BUILD,BUILD+codeSize);
                if(!isRebuilt) for(int i=0;i<targetBegin.length;i++) valid|=within(pc,i==10 ? 2 : 4,targetBegin[i],targetLimit[i]);
                require(valid,"Lifetime PC "+Long.toHexString(pc)); if(!isRebuilt) visited.add(pc);
                require(++steps<6000,"Lifetime instruction budget"); monitor.checkCancelled(); thread.stepInstruction();
            }
            require(event==oracle.events.size() && stopped==oracle.stopped,"Missing boundary/terminal");
            check(oracle.s,"Final");
            if(!stopped) {
                if(kind!=4 && kind!=14 && kind!=15) require(register("r0")==expected,"Result expected="+Long.toHexString(expected)+" actual="+Long.toHexString(register("r0")));
                if(kind==16) {
                    require(register("sp")==STACK-32,"IPC caller stack restoration");
                    long[] args={fo.f.archiveLow,fo.f.archiveHigh,fo.s.get(FDESC),fo.s.get(FDESC+4),fo.s.get(FDESC+8),fo.f.flags,fo.f.attributes,0x96969696L};
                    for(int i=0;i<args.length;i++)require(get(STACK-32+4*i)==args[i],"IPC caller argument preservation");
                    register("sp",STACK);
                }
                if(kind==18) {
                    require(register("sp")==STACK-8 && get(STACK-8)==fo.s.get(FDESC+4) && get(STACK-4)==fo.s.get(FDESC+8),"Archive caller stack preserved");register("sp",STACK);
                }
                finish(steps);
            }
            for(byte b:memory(STACK-0x1000,0xd00)) require(b==(byte)0x96,"Stack guard");
            executing=false;
        }
    }
    State pair(FileMachine a,FileMachine b,State state,FileConfig c,int kind,boolean seed,PrintWriter log) throws Exception {
        try {
            FileOracle oracle=new FileOracle(state,c);long expected=oracle.call(kind);
            if(seed) {a.seed(state,false);b.seed(state,true);}
            a.call(kind,oracle,expected);b.call(kind,oracle,expected);
            require(a.trace.equals(b.trace),"Boundary agreement");
            log.printf("%d\t%d\t%d\t%x\t%d\t%d%n",cases++,kind,c.fileEffect,expected,oracle.events.size(),oracle.stopped ? 1 : 0);fileKinds[kind]++;
            return oracle.s;
        } catch(Exception e) {throw new IllegalStateException("File owner case "+cases+" kind="+kind+" effect="+c.fileEffect,e);}
    }
    @Override public void run() throws Exception {
        Path out=Path.of(getScriptArgs()[0]);require(!Files.exists(out.resolve("comparison.json")),"Existing output");
        loadClear(out);
        recoverArchives=getScriptArgs().length>1 && getScriptArgs()[1].equals("archives");
        recoverServices=recoverArchives || (getScriptArgs().length>1 && getScriptArgs()[1].equals("services"));
        if(recoverServices) {
            targetBegin=Arrays.copyOf(ALL_BEGIN,18);targetLimit=Arrays.copyOf(ALL_LIMIT,18);fileKinds=new int[18];
            targetBegin[16]=FILE_SERVICE_OPEN;targetLimit[16]=0x356c98;targetBegin[17]=FILE_SERVICE_CLOSE;targetLimit[17]=0x356d84;
        }
        if(recoverArchives) {
            targetBegin=Arrays.copyOf(targetBegin,20);targetLimit=Arrays.copyOf(targetLimit,20);fileKinds=new int[20];
            targetBegin[18]=OPEN;targetLimit[18]=0x2adc44;targetBegin[19]=CLOSE;targetLimit[19]=0x2adbe4;
        }
        byte[] map=new byte[0x377000];require(currentProgram.getMemory().getBytes(toAddr(0x100000),map)==map.length,"Map");
        require(HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(map)).equals("834938d18d2b7c688311c46c27bed813d0d7a9f8e3cbb61da8a6a3f23d360ebd"),"Hash");
        require(word(map,(int)(VT-0x100000))==ALL_BEGIN[11] && word(map,(int)(FVT-0x100000+0x2c))==ALL_BEGIN[14] && word(map,(int)(FVT-0x100000+0x30))==ALL_BEGIN[13],"Original file vtable linkage");
        byte[] binary=Files.readAllBytes(out.resolve("resource-worker-file-owner.bin"));codeSize=binary.length;
        var lines=Files.readAllLines(out.resolve("entries.txt"));require(lines.size()==targetBegin.length,"Entries");entry=new long[targetBegin.length];
        for(int i=0;i<entry.length;i++) entry[i]=Long.parseLong(lines.get(i));
        StringBuilder boundaries=new StringBuilder();
        for(int i=11;i<targetBegin.length;i++) {var f=getFunctionAt(toAddr(targetBegin[i]));require(f!=null,"Saved file function");
            require(f.getBody().getMinAddress().getOffset()==targetBegin[i] && f.getBody().getMaxAddress().getOffset()==targetLimit[i]-1,"Saved extent");
            boundaries.append(Long.toHexString(targetBegin[i])+" "+f.getBody()+"\n");}
        Files.writeString(out.resolve("function-boundaries.txt"),boundaries);
        FileMachine a=new FileMachine(map,binary),b=new FileMachine(map,binary);
        try(PrintWriter log=new PrintWriter(Files.newBufferedWriter(out.resolve("results.tsv")))) {
            log.println("case\tkind\teffect\tresult\tboundaries\tterminal");
            if(recoverServices) {
                for(long kernel:new long[]{0,1,0x7fffffffL,0x80000000L,MASK})
                for(long status:new long[]{0,1,0x7fffffffL,0x80000000L,MASK})
                for(boolean response:new boolean[]{false,true}) {
                    FileConfig c=new FileConfig();c.kernelStatus=kernel;c.fileStatus=status;c.closeStatus=status;c.response=response;c.handle=status;
                    for(int kind=16;kind<=17;kind++) pair(a,b,initial(),c,kind,true,log);
                }
                // Descriptor arithmetic wraps in u32. r3 is poisoned padding;
                // full-width transaction/archive/type/flags/attributes are distinct.
                for(long bytes:new long[]{0,1,511,512,513,0x3ffff,0x40000,0x40001,0x7fffffffL,0x80000000L,MASK}) {
                    State s=initial();s.set(FDESC+8,bytes);s.set(FDESC,bytes);s.set(FDESC+4,(bytes&1)==0 ? 0 : MASK);s.set(IPC_HANDLE,bytes);
                    FileConfig c=new FileConfig();c.flags=bytes;c.attributes=~bytes&MASK;c.transaction=bytes;c.archiveLow=bytes;c.archiveHigh=~bytes&MASK;
                    pair(a,b,s,c,16,true,log);
                }
                // Kernel failure through both public open layers, including
                // untouched and overwritten response memory, and concrete close.
                for(boolean response:new boolean[]{false,true}) for(long kernel:new long[]{0x80000000L,MASK}) {
                    State s=initial();s.object(1,2,3);s.set(TABLE,0x726f6d);s.set(TABLE+8,NODE);s.set(FNODE,FVT);s.set(FNODE+4,0x76543210);
                    FileConfig c=new FileConfig();c.kernelStatus=kernel;c.response=response;
                    for(int kind:new int[]{11,8,15}) pair(a,b,s,c,kind,true,log);
                }
            }
            if(recoverArchives) {
                // Independent kernel/service signs, untouched responses, full 64-bit publication.
                for(long kernel:new long[]{0,1,0x7fffffffL,0x80000000L,MASK})
                for(long status:new long[]{0,1,0x7fffffffL,0x80000000L,MASK})
                for(boolean response:new boolean[]{false,true}) {
                    FileConfig c=new FileConfig();c.archiveKernel=kernel;c.status=status;c.closeStatus=status;c.archiveResponse=response;
                    c.low=status;c.high=~status&MASK;
                    for(int kind=18;kind<=19;kind++) pair(a,b,initial(),c,kind,true,log);
                }
                for(long bytes:new long[]{0,1,511,512,513,0x3ffff,0x40000,0x40001,0x7fffffffL,0x80000000L,MASK}) {
                    State s=initial();s.set(FDESC+8,bytes);s.set(FDESC,~bytes&MASK);s.set(FDESC+4,(bytes&1)==0 ? 0 : MASK);s.set(IPC_HANDLE,bytes);
                    FileConfig c=new FileConfig();c.archive=bytes;c.low=bytes;c.high=~bytes&MASK;
                    pair(a,b,s,c,18,true,log);
                    c.archiveLow=bytes;c.archiveHigh=~bytes&MASK;pair(a,b,s,c,19,true,log);
                }
                // Factory caller captures response before lock effects and closes on exhaustion.
                for(long kernel:new long[]{0,1,0x80000000L,MASK}) for(long status:new long[]{0,1,0x80000000L,MASK})
                for(int empty=0;empty<2;empty++) for(int effect=0;effect<4;effect++) {
                    State s=initial();if(empty==1)s.set(POOL+0x24,0);
                    FileConfig c=new FileConfig();c.archiveKernel=kernel;c.status=status;c.effect=effect;c.archive=MASK;
                    c.closeStatus=new long[]{0,1,0x80000000L,MASK}[effect];
                    pair(a,b,s,c,1,true,log);
                }
                // Registration rollback and handle-zero disposal behavior.
                for(int failure=0;failure<2;failure++) for(long handle:new long[]{0,1,0x8000000000000000L,-1L}) {
                    State s=initial();
                    if(failure==0) {s.set(TABLE,0x726f6d);s.set(TABLE+8,NODE+0x40);}
                    else for(int i=0;i<32;i++) {s.set(TABLE+16*i,i+1);s.set(TABLE+16*i+8,NODE+0x40);}
                    FileConfig c=new FileConfig();c.low=handle&MASK;c.high=handle>>>32;
                    pair(a,b,s,c,5,true,log);
                }
                // Teardown keeps the pre-diagnostic handle; close failures still clear it.
                for(int effect=0;effect<4;effect++) for(boolean terminal:new boolean[]{false,true}) {
                    State s=initial();s.object(0x12345678,0x87654321L,0);
                    FileConfig c=new FileConfig();c.effect=effect;c.terminal=terminal;c.archiveKernel=0x80000000L;
                    pair(a,b,s,c,3,true,log);
                }
            }
            // Unsigned descriptor bound, service sign boundary, allocation failure.
            for(long bytes:new long[]{0,1,511,512,513,MASK}) for(long status:new long[]{0,1,0x7fffffffL,0x80000000L,MASK}) for(int empty=0;empty<2;empty++) {
                State s=initial();s.object(0x12345678,0xfedcba98L,0x87654321L);s.set(FDESC+8,bytes);
                if(empty==1) s.set(FPOOL+0x24,0);
                FileConfig c=new FileConfig();c.fileStatus=status;c.handle=bytes==0 ? 0 : 0x80000000L;c.flags=bytes==1 ? MASK : 3;
                c.fileEffect=empty;c.writeHandle=(status&1)==0;
                pair(a,b,s,c,11,true,log);
            }
            // Pool accounting, selective clear, unsigned wrap, callback edits.
            for(long flags:new long[]{0,1,2,MASK}) for(long count:new long[]{0,1,0x7fffffffL,MASK}) for(int effect:new int[]{0,2,4}) {
                State s=initial();s.object(0,0,1);s.set(FPOOL+0x14,flags);s.set(FPOOL+0x2c,count);
                FileConfig c=new FileConfig();c.fileEffect=effect;c.handle=MASK;c.flags=0;
                pair(a,b,s,c,11,true,log);
            }
            // Checked archive accessor: terminal and conditional returning paths.
            for(boolean terminal:new boolean[]{false,true}) for(int effect:new int[]{0,1,3}) {
                State s=initial();s.object(1,2,0);FileConfig c=new FileConfig();c.terminal=terminal;c.effect=effect;
                pair(a,b,s,c,11,true,log);
            }
            State changed=initial();changed.object(1,2,0);FileConfig changing=new FileConfig();changing.effect=1;changing.fileEffect=5;
            pair(a,b,changed,changing,11,true,log);
            for(long type:new long[]{0,1,2,4,MASK}) {
                State s=initial();s.object(1,2,3);s.set(FDESC,type);s.set(FDESC+4,type==0 ? 0 : WPATH);
                FileConfig c=new FileConfig();c.flags=type;c.handle=type;
                pair(a,b,s,c,11,true,log);
            }
            for(long handle:new long[]{0,1,0x80000000L,MASK}) for(int effect:new int[]{0,1,2,3,4}) {
                for(int kind=12;kind<=15;kind++) {
                    State s=initial();s.set(FNODE,FVT);s.set(FNODE+4,handle);s.set(FPOOL+0x24,FNODE+0x40);s.set(FPOOL+0x2c,effect==0 ? 0 : effect==1 ? MASK : 1);
                    FileConfig c=new FileConfig();c.fileEffect=effect;c.closeStatus=new long[]{0,1,0x7fffffffL,0x80000000L,MASK}[effect];c.svcStatus=c.closeStatus;
                    pair(a,b,s,c,kind,true,log);
                }
            }
            State s=initial();s.set(FNODE,FVT);s.set(FNODE+4,0);FileConfig c=new FileConfig();c.terminal=true;
            pair(a,b,s,c,12,true,log);
            c=new FileConfig();c.nullClose=true;pair(a,b,initial(),c,15,true,log);
            // Alternate teardown also runs when the initial handle is zero.
            s=initial();s.set(FNODE,FALT_VT);s.set(FNODE+4,0);s.set(FPOOL+0x24,0);s.set(FPOOL+0x2c,1);
            pair(a,b,s,new FileConfig(),14,true,log);
            // Same emulator storage across archive and file creation, failures,
            // close, pool reuse, prefix removal and archive reuse.
            for(int flags=0;flags<2;flags++) {
                s=initial();s.set(FNODE,0);s.set(POOL+0x14,flags);s.set(FPOOL+0x14,flags);c=new FileConfig();
                if(recoverArchives) s.set(NODE,0);
                a.seed(s,false);b.seed(s,true);
                for(int round=0;round<3;round++) {
                    if(recoverArchives) {
                        c.archiveKernel=0x80000000L;s=pair(a,b,s,c,5,false,log);c.archiveKernel=0;
                        c.status=0x80000001L;s=pair(a,b,s,c,5,false,log);c.status=0;
                        require(s.get(STATE+8)==0 && s.get(POOL+0x24)==NODE,"Failed archive open preserves ownership");
                    }
                    s=pair(a,b,s,c,5,false,log);
                    if(recoverArchives) {
                        s=pair(a,b,s,c,1,false,log);
                        require(s.get(OUT)==0 && s.get(STATE+8)==NODE && s.get(POOL+0x2c)==1,"Archive exhaustion closes new handle and retains owner");
                    }
                    s=pair(a,b,s,c,8,false,log);require(s.get(OUT)==FNODE,"Opened concrete file");
                    s=pair(a,b,s,c,8,false,log);require(s.get(OUT)==FNODE,"Outer output preserved on pool exhaustion");
                    c.fileStatus=0x80000001L;s=pair(a,b,s,c,8,false,log);c.fileStatus=0;
                    if(recoverServices) {
                        c.kernelStatus=0x80000000L;s=pair(a,b,s,c,8,false,log);c.kernelStatus=0;
                        require(s.get(OUT)==FNODE,"Outer output preserved on kernel failure");
                    }
                    s=pair(a,b,s,c,15,false,log);
                    s=pair(a,b,s,c,8,false,log);require(s.get(OUT)==FNODE,"Reused same file object");
                    s=pair(a,b,s,c,15,false,log);
                    s=pair(a,b,s,c,7,false,log);
                    s=pair(a,b,s,c,8,false,log);
                    require(s.get(FPOOL+0x24)==FNODE && s.get(FPOOL+0x2c)==0 && s.get(POOL+0x24)==NODE && s.get(POOL+0x2c)==0 && s.get(STATE+8)==0,"Both owners returned");
                }
                sequences++;
            }
        }
        int count=0,seen=0;StringBuilder listing=new StringBuilder();
        for(int i=11;i<15;i++) for(long pc=ALL_BEGIN[i];pc<ALL_LIMIT[i];pc+=4) {
            var ins=currentProgram.getListing().getInstructionAt(toAddr(pc));require(ins!=null,"Instruction");count++;if(visited.contains(pc))seen++;
            listing.append(String.format("%08x %s %s visited=%s%n",pc,HexFormat.of().formatHex(ins.getBytes()),ins,visited.contains(pc)));
        }
        require(seen==count,"Unvisited file ownership instructions");Files.writeString(out.resolve("original-ghidra.txt"),listing);
        if(recoverServices) {
            int serviceCount=0;StringBuilder serviceListing=new StringBuilder();
            for(int i=16;i<targetBegin.length;i++)for(long pc=targetBegin[i];pc<targetLimit[i];pc+=4) {
                var ins=currentProgram.getListing().getInstructionAt(toAddr(pc));require(ins!=null && visited.contains(pc),"Unvisited service site");serviceCount++;
                serviceListing.append(String.format("%08x %s %s%n",pc,HexFormat.of().formatHex(ins.getBytes()),ins));
            }
            require(tlsReads==requests && fileOpens+fileCloses+(recoverArchives ? openCalls+closeCalls : 0)==requests,"Every service uses TLS and kernel boundary");
            Files.writeString(out.resolve("service-original-ghidra.txt"),serviceListing);
            Files.writeString(out.resolve("services.json"),String.format(Locale.ROOT,"{\"recovered_contracts\":%d,\"original_instruction_sites\":%d,\"tls_reads_both\":%d,\"svc_requests_both\":%d,\"service_call_models_removed\":true,\"tls_svc_modeled\":true}\n",recoverArchives ? 4 : 2,serviceCount,tlsReads,requests));
        }
        if(recoverArchives) Files.writeString(out.resolve("archive-services.json"),String.format(Locale.ROOT,"{\"recovered_contracts\":2,\"original_instruction_sites\":34,\"archive_open_requests_both\":%d,\"archive_close_requests_both\":%d,\"archive_call_models_removed\":true,\"tls_svc_modeled\":true,\"stack_descriptor_addresses_relocated\":true}\n",openCalls,closeCalls));
        Files.writeString(out.resolve("comparison.json"),String.format(Locale.ROOT,"{\"cases\":%d,\"cases_by_kind\":%s,\"persistent_sequences\":%d,\"new_instruction_addresses\":%d,\"visited_new_instructions\":%d,\"file_open_calls_both\":%d,\"file_close_calls_both\":%d,\"svc_close_calls_both\":%d,\"alternate_teardown_calls_both\":%d,\"terminal_diagnostics_both\":%d,\"returning_diagnostics_both\":%d,\"max_steps\":%d,\"services_svc_locks_clear_diagnostics_modeled\":true,\"pool_registry_startup_synthetic\":true,\"live_verified\":false}\n",cases,Arrays.toString(fileKinds),sequences,count,seen,fileOpens,fileCloses,svcCalls,fileAlts,terminals,returningDiagnostics,maxSteps));
        saveClear(out);
        println("SMT4_FILE_OWNER_COMPARE_OK");
    }
}
