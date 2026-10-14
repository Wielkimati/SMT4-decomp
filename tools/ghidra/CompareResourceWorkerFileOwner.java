// Concrete file ownership; reuse archive/prefix oracle and guarded emulator.
// @category SMT4
import ghidra.pcode.emu.PcodeThread;
import ghidra.program.model.listing.Instruction;
import ghidra.pcode.exec.PcodeExecutorStatePiece.Reason;
import ghidra.pcode.utils.Utils;
import ghidra.pcode.exec.*;
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
    boolean recoverServices,recoverArchives,recoverDescriptor,recoverInitialize,recoverStartup,recoverAcquisition,recoverSetup,recoverDiagnostic,recoverDiagnosticWait;
    static final long START=0x44e640, PUBLISHED=0x471a68, SERVICE_NAME=0x407fb3, SETUP=0x2c15c4, LENGTH=0x2c32e4, GET_SERVICE=0x2c1590;
    static final long MANAGER=0x471b90, MANAGER_HANDLE=0x471ba4;
    static final long MANAGER_LOCK=0x4e9ba8, MANAGER_NAME=0x40b6e4, CONNECT_SVC=0x78001c, SLEEP=0x1382e4;
    static final long DRECORD=0x4d4200,DLOCK=0x4d4280,DHANDLE=0x44e608,DCONST=0x407f9c,DNAME=0x4259a0;
    static final long PROCESS_SVC=0x780020,WAIT_INIT=0x2c5470,WAIT=0x2c367c,COPY_DATA=0x91c000;
    int diagnosticRequests,processCalls,diagnosticWaits,diagnosticSleeps,diagnosticPrefetchHints;
    int[] diagnosticWaitsByKind=new int[41];
    static final long WAIT_DATA=0x91d020,ARB_HANDLE=0x471b58,WAIT_ARB=0x780024;
    int waitExclusiveAttempts,waitClears,waitArbitrations,waitPending;
    record WaitAction(String kind,int offset,long before,long value,long extra) {}

    int connectCalls,registerRequests,sleepCalls,setupSequences;
    int byteAt(State s,long a){var e=s.blocks.floorEntry(a);return e.getValue()[(int)(a-e.getKey())]&255;}
    void byteSet(State s,long a,int v){var e=s.blocks.floorEntry(a);e.getValue()[(int)(a-e.getKey())]=(byte)v;}
    void copyBatch(State s,long dest,long source,int bytes){
        int[] data=new int[bytes];for(int i=0;i<bytes;i++)data[i]=byteAt(s,source+i);
        for(int i=0;i<bytes;i++)byteSet(s,dest+i,data[i]);
    }
    long copyOracle(State s,long dest,long source,int bytes){
        int offset=0;
        while(bytes-offset>=32){copyBatch(s,dest+offset,source+offset,32);offset+=32;}
        for(int block:new int[]{16,8,4})if(bytes-offset>=block){copyBatch(s,dest+offset,source+offset,block);offset+=block;}
        copyBatch(s,dest+offset,source+offset,bytes-offset);return dest+bytes;
    }
    int acquisitionRequests,uqsub8Instructions;
    static long unsignedSaturatingSubtractBytes(long left,long right){
        long result=0;
        for(int shift=0;shift<32;shift+=8)
            result|=(long)Math.max(0,((int)(left>>>shift)&255)-((int)(right>>>shift)&255))<<shift;
        return result;
    }
    int startupRequests,startupSequences;
    int initializeRequests;
    int descriptorSequences;
    static final long REGISTER_PATH=0x91b040;
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
        if(recoverStartup){s.add(PUBLISHED-16,36,0x95);s.set(START+4,0);}
        if(recoverAcquisition){
            s.add(MANAGER-16,56,0x97);s.set(MANAGER,1);s.set(MANAGER_HANDLE,0x24681357);
            s.add(SERVICE_NAME-3,16,0x98);
            System.arraycopy(new byte[]{'f','s',':','U','S','E','R',0},0,s.blocks.get(SERVICE_NAME-3),3,8);
        }
        if(recoverSetup){
            s.add(MANAGER_LOCK-16,44,0x99);s.add(MANAGER_NAME,8,0);
            System.arraycopy(new byte[]{'s','r','v',':',0},0,s.blocks.get(MANAGER_NAME),0,5);
        }
        if(recoverDiagnostic){
            s.add(DRECORD-16,176,0x9a);s.add(DHANDLE-16,36,0x9b);s.set(DHANDLE,0);
            s.add(DCONST,12,0);s.set(DCONST,0xffff8001L);s.set(DCONST+4,0);s.set(DCONST+8,DNAME);
            s.add(COPY_DATA,768,0);for(int i=0;i<768;i++)byteSet(s,COPY_DATA+i,(i*37+11)&255);
        }
        if(recoverDiagnosticWait){s.add(WAIT_DATA-16,40,0xa6);s.add(ARB_HANDLE-16,36,0xa7);s.set(ARB_HANDLE,0x24681357);}
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
        long initializeValue=0xfedcba98L,initializeService=0x87654321L;
        long acquireKernel,namePointer=NAME,nameBytes=7,nameFlags=0,copyOutput=FDESC;
        long[] connectStatuses={0},connectHandles={0x13572468L};
        long registerKernel,registerStatus,registerCount=-1,unlockCount=-1,sleepCount=-1;
        boolean registerResponse=true;
        long connectName=NAME;
        long[] diagStatuses={0},diagHandles={0x12344321};
        long processStatus,processValue=0xfeed9876L,processArg=0xffff8001L;
        long diagKernel,diagStatus=0xabcdef12L,diagResult=0xfedcba98L,diagSite=0x12345678;
        long processHandle=-1,requestHandle=-1,lockHandle=-1,unlockHandle=-1,releaseType=-1;
        boolean diagResponse=true,waitTerminal;
        long waitResult=0xabcdef01L,waitFirst=0xfffffffeL,waitSecond=1;
        long waitMode=1,waitPayload=0x12345678L;
        int baseFails,stateFails,pendingExclusive,terminalArbitration=1;
        long[] exclusiveValues={},arbStates={1},arbHandles={0x89abcdefL};
        long copyIn=COPY_DATA+64,copyOut=COPY_DATA+384;int copyBytes=128;
        long setupCount=-1;
        long setupStatus,acquireStatus,acquired=0x12345678L,diagnosticValue=0xabcdef01L;
        long stateKernel,stateStatus,publication=START+8;
        boolean acquireWrite=true,stateResponse=true,diagnosticWrite;
        long terminalSite,initializeEffect=-1;
        long descriptor=FDESC,selector=0,identifier=0xf000000bL,descriptorHigh;
    }
    class FileOracle extends Oracle {
        FileConfig f;
        List<WaitAction> waitActions=new ArrayList<>();
        boolean waitDirect;long w0,w1,expectedWaitPayload;
        void waitValue(int offset,long value){if(offset==0)w0=value;else w1=value;if(waitDirect)s.set(WAIT_DATA+offset,value);}
        long waitValue(int offset){return offset==0?w0:w1;}
        void wa(String kind,int offset,long before,long value,long extra){waitActions.add(new WaitAction(kind,offset,before,value,extra));}
        long exchange(int offset,long value,int failures,boolean pending){
            long observed=0;
            for(int i=0;i<=failures;i++){
                if(pending && i==failures){wa("pending",offset,0,0,0);stopped=true;return 0;}
                observed=waitValue(offset);
                long loaded=offset==0 && i<f.exclusiveValues.length ? f.exclusiveValues[i] : observed;
                wa("load",offset,observed,loaded,0);waitValue(offset,loaded);observed=loaded;
                wa("store",offset,loaded,value,i==failures?1:0);
                if(i==failures)waitValue(offset,value);
            }
            return observed;
        }
        long waitInitialize(long mode){
            exchange(4,1,f.baseFails,f.pendingExclusive==1);if(stopped)return 0;
            return exchange(0,mode==0?MASK:MASK-1,f.stateFails,f.pendingExclusive==2);
        }
        long waitRun(long result){
            int arb=0,ex=0;expectedWaitPayload=f.waitPayload;
            for(int iteration=0;iteration<12;iteration++){
                long value=w0;wa("read",0,value,value,0);
                if(value==1)return 1;
                if(value==0){
                    for(int i=0;;i++){
                        if(f.pendingExclusive==2 && i==f.stateFails){wa("pending",0,0,0,0);stopped=true;return 0;}
                        long old=w0,loaded=ex<f.exclusiveValues.length?f.exclusiveValues[ex++]:w0;
                        wa("load",0,old,loaded,0);waitValue(0,loaded);
                        if(loaded!=0){wa("clear",0,loaded,loaded,0);break;}
                        boolean success=i>=f.stateFails;wa("store",0,loaded,MASK,success?1:0);
                        if(success){waitValue(0,MASK);expectedWaitPayload=0;return 0;}
                    }
                }
                wa("handle",0,s.get(ARB_HANDLE),s.get(ARB_HANDLE),0);
                long next=arb<f.arbStates.length?f.arbStates[arb]:1;
                Event e=begin(WAIT_ARB,result,s.get(ARB_HANDLE),w0,w1,next);
                waitValue(0,next);expectedWaitPayload=(f.waitPayload ^ result ^ (arb+1)) & MASK;
                if(arb<f.arbHandles.length)s.set(ARB_HANDLE,f.arbHandles[arb]);arb++;
                e.terminal=f.waitTerminal && arb>=f.terminalArbitration;if(e.terminal)stopped=true;end(e);
                if(stopped || value==MASK-1)return result;
            }
            throw new IllegalStateException("Wait oracle finite schedule exhausted");
        }
        FileOracle(State s,FileConfig c) { super(s,c);f=c; }
        @Override Event begin(long pc,long result,long... args){
            if(!recoverDiagnostic || pc!=DIAG)return super.begin(pc,result,args);
            record(args[0],args[1]);deliver(DRECORD,result);
            Event e=events.get(events.size()-1);require(e.pc==(recoverDiagnosticWait?WAIT_ARB:WAIT),"Wrapper enters lower wait");return e;
        }
        void record(long result,long site){
            byteSet(s,DRECORD+1,0);byteSet(s,DRECORD+2,0xa3);byteSet(s,DRECORD+3,0xbc);
            byteSet(s,DRECORD,0);s.set(DRECORD+8,site);s.set(DRECORD+4,result);
        }
        long process(long output,long handle){
            Event e=begin(PROCESS_SVC,f.processStatus,output,handle,f.processValue);
            if(f.processHandle>=0)s.set(DHANDLE,f.processHandle);end(e);
            s.set(output,f.processValue);return f.processStatus;
        }
        long diagnosticRequest(long handle,long record){
            s.set(CMD,0x00010800);copyBatch(s,CMD+4,record,128);
            Event e=begin(REQUEST,f.diagKernel,handle,8);
            if(f.diagResponse){s.set(CMD+4,f.diagStatus);s.set(CMD+128,0x88776655);}
            if(f.requestHandle>=0)s.set(DHANDLE,f.requestHandle);end(e);
            return (f.diagKernel&0x80000000L)!=0 ? f.diagKernel : s.get(CMD+4);
        }
        long deliver(long record,long waitResult){
            int attempt=0;
            for(;;){
                Event e=begin(ACQUIRE,0xabcd1234,DLOCK);if(f.lockHandle>=0)s.set(DHANDLE,f.lockHandle);end(e);
                long status=0;
                if(s.get(DHANDLE)==0){
                    require(attempt<f.diagStatuses.length,"Finite diagnostic connect script exhausted");
                    status=f.diagStatuses[attempt];long h=f.diagHandles[attempt++];
                    e=begin(CONNECT_SVC,status,DHANDLE,DNAME,h);end(e);s.set(DHANDLE,h);
                }
                if((status&0x80000000L)==0){
                    process(record+12,s.get(DCONST));diagnosticRequest(s.get(DHANDLE),record);
                    long h=s.get(DHANDLE);
                    if(h!=0){e=begin(SVC,f.svcStatus,h);s.set(DHANDLE,0x77778888);end(e);s.set(DHANDLE,s.get(DCONST+4));}
                }else if(status==0xd0401834L && byteAt(s,record)==2){
                    e=begin(SLEEP,0x556677,5000000,0);end(e);
                    e=begin(RELEASE,0x12344321,DLOCK);
                    if(f.unlockHandle>=0)s.set(DHANDLE,f.unlockHandle);
                    if(f.releaseType>=0)byteSet(s,record,(int)f.releaseType);end(e);continue;
                }
                e=begin(RELEASE,0x12344321,DLOCK);
                if(f.unlockHandle>=0)s.set(DHANDLE,f.unlockHandle);
                if(f.releaseType>=0)byteSet(s,record,(int)f.releaseType);end(e);
                int type=byteAt(s,record);if(type==2 || type==5)return type;
                if(recoverDiagnosticWait){
                    waitDirect=false;w0=w1=0;waitInitialize(1);
                    return waitRun(waitResult);
                }
                e=begin(WAIT_INIT,0x87654321,1,f.waitFirst,f.waitSecond);end(e);
                e=begin(WAIT,waitResult,f.waitFirst,f.waitSecond);e.terminal=f.waitTerminal;
                if(e.terminal)stopped=true;end(e);return waitResult;
            }
        }
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
        long descriptorCreate(boolean publish,long descriptor) {
            Event e=archiveEvent(true,s.get(STATE+16),7,2,descriptor,12,0,0);
            if(c.effect>=1)s.set(STATE+16,0x22334455);end(e);
            long result=archiveResult();if((result&0x80000000L)!=0)return result;
            long low=s.get(CMD+8),high=s.get(CMD+12),service=s.get(STATE+16),node=take();
            if(node!=0){s.set(node,VT);s.set(node+4,service);s.set(node+8,low);s.set(node+12,high);}
            if(publish)s.set(OUT,node);created=node;
            if(node==0){close(s.get(STATE+16),low,high);return EMPTY;}return 0;
        }
        long startupDiagnostic(long result,long site,boolean negative) {
            Event e=negative ? begin(DIAG,f.diagnosticValue,result,site,1) : begin(DIAG,f.diagnosticValue,result,site);
            e.terminal=f.terminalSite==site;
            if(e.terminal)stopped=true;
            else if(f.diagnosticWrite)s.set(START+4,f.acquired ^ 0x55555555L);
            end(e);return f.diagnosticValue;
        }
        long startupGet() {
            if(s.get(START+4)==0)startupDiagnostic(0xe0a046dbL,0x2bbd58,false);
            return s.get(START+4);
        }
        long stateRequest(long service,long value) {
            s.set(CMD,0x08620040);s.set(CMD+4,value);
            Event e=begin(REQUEST,f.stateKernel,service,5);
            if(f.stateResponse){s.set(CMD+4,f.stateStatus);s.set(CMD+60,0x99887766L);}end(e);
            return (f.stateKernel&0x80000000L)!=0 ? f.stateKernel : s.get(CMD+4);
        }
        long acquire(long output,long name,long length,long flags) {
            if((int)s.get(MANAGER)<=0)return 0xd8a067f8L;
            if((int)length>8)return 0xd9006405L;
            long low=s.get(name),high=s.get(name+4);
            s.set(CMD,0x00050100);s.set(CMD+4,low);s.set(CMD+8,high);
            s.set(CMD+12,length);s.set(CMD+16,flags);
            Event e=begin(REQUEST,f.acquireKernel,s.get(MANAGER_HANDLE),6);
            if(f.acquireWrite){s.set(CMD+4,f.acquireStatus);s.set(CMD+12,f.acquired);s.set(CMD+60,0xabcdef98L);}end(e);
            if((f.acquireKernel&0x80000000L)!=0)return f.acquireKernel;
            s.set(output,s.get(CMD+12));return s.get(CMD+4);
        }
        long managerRegister() {
            s.set(CMD,0x00010002);s.set(CMD+4,0x20);
            Event e=begin(REQUEST,f.registerKernel,s.get(MANAGER_HANDLE),7);
            if(f.registerResponse){s.set(CMD+4,f.registerStatus);s.set(CMD+60,0x55667788);}
            if(f.registerCount>=0)s.set(MANAGER,f.registerCount);end(e);
            return (f.registerKernel&0x80000000L)!=0 ? f.registerKernel : s.get(CMD+4);
        }
        long connectPort(long output,long name,int attempt) {
            require(attempt<f.connectStatuses.length,"Finite scripted connect attempts exhausted");
            long result=f.connectStatuses[attempt],handle=f.connectHandles[attempt];
            Event e=begin(CONNECT_SVC,result,output,name,handle);end(e);
            s.set(output,handle);return result;
        }
        long managerConnect(long name) {
            long result;int attempt=0;
            for(;;){
                result=connectPort(MANAGER_HANDLE,name,attempt++);
                // Independent mask form: level -5, summary 4, description 1018.
                if((result&0xffe003ffL)!=0xd88003faL)break;
                Event e=begin(SLEEP,0x778899,500000,0);
                if(f.sleepCount>=0)s.set(MANAGER,f.sleepCount);end(e);
            }
            if((result&0x80000000L)!=0)return result;
            result=managerRegister();s.set(MANAGER,s.get(MANAGER)+1);return result;
        }
        long managerSetup() {
            Event e=begin(ACQUIRE,0xfedcba98L,MANAGER_LOCK);
            if(f.setupCount>=0)s.set(MANAGER,f.setupCount);end(e);
            long result;
            if((int)s.get(MANAGER)>0){s.set(MANAGER,s.get(MANAGER)+1);result=0x082067f9L;}
            else result=managerConnect(MANAGER_NAME);
            e=begin(RELEASE,0x87654321L,MANAGER_LOCK);
            if(f.unlockCount>=0)s.set(MANAGER,f.unlockCount);end(e);return result;
        }
        long startup() {
            if(s.get(START+4)!=0)return s.get(START+4);
            Event e;long setupResult;
            if(recoverSetup)setupResult=managerSetup();
            else {e=begin(SETUP,f.setupStatus);
                if(recoverAcquisition && f.setupCount>=0)s.set(MANAGER,f.setupCount);end(e);setupResult=f.setupStatus;}
            if(setupResult!=0x08a067f9L && (setupResult&0x80000000L)!=0)
                startupDiagnostic(setupResult,0x10f5e4,true);
            if(stopped)return 0;
            long acquiredStatus;
            if(recoverAcquisition)acquiredStatus=acquire(START+4,SERVICE_NAME,7,0);
            else {
                e=begin(LENGTH,7,SERVICE_NAME);end(e);
                e=begin(GET_SERVICE,f.acquireStatus,START+4,SERVICE_NAME,7,0);
                if(f.acquireWrite)s.set(START+4,f.acquired);end(e);acquiredStatus=f.acquireStatus;
            }
            if((acquiredStatus&0x80000000L)!=0)startupDiagnostic(acquiredStatus,0x10f60c,true);
            if(stopped)return 0;
            long service=s.get(START+4);s.set(STATE+16,service);
            s.set(CMD,0x08610042);s.set(CMD+4,0x040201c8);s.set(CMD+8,0x20);
            e=begin(REQUEST,f.kernelStatus,service,4);
            if(f.response){s.set(CMD+4,f.fileStatus);s.set(CMD+60,0x5a5a1234);}
            if(f.initializeEffect>=0)s.set(START+4,f.initializeEffect);end(e);
            s.set(START+8,START);s.set(PUBLISHED,START+8);
            service=startupGet();if(stopped)return 0;
            long result=stateRequest(service,0);
            if((result&0x80000000L)!=0)return startupDiagnostic(result,0x10f654,true);
            return result;
        }
        @Override long call(int kind) {
            switch(kind) {
                case 41:waitDirect=true;w0=s.get(WAIT_DATA);w1=s.get(WAIT_DATA+4);return waitInitialize(f.waitMode);
                case 42:waitDirect=true;w0=s.get(WAIT_DATA);w1=s.get(WAIT_DATA+4);return waitRun(f.waitResult);
                case 36:{Event e=begin(DIAG,f.waitResult,f.diagResult,f.diagSite);end(e);return f.waitResult;}
                case 37:return deliver(DRECORD,f.waitResult);
                case 38:return process(IPC_OUTPUT,f.processArg);
                case 39:return diagnosticRequest(s.get(IPC_HANDLE),DRECORD);
                case 40:return copyOracle(s,f.copyOut,f.copyIn,f.copyBytes);
                case 32:return managerSetup();
                case 33:return managerConnect(f.connectName);
                case 34:return managerRegister();
                case 35:return connectPort(IPC_OUTPUT,f.connectName,0);
                case 29:return acquire(IPC_OUTPUT,f.namePointer,f.nameBytes,f.nameFlags);
                case 30:{long low=s.get(f.namePointer),high=s.get(f.namePointer+4);s.set(f.copyOutput,low);s.set(f.copyOutput+4,high);return f.copyOutput;}
                case 31:{var e=s.blocks.floorEntry(f.namePointer);int start=(int)(f.namePointer-e.getKey()),i=start;
                    while(e.getValue()[i]!=0)i++;return i-start;}
                case 25:return startup();
                case 26:return stateRequest(s.get(IPC_HANDLE),f.initializeValue);
                case 27:s.set(PUBLISHED,f.publication);return f.publication;
                case 28:return startupGet();
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
                case 23:case 24: {
                    long service=kind==24 ? f.initializeService : s.get(IPC_HANDLE);
                    if(kind==24)s.set(STATE+16,service);
                    s.set(CMD,0x08610042);s.set(CMD+4,kind==24 ? 0x040201c8 : f.initializeValue);s.set(CMD+8,0x20);
                    Event e=begin(REQUEST,f.kernelStatus,service,4);
                    if(f.response){s.set(CMD+4,f.fileStatus);s.set(CMD+60,0x5a5a1234);}
                    end(e);
                    return kind==24 ? 0 : ((f.kernelStatus&0x80000000L)!=0 ? f.kernelStatus : s.get(CMD+4));
                }
                case 20:return descriptorCreate(true,f.descriptor);
                case 21:s.set(FDESC,f.selector&255);s.set(FDESC+4,f.identifier);s.set(FDESC+8,f.descriptorHigh);return FDESC;
                case 22:{
                    long r=descriptorCreate(false,REGISTER_PATH);if((r&0x80000000L)!=0)return r;
                    r=register(created);if((r&0x80000000L)!=0)dispose(created);return r;
                }
                case 19: {Event e=archiveEvent(false,s.get(IPC_HANDLE),0,0,0,0,f.archiveLow,f.archiveHigh);end(e);return archiveResult();}
                default:return super.call(kind);
            }
        }
    }
    class FileMachine extends BackendMachine {
        long archiveData,registerData;
        int activeKind;
        List<String> nameReads=new ArrayList<>(),diagnosticWrites=new ArrayList<>();
        long waitPointer,waitReturn;boolean waitActive,waitLoad,reservation,storePending,storeSuccess;
        FileOracle waitOracle;int waitCursor;WaitAction waitStore;
        List<String> waitTrace=new ArrayList<>();
        WaitAction takeWait(String kind,int offset){
            require(waitCursor<waitOracle.waitActions.size(),"Extra wait action "+kind);
            WaitAction a=waitOracle.waitActions.get(waitCursor++);
            require(a.kind().equals(kind) && a.offset()==offset,"Wait action expected "+a+" got "+kind+":"+offset);
            waitTrace.add(a.toString());return a;
        }
        @Override public void beforeExecuteInstruction(PcodeThread<byte[]> t,Instruction instruction,PcodeProgram program){
            if(!recoverDiagnosticWait || !waitActive)return;
            String mnemonic=instruction.getMnemonicString().toLowerCase(Locale.ROOT);
            waitLoad=mnemonic.equals("ldrex");
            if(mnemonic.equals("strex")){
                long bits=get(instruction.getAddress().getOffset()),address=register("r"+((bits>>>16)&15));
                require(reservation && !storePending,"Wait STREX reservation");
                waitStore=takeWait("store",(int)(address-waitPointer));
                require(get(address)==waitStore.before() && register("r"+(bits&15))==waitStore.value(),"Wait attempted store/current state");
                storePending=true;
            }
        }
        int waitSvcIndex;
        FileMachine(byte[] map,byte[] binary) {super(map,binary);}
        @Override public boolean handleMissingUserop(PcodeThread<byte[]> t,PcodeOp op,PcodeFrame frame,String name,PcodeUseropLibrary<byte[]> library) {
            long pc=thread.getCounter().getOffset();
            if(recoverDiagnosticWait && waitActive && name.equals("ClearExclusiveLocal")){
                require(reservation && !storePending,"Wait CLREX reservation");takeWait("clear",0);reservation=false;waitClears++;return true;
            }
            if(recoverDiagnosticWait && waitActive && name.equals("hasExclusiveAccess")){
                byte[] arg=t.getState().getVar(op.getInput(1),Reason.INSPECT);
                require(reservation && storePending && Utils.bytesToLong(arg,arg.length,false)==waitPointer+waitStore.offset(),"Wait exclusive address");
                reservation=false;storePending=false;storeSuccess=waitStore.extra()==1;waitExclusiveAttempts++;
                t.getState().setVar(op.getOutput(),machine.getArithmetic().fromConst(storeSuccess?1:0,op.getOutput().getSize()));return true;
            }
            if(recoverDiagnostic && !isRebuilt && name.equals("HintPreloadData") && (pc==0x2bcfbc || pc==0x2bcfd4)){
                require(get(pc)==0xf5d1f040L,"Pinned copy PLD encoding");
                diagnosticPrefetchHints++;return true; // Cache hint only; no architectural data result.
            }
            return super.handleMissingUserop(t,op,frame,name,library);
        }
        State relocated(State s) {
            if(!recoverArchives)return s;
            long pointer=s.get(CMD+20);if(pointer!=STACK_PATH && (!recoverDescriptor || pointer!=REGISTER_PATH))return s;
            State result=new State(s);result.set(CMD+20,pointer==STACK_PATH ? archiveData : registerData);return result;
        }
        @Override void check(State s,String label) {super.check(relocated(s),label);}
        @Override void apply(Event e) {
            Event translated=new Event(e.pc,e.result,relocated(e.before),e.args);
            translated.after=relocated(e.after);super.apply(translated);
        }
        @Override public void beforeStore(PcodeThread<byte[]> t,PcodeOp op,AddressSpace sp,byte[] offset,int size,byte[] value) {
            long a=Utils.bytesToLong(offset,offset.length,false);
            if(recoverDiagnosticWait && waitActive && within(a,size,waitPointer,waitPointer+8)){
                require(size==4 && storeSuccess && a==waitPointer+waitStore.offset() && word(value,0)==waitStore.value(),"Wait actual exclusive write");
                storeSuccess=false;return;
            }
            if(recoverDiagnostic){
                if(within(a,size,DRECORD,DRECORD+12))diagnosticWrites.add(Long.toHexString(a)+":"+size+":"+HexFormat.of().formatHex(value));
                if(within(a,size,DRECORD,DRECORD+128) || within(a,size,DHANDLE,DHANDLE+4) || within(a,size,CMD,CMD+132) || activeKind==40 && within(a,size,COPY_DATA,COPY_DATA+768))return;
            }
            if(recoverSetup && (within(a,size,MANAGER,MANAGER+4) || within(a,size,MANAGER_HANDLE,MANAGER_HANDLE+4)))return;
            if(recoverAcquisition && (within(a,size,START+4,START+8) || activeKind==30 && (within(a,size,NAME,NAME+64) || within(a,size,FDESC,FDESC+8))))return;
            if(recoverStartup && (within(a,size,START+8,START+12) || within(a,size,PUBLISHED,PUBLISHED+4)))return;
            if(recoverServices && (within(a,size,CMD,CMD+40) || within(a,size,IPC_OUTPUT,IPC_OUTPUT+4))) return;
            if(recoverArchives && within(a,size,ARCHIVE_OUTPUT,ARCHIVE_OUTPUT+8)) return;
            if(recoverDescriptor && within(a,size,FDESC,FDESC+12))return;
            if(within(a,size,FPOOL,FPOOL+0x3c) || within(a,size,FNODE,FNODE+8) || within(a,size,FNODE+0x40,FNODE+0x48)) return;
            super.beforeStore(t,op,sp,offset,size,value);
        }
        @Override public void beforeLoad(PcodeThread<byte[]> t,PcodeOp op,AddressSpace sp,byte[] offset,int size) {
            long a=Utils.bytesToLong(offset,offset.length,false);
            if(recoverDiagnosticWait && waitActive && (within(a,size,waitPointer,waitPointer+8) || a==ARB_HANDLE)){
                require(size==4,"Wait word access width");
                WaitAction action=takeWait(a==ARB_HANDLE?"handle":waitLoad?"load":"read",a==ARB_HANDLE?0:(int)(a-waitPointer));
                require(get(a)==action.before(),"Wait observed memory before scheduled change");
                if(action.value()!=action.before())writeWord(a,action.value());
                if(waitLoad){require(!reservation,"Wait overlapping reservations");reservation=true;}
            }
            if(recoverAcquisition && activeKind==31 && within(a,size,NAME,NAME+64))nameReads.add(Long.toHexString(a)+":"+size);
            if(within(a,size,FALT_VT,FALT_VT+52)) return;
            super.beforeLoad(t,op,sp,offset,size);
        }
        @Override void seed(State s,boolean rebuilt) {
            super.seed(s,rebuilt);writeWord(VT,rebuilt ? entry[11] : ALL_BEGIN[11]);
            writeWord(FVT+0x2c,rebuilt ? entry[14] : ALL_BEGIN[14]);writeWord(FVT+0x30,rebuilt ? entry[13] : ALL_BEGIN[13]);
            memory(FALT_VT,new byte[52]);writeWord(FALT_VT+0x30,FILE_ALT);
        }
        void call(int kind,Oracle oracle,long expected) throws Exception {
            waitSvcIndex=0;waitActive=reservation=storePending=storeSuccess=false;waitCursor=0;waitTrace.clear();waitOracle=(FileOracle)oracle;activeKind=kind;nameReads.clear();diagnosticWrites.clear();initialize(isRebuilt,0,new byte[0x144]); trace.clear(); FileOracle fo=(FileOracle)oracle;
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
            if(kind==20){register("r0",OUT);register("r1",fo.f.descriptor);register("r2",0xdead1234L);register("r3",0xbeef5678L);}
            if(kind==21){register("r0",FDESC);register("r1",fo.f.selector);register("r2",fo.f.identifier);register("r3",fo.f.descriptorHigh);}
            if(kind==22){register("r0",NAME);register("r1",fo.f.identifier);register("r2",0xdead1234L);register("r3",0xbeef5678L);}
            if(kind==23){register("r0",IPC_HANDLE);register("r1",fo.f.initializeValue);}
            if(kind==24){register("r0",fo.f.initializeService);}
            if(kind==26){register("r0",IPC_HANDLE);register("r1",fo.f.initializeValue);}
            if(kind==27){register("r0",fo.f.publication);}
            if(kind==29){register("r0",IPC_OUTPUT);register("r1",fo.f.namePointer);register("r2",fo.f.nameBytes);register("r3",fo.f.nameFlags);}
            if(kind==30){register("r0",fo.f.copyOutput);register("r1",fo.f.namePointer);}
            if(kind==31){register("r0",fo.f.namePointer);}
            if(kind==33)register("r0",fo.f.connectName);
            if(kind==35){register("r0",IPC_OUTPUT);register("r1",fo.f.connectName);}
            if(kind==36){register("r0",fo.f.diagResult);register("r1",fo.f.diagSite);register("r2",0x98765432);}
            if(kind==37)register("r0",DRECORD);
            if(kind==38){register("r0",IPC_OUTPUT);register("r1",fo.f.processArg);}
            if(kind==39){register("r0",IPC_HANDLE);register("r1",DRECORD);}
            if(kind==40){register("r0",fo.f.copyOut);register("r1",fo.f.copyIn);register("r2",fo.f.copyBytes);}
            if(kind==41 || kind==42){register("r0",WAIT_DATA);register("r1",fo.f.waitMode);register("r2",fo.f.waitPayload);}
            thread.overrideCounter(toAddr(isRebuilt ? entry[kind] : targetBegin[kind])); executing=true;
            int steps=0,event=0; boolean stopped=false;
            while(thread.getCounter().getOffset()!=RETURN) {
                long actualPC=thread.getCounter().getOffset(),pc=actualPC;
                if(recoverDiagnosticWait){
                    if(waitActive && pc==waitReturn)waitActive=false;
                    if(pc==(isRebuilt?entry[41]:WAIT_INIT) || pc==(isRebuilt?entry[42]:WAIT)){
                        boolean init=pc==(isRebuilt?entry[41]:WAIT_INIT);
                        waitPointer=register("r0");waitReturn=register("lr");waitActive=true;
                        require((waitPointer&3)==0,"Aligned wait object");
                        if(kind<41){
                            require(within(waitPointer,8,register("sp"),STACK),"Diagnostic local wait object");
                            if(init)require(get(waitPointer)==0 && get(waitPointer+4)==0 && register("r1")==1,"Zeroed diagnostic wait state/mode");
                            else {require(get(waitPointer)==MASK-1 && get(waitPointer+4)==1,"Recovered initialized wait state");diagnosticWaits++;diagnosticWaitsByKind[kind]++;}
                        }else require(waitPointer==WAIT_DATA,"Direct wait object");
                    }
                    if(waitActive && waitCursor<fo.waitActions.size() && fo.waitActions.get(waitCursor).kind().equals("pending")){
                        // A bounded prefix stops at the next exclusive load, after the failed store and retry branch.
                        if((get(pc)&0x0ff00fffL)==0x01900f9fL){takeWait("pending",(int)(register("r"+((get(pc)>>>16)&15))-waitPointer));stopped=true;waitPending++;break;}
                    }
                }
                if(recoverClear && isRebuilt && pc==clearEntry)pc=CLEAR;
                if(recoverServices && (pc==(isRebuilt ? entry[16] : FILE_SERVICE_OPEN) || pc==(isRebuilt ? entry[17] : FILE_SERVICE_CLOSE)))
                    require((register("sp")&7)==0,"IPC public boundary stack alignment");
                if(recoverArchives && (pc==(isRebuilt ? entry[18] : OPEN) || pc==(isRebuilt ? entry[19] : CLOSE))) {
                    require((register("sp")&7)==0,"Archive public stack alignment");
                    if(pc==(isRebuilt ? entry[18] : OPEN) && kind!=18) {
                        long sp=register("sp"),data=get(sp),output=register("r1"),service=register("r0");
                        require(within(service,4,sp,STACK) && within(output,8,sp,STACK) && (output&7)==0,"Archive caller locals");
                        if(kind==20) require(data==fo.f.descriptor && get(sp+4)==12 && register("r2")==7 && register("r3")==2,"Incoming archive descriptor transport");
                        else if(kind==22){
                            require(within(data,12,sp,STACK) && get(data)==0 && get(data+4)==fo.f.identifier && get(data+8)==0,"Constructed archive descriptor bytes");
                            require(get(sp+4)==12 && register("r2")==7 && register("r3")==2,"Constructed archive descriptor transport");registerData=data;
                        } else {
                            require(within(data,8,sp,STACK) && get(data)==data && get(data+4)==1 && get(sp+4)==1,"Archive self descriptor");
                            archiveData=data;
                        }
                    }
                }
                boolean code=within(pc,4,0x100000,0x477000) || within(pc,4,BUILD,BUILD+codeSize);
                if(recoverServices && code && (get(pc)&0xffff0fffL)==0xee1d0f70L) {
                    require(isRebuilt || (recoverInitialize && pc==0x1272d8) || (recoverStartup && pc==0x11ba84) || (recoverAcquisition && pc==0x12955c) || (recoverSetup && pc==0x129514) || (recoverDiagnostic && pc==0x14696c) || pc==0x356c40 || pc==0x356d60 || (recoverArchives && (pc==0x2adbf8 || pc==0x2adbbc)),"Named TLS sites");
                    long tlsRegister=(get(pc)>>>12)&15;
                    register(tlsRegister==14 ? "lr" : "r"+tlsRegister,TLS);tlsReads++;if(!isRebuilt)visited.add(pc);
                    thread.overrideCounter(toAddr(pc+4));continue;
                }
                boolean arbitrationSvc=recoverDiagnosticWait && code && get(actualPC)==0xef000022L;
                if(arbitrationSvc){pc=WAIT_ARB;if(!isRebuilt)visited.add(actualPC);}
                boolean processSvc=recoverDiagnostic && code && get(actualPC)==0xef000035L;
                if(processSvc){pc=PROCESS_SVC;if(!isRebuilt)visited.add(actualPC);}
                boolean connectSvc=recoverSetup && code && get(actualPC)==0xef00002dL;
                if(connectSvc){pc=CONNECT_SVC;if(!isRebuilt)visited.add(actualPC);}
                boolean request=recoverServices && code && get(actualPC)==0xef000032L;
                if(request) {pc=REQUEST;if(!isRebuilt)visited.add(actualPC);}
                boolean svc=(within(pc,4,0x100000,0x477000) || within(pc,4,BUILD,BUILD+codeSize)) && get(pc)==0xef000023L;
                if(svc) { pc=SVC; if(!isRebuilt) visited.add(actualPC); }
                if((recoverStartup && (!recoverSetup && pc==SETUP || !recoverAcquisition && (pc==LENGTH || pc==GET_SERVICE))) || (!recoverArchives && (pc==OPEN || pc==CLOSE)) || pc==ACQUIRE || pc==RELEASE || pc==CLEAR || (!recoverDiagnostic && pc==DIAG) || recoverDiagnostic && (pc==PROCESS_SVC || !recoverDiagnosticWait && (pc==WAIT_INIT || pc==WAIT)) || pc==WAIT_ARB || (!recoverServices && (pc==FILE_SERVICE_OPEN || pc==FILE_SERVICE_CLOSE)) || pc==REQUEST || pc==SVC || recoverSetup && (pc==CONNECT_SVC || pc==SLEEP) || pc==FILE_ALT || pc==ALT) {
                    require(event<oracle.events.size(),"Unexpected boundary "+Long.toHexString(pc)); Event e=oracle.events.get(event++);
                    require(pc==e.pc,"Boundary order"); check(e.before,"Before "+Long.toHexString(pc));
                    // SVC is an instruction, not an AAPCS public call. GCC's
                    // leaf teardown may retain only word alignment at this site.
                    require((register("sp")&(svc || request || connectSvc || processSvc || arbitrationSvc ? 3 : 7))==0,"Boundary stack alignment");
                    long r0=register("r0"),r1=register("r1"),r2=register("r2"),r3=register("r3"),sp=register("sp");
                    if(pc==WAIT_ARB){
                        require(r0==e.args[0] && r1==waitPointer && r2==1 && r3==0 && register("r4")==0 && register("r5")==0,"Wait arbitration six argument words");
                        require(get(waitPointer)==e.args[1] && get(waitPointer+4)==e.args[2] && !reservation,"Wait arbitration state/reservation");
                        writeWord(waitPointer,e.args[3]);waitArbitrations++;
                        if(kind<41 && !e.terminal)returningDiagnostics++;
                    }else if(pc==PROCESS_SVC){
                        require(r0==e.args[0] && r1==e.args[1],"Process output/handle transport");processCalls++;
                    }else if(pc==WAIT_INIT){
                        require(within(r0,8,sp,STACK) && get(r0)==0 && get(r0+4)==0 && r1==1,"Zeroed two-word diagnostic wait state/mode");
                        waitPointer=r0;writeWord(r0,e.args[1]);writeWord(r0+4,e.args[2]);
                    }else if(pc==WAIT){
                        require(r0==waitPointer && get(r0)==e.args[0] && get(r0+4)==e.args[1],"Initialized wait state reused");diagnosticWaits++;diagnosticWaitsByKind[kind]++;
                        if(!e.terminal)returningDiagnostics++;
                    }else if(pc==CONNECT_SVC){
                        require(r0==e.args[0] && r1==e.args[1],"Connect output/name transport");
                        if(r1==MANAGER_NAME)require(Arrays.equals(memory(r1,5),new byte[]{'s','r','v',':',0}),"Pinned manager name");
                        connectCalls++;
                    } else if(pc==SLEEP){
                        require(r0==e.args[0] && r1==e.args[1],"Retry signed 64-bit delay");sleepCalls++;if(r0==5000000)diagnosticSleeps++;
                    } else if(pc==SETUP) {
                        // No consumed arguments.
                    } else if(pc==LENGTH) {
                        require(r0==SERVICE_NAME && Arrays.equals(memory(r0,8),new byte[]{'f','s',':','U','S','E','R',0}),"Exact service name");
                    } else if(pc==GET_SERVICE) {
                        require(r0==START+4 && r1==SERVICE_NAME && r2==7 && r3==0,"Acquisition output/name/length/flags");
                    } else if(pc==OPEN) {
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
                        if(e.args[1]==1)fileOpens++;else if(e.args[1]==0)fileCloses++;else if(e.args[1]==2)openCalls++;else if(e.args[1]==3)closeCalls++;else if(e.args[1]==4)initializeRequests++;else if(e.args[1]==5)startupRequests++;else if(e.args[1]==6)acquisitionRequests++;else if(e.args[1]==7)registerRequests++;else if(e.args[1]==8)diagnosticRequests++;else throw new IllegalStateException("Unknown IPC kind");
                    } else if(pc==SVC) {
                        require(r0==e.args[0],"SVC close handle"); svcCalls++;
                    } else if(pc==FILE_ALT) {
                        require(r0==FNODE,"Alternate file teardown receiver"); fileAlts++;
                    } else {
                        require(r0==e.args[0],"Boundary r0");
                        if(pc==DIAG) { require(r1==e.args[1],"Diagnostic original site"); if(e.args.length==3)require(r2==e.args[2],"Diagnostic sign argument"); if(recoverStartup && r1==0x10f654)require(sp==STACK && register("lr")==RETURN,"Final diagnostic restores frame before tail call"); if(!e.terminal) returningDiagnostics++; }
                        if(pc==CLEAR) { require(r1==e.args[1] && r2==0,"Clear end/value"); clearCalls++; }
                        if(pc==ALT) altCalls++;
                    }
                    if(recoverClear && pc==CLEAR) {
                        executeClear(); check(e.after,"Executed clear");
                        trace.add(Long.toHexString(pc)+":"+Arrays.toString(e.args)); continue;
                    }
                    apply(e); trace.add(Long.toHexString(pc)+":"+Arrays.toString(e.args));
                    if(e.terminal) { stopped=true; terminals++; break; }
                    externalReturn(e.result); if(connectSvc || processSvc)register("r1",e.args[2]); if(arbitrationSvc){register("r2",(fo.f.waitPayload ^ e.result ^ ++waitSvcIndex)&MASK);register("r4",0xcccc4444L);register("r5",0xcccc5555L);} if(svc || request || connectSvc || processSvc || arbitrationSvc) thread.overrideCounter(toAddr(actualPC+4)); continue;
                }
                // Ghidra 12.1.4 exposes UQSUB8 saturation as an undefined userop.
                // Implement only the exact original instruction, not the strlen call.
                if(recoverAcquisition && !isRebuilt && pc==0x2c330c){
                    require(get(pc)==0xe6621ff1L,"Pinned UQSUB8 encoding");
                    register("r1",unsignedSaturatingSubtractBytes(register("r2"),register("r1")));
                    visited.add(pc);uqsub8Instructions++;thread.overrideCounter(toAddr(pc+4));continue;
                }
                boolean valid=isRebuilt && within(pc,4,BUILD,BUILD+codeSize);
                if(!isRebuilt) for(int i=0;i<targetBegin.length;i++) valid|=within(pc,i==10 ? 2 : 4,targetBegin[i],targetLimit[i]);
                if(recoverAcquisition && !isRebuilt)valid|=within(pc,4,0x12954c,0x1295a0);
                if(recoverSetup && !isRebuilt)valid|=within(pc,4,0x2bb4f0,0x2bb518);
                if(recoverDiagnosticWait && !isRebuilt)valid|=within(pc,4,0x138f44,0x138f5c) || within(pc,4,0x2a88fc,0x2a8914);
                require(valid,"Lifetime PC "+Long.toHexString(pc)); if(!isRebuilt) visited.add(pc);
                require(++steps<6000,"Lifetime instruction budget"); monitor.checkCancelled(); thread.stepInstruction();
            }
            require(event==oracle.events.size() && stopped==oracle.stopped,"Missing boundary/terminal");
            if(recoverDiagnosticWait)require(waitCursor==fo.waitActions.size() && !reservation && !storePending,"Complete wait action trace/reservation");
            check(oracle.s,"Final");
            if(!stopped) {
                if(kind==42)require(register("r2")==fo.expectedWaitPayload,"Wait returned r2 oracle");
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
            if(recoverSetup && kind==25 && seed && c.setupStatus!=0){
                state=new State(state);state.set(MANAGER,0);c.registerStatus=c.setupStatus;
            }
            FileOracle oracle=new FileOracle(state,c);long expected=oracle.call(kind);
            if(seed) {a.seed(state,false);b.seed(state,true);}
            a.call(kind,oracle,expected);b.call(kind,oracle,expected);
            require(a.trace.equals(b.trace),"Boundary agreement");
            if(recoverDiagnosticWait)require(a.waitTrace.equals(b.waitTrace),"Wait access/exclusive agreement");
            if(recoverDiagnostic)require(a.diagnosticWrites.equals(b.diagnosticWrites),"Diagnostic record write order/width/value");
            if(recoverAcquisition && kind==31)require(a.nameReads.equals(b.nameReads),"Length mapped read widths/order");
            log.printf("%d\t%d\t%d\t%x\t%d\t%d%n",cases++,kind,c.fileEffect,expected,oracle.events.size(),oracle.stopped ? 1 : 0);fileKinds[kind]++;
            return oracle.s;
        } catch(Exception e) {throw new IllegalStateException("File owner case "+cases+" kind="+kind+" effect="+c.fileEffect,e);}
    }
    void waitCases(FileMachine a,FileMachine b,PrintWriter log) throws Exception {
        for(long mode:new long[]{0,1,2,0x80000000L,MASK})for(long old:new long[]{0,1,MASK-1,MASK})for(int failures:new int[]{0,2}){
            State state=initial();state.set(WAIT_DATA,old);state.set(WAIT_DATA+4,0x87654321L);
            FileConfig c=new FileConfig();c.waitMode=mode;c.baseFails=failures;c.stateFails=failures;
            pair(a,b,state,c,41,true,log);
        }
        for(int part:new int[]{1,2})for(int failures:new int[]{1,4}){
            State state=initial();state.set(WAIT_DATA,0xabcdef01L);state.set(WAIT_DATA+4,0x12345678);
            FileConfig c=new FileConfig();c.pendingExclusive=part;c.baseFails=part==1?failures:0;c.stateFails=part==2?failures:0;
            pair(a,b,state,c,41,true,log);
        }
        {State state=initial();state.set(WAIT_DATA,0x12345678);state.set(WAIT_DATA+4,0);
            FileConfig c=new FileConfig();c.stateFails=2;c.exclusiveValues=new long[]{1,0x80000000L,0xabcdef01L};pair(a,b,state,c,41,true,log);}
        for(long value:new long[]{MASK-1,MASK,0,1,2,0x7fffffffL,0x80000000L})for(long result:new long[]{0,1,0x80000000L,MASK}){
            State state=initial();state.set(WAIT_DATA,value);state.set(WAIT_DATA+4,0xdead1234L);
            FileConfig c=new FileConfig();c.waitResult=result;c.waitPayload=(result ^ value ^ 0x13579bdfL)&MASK;pair(a,b,state,c,42,true,log);
        }
        for(long changed:new long[]{MASK-1,MASK,1,2,0x80000000L}){
            State state=initial();state.set(WAIT_DATA,0);state.set(WAIT_DATA+4,0);
            FileConfig c=new FileConfig();c.exclusiveValues=new long[]{changed};c.arbStates=new long[]{0};
            pair(a,b,state,c,42,true,log);
        }
        for(int failures:new int[]{1,4})for(boolean pending:new boolean[]{false,true}){
            State state=initial();state.set(WAIT_DATA,0);state.set(WAIT_DATA+4,MASK);
            FileConfig c=new FileConfig();c.stateFails=failures;c.pendingExclusive=pending?2:0;
            pair(a,b,state,c,42,true,log);
        }
        for(long end:new long[]{0,1,MASK-1}){
            State state=initial();state.set(WAIT_DATA,MASK);state.set(WAIT_DATA+4,0x13572468);
            FileConfig c=new FileConfig();c.arbStates=new long[]{MASK,2,0x80000000L,end,1};
            c.arbHandles=new long[]{0,MASK,0x80000000L,0x12345678,0x55556666};
            pair(a,b,state,c,42,true,log);
        }
        {State state=initial();state.set(WAIT_DATA,0);state.set(WAIT_DATA+4,0x12345678);
            FileConfig c=new FileConfig();c.stateFails=3;c.exclusiveValues=new long[]{0,0,1};pair(a,b,state,c,42,true,log);}
        for(long changed:new long[]{0,MASK,0x80000000L}){
            State state=initial();state.set(WAIT_DATA,MASK-1);state.set(WAIT_DATA+4,2);
            FileConfig c=new FileConfig();c.arbStates=new long[]{changed};pair(a,b,state,c,42,true,log);
        }
        {State state=initial();state.set(WAIT_DATA,MASK);state.set(WAIT_DATA+4,1);
            FileConfig c=new FileConfig();c.waitTerminal=true;c.terminalArbitration=3;c.arbStates=new long[]{MASK,MASK,MASK};
            c.arbHandles=new long[]{MASK,0,0x12345678};pair(a,b,state,c,42,true,log);}
        for(long value:new long[]{MASK-1,MASK,2}){
            State state=initial();state.set(WAIT_DATA,value);state.set(WAIT_DATA+4,1);
            FileConfig c=new FileConfig();c.waitTerminal=true;c.arbStates=new long[]{value};pair(a,b,state,c,42,true,log);
        }
    }
    void diagnosticCases(FileMachine a,FileMachine b,PrintWriter log) throws Exception {
        for(long result:new long[]{0,0x7fffffffL,0x80000000L,MASK})for(boolean terminal:new boolean[]{false,true}){
            FileConfig c=new FileConfig();c.diagResult=result;c.diagSite=result^0x12345678;
            c.waitTerminal=terminal;c.waitFirst=0xfffffffeL;c.waitSecond=1;
            pair(a,b,initial(),c,36,true,log);
        }
        for(int type:new int[]{0,1,2,3,5,255})for(long existing:new long[]{0,0x80000000L})
        for(long status:new long[]{0,1,0x80000000L,0xd0401834L,MASK}){
            State s=initial();byteSet(s,DRECORD,type);s.set(DHANDLE,existing);
            FileConfig c=new FileConfig();c.diagStatuses=new long[]{status,0};c.diagHandles=new long[]{0,0x87654321L};
            c.processStatus=MASK;c.diagKernel=MASK;c.waitTerminal=type==3;
            pair(a,b,s,c,37,true,log);
        }
        // Every retry-status bit matters; successful connection with a zero handle
        // still requests, whereas a failed connection publishes its handle too.
        for(int bit=0;bit<32;bit++){
            State s=initial();byteSet(s,DRECORD,2);FileConfig c=new FileConfig();
            c.diagStatuses=new long[]{0xd0401834L^(1L<<bit)};c.diagHandles=new long[]{MASK};
            pair(a,b,s,c,37,true,log);
        }
        for(long afterProcess:new long[]{-1,0,0x87654321L})for(long afterRequest:new long[]{-1,0,MASK}){
            State s=initial();byteSet(s,DRECORD,5);s.set(DHANDLE,0x12345678);
            FileConfig c=new FileConfig();c.processHandle=afterProcess;c.requestHandle=afterRequest;
            pair(a,b,s,c,37,true,log);
        }
        for(long lockHandle:new long[]{-1,0,0x87654321L})for(long type:new long[]{0,2,5,255}){
            State s=initial();byteSet(s,DRECORD,2);s.set(DHANDLE,0x12345678);
            FileConfig c=new FileConfig();c.lockHandle=lockHandle;c.releaseType=type;c.unlockHandle=MASK;
            pair(a,b,s,c,37,true,log);
        }
        // Finite prefixes: repeated failure, failure-published nonzero handle,
        // and release mutation each independently determine the next iteration.
        for(int variant=0;variant<3;variant++){
            State s=initial();byteSet(s,DRECORD,2);FileConfig c=new FileConfig();
            c.diagStatuses=new long[]{0xd0401834L,0xd0401834L,0};
            c.diagHandles=new long[]{variant==1 ? MASK : 0,0,0x10203040};
            if(variant==2){c.releaseType=5;c.unlockHandle=0x98765432L;}
            pair(a,b,s,c,37,true,log);
        }
        for(long status:new long[]{0,1,0x7fffffffL,0x80000000L,MASK})for(long value:new long[]{0,MASK}){
            FileConfig c=new FileConfig();c.processStatus=status;c.processValue=value;c.processArg=value;
            pair(a,b,initial(),c,38,true,log);
        }
        for(long kernel:new long[]{0,1,0x7fffffffL,0x80000000L,MASK})for(boolean response:new boolean[]{false,true}){
            FileConfig c=new FileConfig();c.diagKernel=kernel;c.diagResponse=response;c.diagStatus=kernel^0x87654321L;
            pair(a,b,initial(),c,39,true,log);
        }
        for(int bytes:new int[]{0,1,2,3,4,7,8,15,16,17,31,32,33,63,64,65,127,128,129,160})
        for(int shift:new int[]{-32,-4,0,4,16,32,320}){
            FileConfig c=new FileConfig();c.copyIn=COPY_DATA+128;c.copyOut=c.copyIn+shift;c.copyBytes=bytes;
            pair(a,b,initial(),c,40,true,log);
        }
    }
    void setupCases(FileMachine a,FileMachine b,PrintWriter log) throws Exception {
        long[] counts={0,1,0x7fffffffL,0x80000000L,MASK};
        for(long count:counts)for(long lockCount:new long[]{-1,0,1,0x7fffffffL,0x80000000L,MASK}){
            State s=initial();s.set(MANAGER,count);FileConfig c=new FileConfig();c.setupCount=lockCount;
            c.unlockCount=0x12345678;c.registerStatus=0x80000123L;
            pair(a,b,s,c,32,true,log);
        }
        // Kernel result and output are independent, including failures and high handles.
        for(long status:new long[]{0,1,0x7fffffffL,0x80000000L,0xd88003faL,MASK})
        for(long handle:new long[]{0,0x80000000L,MASK}){
            FileConfig c=new FileConfig();c.connectStatuses=new long[]{status};c.connectHandles=new long[]{handle};
            pair(a,b,initial(),c,35,true,log);
        }
        // A single-bit change distinguishes every tested retry field from ignored bits.
        for(int bit=-1;bit<32;bit++){
            long status=bit<0 ? 0xd88003faL : 0xd88003faL^(1L<<bit);
            FileConfig c=new FileConfig();c.connectStatuses=new long[]{status,0};c.connectHandles=new long[]{0xdead1234L,0x24681357};
            State s=initial();s.set(MANAGER,0);pair(a,b,s,c,33,true,log);
        }
        for(long status:new long[]{0,1,0x7fffffffL,0x80000000L,MASK})for(long count:counts){
            FileConfig c=new FileConfig();c.connectStatuses=new long[]{status};c.connectHandles=new long[]{MASK};
            c.registerStatus=0x80001234L;c.registerCount=count;
            State s=initial();s.set(MANAGER,count);pair(a,b,s,c,33,true,log);
        }
        for(long kernel:new long[]{0,1,0x7fffffffL,0x80000000L,MASK})
        for(long status:new long[]{0,0x7fffffffL,0x80000000L,MASK})for(boolean reply:new boolean[]{false,true}){
            FileConfig c=new FileConfig();c.registerKernel=kernel;c.registerStatus=status;c.registerResponse=reply;
            pair(a,b,initial(),c,34,true,log);
            State s=initial();s.set(MANAGER,0);c.registerCount=0x7fffffffL;
            pair(a,b,s,c,32,true,log);
        }
        for(boolean failure:new boolean[]{false,true}){
            FileConfig c=new FileConfig();
            c.connectStatuses=new long[]{0xd88003faL,0xd89ffffaL,failure ? MASK : 1};
            c.connectHandles=new long[]{0,0x80000000L,MASK};c.sleepCount=0x7fffffffL;
            State s=initial();s.set(MANAGER,0);pair(a,b,s,c,32,true,log);
        }
        // Two complete lifetimes without reseeding: retry, setup, startup guard,
        // repeat setup count, descriptor archive, file, cleanup, and guard reuse.
        for(boolean registrationFailure:new boolean[]{false,true}){
            State s=initial();s.set(MANAGER,0);s.set(NODE,0);s.set(FNODE,0);
            FileConfig c=new FileConfig();c.connectStatuses=new long[]{0xd88003faL,0};c.connectHandles=new long[]{MASK,0x13572468};
            if(registrationFailure)c.registerKernel=MASK;
            a.seed(s,false);b.seed(s,true);
            for(int kind:new int[]{25,25,32,22,8,15,7,25})s=pair(a,b,s,c,kind,false,log);
            require(s.get(MANAGER)==2 && s.get(POOL+0x2c)==0 && s.get(FPOOL+0x2c)==0,"Connected setup count and lifetime");
            setupSequences++;
        }
    }
    @Override public void run() throws Exception {
        Path out=Path.of(getScriptArgs()[0]);require(!Files.exists(out.resolve("comparison.json")),"Existing output");
        loadClear(out);
        recoverDiagnosticWait=getScriptArgs().length>1 && getScriptArgs()[1].equals("diagnostic-wait");
        recoverDiagnostic=recoverDiagnosticWait || getScriptArgs().length>1 && getScriptArgs()[1].equals("diagnostic");
        recoverSetup=recoverDiagnostic || getScriptArgs().length>1 && getScriptArgs()[1].equals("setup");
        recoverAcquisition=recoverSetup || getScriptArgs().length>1 && getScriptArgs()[1].equals("acquisition");
        recoverStartup=recoverAcquisition || getScriptArgs().length>1 && getScriptArgs()[1].equals("startup");
        recoverInitialize=recoverStartup || getScriptArgs().length>1 && getScriptArgs()[1].equals("initialize");
        recoverDescriptor=recoverInitialize || getScriptArgs().length>1 && getScriptArgs()[1].equals("descriptor");
        recoverArchives=recoverDescriptor || (getScriptArgs().length>1 && getScriptArgs()[1].equals("archives"));
        recoverServices=recoverArchives || (getScriptArgs().length>1 && getScriptArgs()[1].equals("services"));
        if(recoverServices) {
            targetBegin=Arrays.copyOf(ALL_BEGIN,18);targetLimit=Arrays.copyOf(ALL_LIMIT,18);fileKinds=new int[18];
            targetBegin[16]=FILE_SERVICE_OPEN;targetLimit[16]=0x356c98;targetBegin[17]=FILE_SERVICE_CLOSE;targetLimit[17]=0x356d84;
        }
        if(recoverArchives) {
            targetBegin=Arrays.copyOf(targetBegin,20);targetLimit=Arrays.copyOf(targetLimit,20);fileKinds=new int[20];
            targetBegin[18]=OPEN;targetLimit[18]=0x2adc44;targetBegin[19]=CLOSE;targetLimit[19]=0x2adbe4;
        }
        if(recoverDescriptor){
            targetBegin=Arrays.copyOf(targetBegin,23);targetLimit=Arrays.copyOf(targetLimit,23);fileKinds=new int[23];
            targetBegin[20]=0x127220;targetLimit[20]=0x1272c4;
            targetBegin[21]=0x2b5fcc;targetLimit[21]=0x2b5fe4;targetBegin[22]=0x11b860;targetLimit[22]=0x11b8d0;
        }
        if(recoverInitialize){
            targetBegin=Arrays.copyOf(targetBegin,25);targetLimit=Arrays.copyOf(targetLimit,25);fileKinds=new int[25];
            targetBegin[23]=0x1272d4;targetLimit[23]=0x127308;targetBegin[24]=0x11ba54;targetLimit[24]=0x11ba78;
        }
        if(recoverStartup){
            targetBegin=Arrays.copyOf(targetBegin,29);targetLimit=Arrays.copyOf(targetLimit,29);fileKinds=new int[29];
            long[] starts={0x10f5b8,0x11ba80,0x11bab0,0x2bbd3c},ends={0x10f664,0x11baac,0x11babc,0x2bbd64};
            System.arraycopy(starts,0,targetBegin,25,4);System.arraycopy(ends,0,targetLimit,25,4);
        }
        if(recoverAcquisition){
            targetBegin=Arrays.copyOf(targetBegin,32);targetLimit=Arrays.copyOf(targetLimit,32);fileKinds=new int[32];
            long[] starts={GET_SERVICE,0x2adba4,LENGTH},ends={0x2c15b8,0x2adbb8,0x2c3340};
            System.arraycopy(starts,0,targetBegin,29,3);System.arraycopy(ends,0,targetLimit,29,3);
        }
        if(recoverSetup){
            targetBegin=Arrays.copyOf(targetBegin,36);targetLimit=Arrays.copyOf(targetLimit,36);fileKinds=new int[36];
            long[] starts={SETUP,0x11cd48,0x129510,0x1382cc},ends={0x2c161c,0x11cdd8,0x129544,0x1382e4};
            System.arraycopy(starts,0,targetBegin,32,4);System.arraycopy(ends,0,targetLimit,32,4);
        }
        if(recoverDiagnostic){
            targetBegin=Arrays.copyOf(targetBegin,41);targetLimit=Arrays.copyOf(targetLimit,41);fileKinds=new int[41];
            long[] starts={DIAG,0x2ad7e8,0x144900,0x146964,0x2bcfac},ends={0x2bbd98,0x2ad8f0,0x144918,0x14699c,0x2bd020};
            System.arraycopy(starts,0,targetBegin,36,5);System.arraycopy(ends,0,targetLimit,36,5);
        }
        if(recoverDiagnosticWait){
            diagnosticWaitsByKind=new int[43];targetBegin=Arrays.copyOf(targetBegin,43);targetLimit=Arrays.copyOf(targetLimit,43);fileKinds=new int[43];
            targetBegin[41]=WAIT_INIT;targetLimit[41]=0x2c54a4;targetBegin[42]=WAIT;targetLimit[42]=0x2c373c;
        }
        byte[] map=new byte[0x377000];require(currentProgram.getMemory().getBytes(toAddr(0x100000),map)==map.length,"Map");
        require(HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(map)).equals("834938d18d2b7c688311c46c27bed813d0d7a9f8e3cbb61da8a6a3f23d360ebd"),"Hash");
        require(word(map,(int)(VT-0x100000))==ALL_BEGIN[11] && word(map,(int)(FVT-0x100000+0x2c))==ALL_BEGIN[14] && word(map,(int)(FVT-0x100000+0x30))==ALL_BEGIN[13],"Original file vtable linkage");
        byte[] binary=Files.readAllBytes(out.resolve("resource-worker-file-owner.bin"));codeSize=binary.length;
        var lines=Files.readAllLines(out.resolve("entries.txt"));require(lines.size()==targetBegin.length,"Entries");entry=new long[targetBegin.length];
        for(int i=0;i<entry.length;i++) entry[i]=Long.parseLong(lines.get(i));
        StringBuilder boundaries=new StringBuilder();
        for(int i=11;i<targetBegin.length;i++) {var f=getFunctionAt(toAddr(targetBegin[i]));require(f!=null,"Saved file function");
            if(recoverAcquisition && i==29){
                AddressSet expectedBody=new AddressSet(toAddr(0x12954c),toAddr(0x12959f));expectedBody.add(toAddr(0x2c1590),toAddr(0x2c15b7));
                require(f.getBody().equals(expectedBody),"Noncontiguous acquisition body");
            } else require(f.getBody().getMinAddress().getOffset()==targetBegin[i] && f.getBody().getMaxAddress().getOffset()==targetLimit[i]-1,"Saved extent");
            boundaries.append(Long.toHexString(targetBegin[i])+" "+f.getBody()+"\n");}
        Files.writeString(out.resolve("function-boundaries.txt"),boundaries);
        FileMachine a=new FileMachine(map,binary),b=new FileMachine(map,binary);
        try(PrintWriter log=new PrintWriter(Files.newBufferedWriter(out.resolve("results.tsv")))) {
            log.println("case\tkind\teffect\tresult\tboundaries\tterminal");
            if(recoverDiagnosticWait)waitCases(a,b,log);
            if(recoverDiagnostic)diagnosticCases(a,b,log);
            if(recoverSetup)setupCases(a,b,log);
            if(recoverAcquisition) {
                // Signed guard precedence, including negative lengths that reach IPC.
                for(long count:new long[]{0,1,0x7fffffffL,0x80000000L,MASK})
                for(long length:new long[]{0,7,8,9,0x7fffffffL,0x80000000L,MASK}) {
                    State s=initial();s.set(MANAGER,count);FileConfig c=new FileConfig();c.nameBytes=length;c.nameFlags=MASK;
                    if((int)count<=0 || (int)length>8)c.namePointer=0; // Must not be dereferenced.
                    pair(a,b,s,c,29,true,log);
                }
                // Kernel vs service status and untouched output/command neighbours.
                for(long kernel:new long[]{0,1,0x7fffffffL,0x80000000L,MASK})
                for(long status:new long[]{0,1,0x7fffffffL,0x80000000L,MASK})
                for(boolean reply:new boolean[]{false,true}) {
                    State s=initial();FileConfig c=new FileConfig();c.acquireKernel=kernel;c.acquireStatus=status;c.acquireWrite=reply;
                    c.acquired=status;c.nameBytes=8;c.nameFlags=0x13579bdfL;s.set(MANAGER_HANDLE,status);
                    pair(a,b,s,c,29,true,log);
                }
                // Unaligned names and embedded zeroes still transport all eight bytes.
                for(int offset=0;offset<4;offset++)for(int zero:new int[]{0,3,7,8}){
                    State s=initial();byte[] n=s.blocks.get(NAME);for(int i=0;i<n.length;i++)n[i]=(byte)(0x80+i);
                    n[offset+zero]=0;FileConfig c=new FileConfig();c.namePointer=NAME+offset;c.nameBytes=zero;
                    pair(a,b,s,c,29,true,log);
                    for(long destination:new long[]{FDESC,NAME+offset,NAME+offset+1,NAME+offset+4,NAME+offset+16}){
                        c.copyOutput=destination;pair(a,b,s,c,30,true,log);
                    }
                }
                // Every initial alignment and zero lane; final aligned word stays mapped.
                for(int offset=0;offset<4;offset++)for(int length:new int[]{0,1,2,3,4,7,8,15,31,59}) {
                    State s=initial();byte[] n=s.blocks.get(NAME);Arrays.fill(n,(byte)0xff);n[offset+length]=0;
                    if(offset+length+1<n.length)n[offset+length+1]=0;
                    FileConfig c=new FileConfig();c.namePointer=NAME+offset;pair(a,b,s,c,31,true,log);
                }
                // Saturation has a host implementation: independently scan every
                // possible byte value in each lane, including high-bit bytes.
                for(int value=0;value<256;value++)for(int lane=0;lane<4;lane++){
                    State s=initial();byte[] n=s.blocks.get(NAME);Arrays.fill(n,(byte)1);n[lane]=(byte)value;n[4]=0;
                    pair(a,b,s,new FileConfig(),31,true,log);
                }
                for(long count:new long[]{0,1,0x80000000L,MASK})for(boolean terminal:new boolean[]{false,true}) {
                    FileConfig c=new FileConfig();c.setupCount=count;c.terminalSite=terminal ? 0x10f60c : 0;
                    pair(a,b,initial(),c,25,true,log);
                }
                for(long kernel:new long[]{1,0x80000000L,MASK}) {
                    FileConfig c=new FileConfig();c.acquireKernel=kernel;c.acquireStatus=MASK;c.diagnosticWrite=true;
                    pair(a,b,initial(),c,25,true,log);
                }
            }
            if(recoverStartup) {
                for(long value:new long[]{0,1,0x7fffffffL,0x80000000L,MASK}) {
                    State s=initial();s.set(START+4,value);FileConfig c=new FileConfig();c.publication=value;
                    pair(a,b,s,c,25,true,log);pair(a,b,s,c,27,true,log);pair(a,b,s,c,28,true,log);
                }
                for(long kernel:new long[]{0,1,0x7fffffffL,0x80000000L,MASK})
                for(long status:new long[]{0,1,0x7fffffffL,0x80000000L,MASK})
                for(boolean response:new boolean[]{false,true}) {
                    FileConfig c=new FileConfig();c.stateKernel=kernel;c.stateStatus=status;c.stateResponse=response;c.initializeValue=status;
                    State s=initial();s.set(IPC_HANDLE,status);pair(a,b,s,c,26,true,log);
                    c.kernelStatus=kernel;c.fileStatus=status;pair(a,b,initial(),c,25,true,log);
                }
                for(long setup:new long[]{0,1,0x08a067f9L,0x7fffffffL,0x80000000L,MASK})
                for(long acquired:new long[]{0,0x80000000L,MASK})
                for(int failure=0;failure<4;failure++) {
                    FileConfig c=new FileConfig();c.setupStatus=setup;c.acquired=acquired;
                    c.acquireStatus=failure==0 ? 0 : failure==1 ? 1 : failure==2 ? 0x80000000L : MASK;
                    c.diagnosticWrite=(failure&1)!=0;c.acquireWrite=failure!=2;
                    pair(a,b,initial(),c,25,true,log);
                }
                for(long site:new long[]{0x10f5e4,0x10f60c,0x2bbd58,0x10f654}) {
                    FileConfig c=new FileConfig();c.terminalSite=site;
                    if(site==0x10f5e4)c.setupStatus=MASK;
                    if(site==0x10f60c)c.acquireStatus=MASK;
                    if(site==0x2bbd58)c.acquired=0;
                    if(site==0x10f654)c.stateStatus=MASK;
                    pair(a,b,initial(),c,25,true,log);
                }
                for(long effect:new long[]{0,0x87654321L})for(boolean edit:new boolean[]{false,true}) {
                    FileConfig c=new FileConfig();c.initializeEffect=effect;c.diagnosticWrite=edit;
                    pair(a,b,initial(),c,25,true,log);
                    pair(a,b,initial(),c,28,true,log);
                }
                // Persistent startup, repeat guard, registered archive/file lifetime,
                // cleanup, then another startup call without reseeding storage.
                for(int mode=0;mode<2;mode++) {
                    State s=initial();s.set(NODE,0);s.set(FNODE,0);FileConfig c=new FileConfig();
                    if(mode==1){c.acquired=0;c.kernelStatus=MASK;c.initializeEffect=0x87654321L;c.stateStatus=MASK;}
                    a.seed(s,false);b.seed(s,true);s=pair(a,b,s,c,25,false,log);
                    s=pair(a,b,s,c,25,false,log);c.kernelStatus=0;c.fileStatus=0;
                    s=pair(a,b,s,c,22,false,log);s=pair(a,b,s,c,8,false,log);
                    s=pair(a,b,s,c,15,false,log);s=pair(a,b,s,c,7,false,log);
                    s=pair(a,b,s,c,25,false,log);
                    require(s.get(POOL+0x2c)==0 && s.get(FPOOL+0x2c)==0,"Startup lifetime returned nodes");startupSequences++;
                }
            }
            if(recoverInitialize) {
                for(long kernel:new long[]{0,1,0x7fffffffL,0x80000000L,MASK})
                for(long status:new long[]{0,1,0x7fffffffL,0x80000000L,MASK})
                for(boolean response:new boolean[]{false,true}) {
                    FileConfig c=new FileConfig();c.kernelStatus=kernel;c.fileStatus=status;c.response=response;
                    c.initializeValue=status;c.initializeService=status;
                    State s=initial();s.set(IPC_HANDLE,status);
                    pair(a,b,s,c,23,true,log);pair(a,b,s,c,24,true,log);
                }
            }
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
            if(recoverDescriptor) {
                // Independent kernel/service signs, no-response paths, output poison,
                // both pool states and service changes at open/acquire/release.
                for(long kernel:new long[]{0,1,0x80000000L,MASK})
                for(long status:new long[]{0,1,0x7fffffffL,0x80000000L,MASK})
                for(int empty=0;empty<2;empty++) for(int effect=0;effect<4;effect++) {
                    State s=initial();if(empty==1)s.set(POOL+0x24,0);
                    FileConfig c=new FileConfig();c.archiveKernel=kernel;c.status=status;c.effect=effect;
                    c.closeStatus=new long[]{0,1,0x80000000L,MASK}[effect];
                    pair(a,b,s,c,20,true,log);
                }
                for(long kernel:new long[]{0,1,0x80000000L}) for(int empty=0;empty<2;empty++) {
                    State s=initial();if(empty==1)s.set(POOL+0x24,0);
                    FileConfig c=new FileConfig();c.archiveKernel=kernel;c.archiveResponse=false;
                    pair(a,b,s,c,20,true,log);
                }
                for(long handle:new long[]{0,1,0x8000000000000000L,-1L})
                for(long descriptor:new long[]{0,FDESC,FDESC+1,MASK}) for(int empty=0;empty<2;empty++) {
                    State s=initial();if(empty==1)s.set(POOL+0x24,0);
                    FileConfig c=new FileConfig();c.low=handle&MASK;c.high=handle>>>32;c.descriptor=descriptor;
                    pair(a,b,s,c,20,true,log);
                }
                for(long flags:new long[]{0,1,2,MASK}) for(long count:new long[]{0,1,0x7fffffffL,MASK}) {
                    State s=initial();s.set(POOL+0x14,flags);s.set(POOL+0x2c,count);
                    pair(a,b,s,new FileConfig(),20,true,log);
                }
                for(long selector:new long[]{0,1,255,256,257,0x80000000L,MASK})
                for(long value:new long[]{0,1,0x80000000L,MASK}) {
                    FileConfig c=new FileConfig();c.selector=selector;c.identifier=value;c.descriptorHigh=~value&MASK;
                    pair(a,b,initial(),c,21,true,log);
                }
                for(long service:new long[]{0,1,0x80000000L,MASK}) {
                    State s=initial();s.set(STATE+16,service);pair(a,b,s,new FileConfig(),20,true,log);
                }
                for(boolean terminal:new boolean[]{false,true}) {
                    State s=initial();s.set(STATE+16,0);s.blocks.get(NAME)[0]=0;
                    FileConfig c=new FileConfig();c.terminal=terminal;pair(a,b,s,c,22,true,log);
                }
                // Actual registration caller: success, empty/duplicate/full names,
                // acquisition failures, close failures and zero/high-only handles.
                for(int registry=0;registry<4;registry++) for(int failure=0;failure<4;failure++)
                for(long handle:new long[]{0,0x8000000000000000L,0xfedcba9876543210L}) {
                    State s=initial();s.set(NODE,0);FileConfig c=new FileConfig();c.low=handle&MASK;c.high=handle>>>32;
                    c.identifier=handle&MASK;c.effect=2;
                    if(registry==1)s.blocks.get(NAME)[0]=0;
                    if(registry==2){s.set(TABLE,0x726f6d);s.set(TABLE+8,NODE+0x40);}
                    if(registry==3)for(int i=0;i<32;i++){s.set(TABLE+16*i,i+1);s.set(TABLE+16*i+8,NODE+0x40);}
                    if(failure==1)c.archiveKernel=0x80000000L;
                    if(failure==2)c.status=MASK;
                    if(failure==3)s.set(POOL+0x24,0);
                    pair(a,b,s,c,22,true,log);
                }
                // Persistent descriptor creation -> registration -> file lifetime ->
                // removal, exhaustion and reuse, without reseeding either machine.
                for(int flags=0;flags<2;flags++) {
                    State s=initial();s.set(NODE,0);s.set(FNODE,0);s.set(POOL+0x14,flags);s.set(FPOOL+0x14,flags);
                    FileConfig c=new FileConfig();a.seed(s,false);b.seed(s,true);
                    for(int round=0;round<3;round++) {
                        if(recoverInitialize){c.initializeService=new long[]{0,0x12345678L,MASK}[round];c.kernelStatus=round==1 ? 0x80000001L : 0;c.fileStatus=MASK;
                            s=pair(a,b,s,c,24,false,log);c.kernelStatus=0;c.fileStatus=0;}
                        c.archiveKernel=0x80000000L;s=pair(a,b,s,c,22,false,log);c.archiveKernel=0;
                        c.status=0x80000001L;s=pair(a,b,s,c,22,false,log);c.status=0;
                        s=pair(a,b,s,c,22,false,log);require(s.get(TABLE+8)==NODE,"Descriptor owner registered/reused");
                        s=pair(a,b,s,c,20,false,log);require(s.get(OUT)==0 && s.get(POOL+0x2c)==1,"Descriptor exhaustion retains owner");
                        s=pair(a,b,s,c,8,false,log);require(s.get(OUT)==FNODE,"Descriptor archive opens concrete file");
                        s=pair(a,b,s,c,15,false,log);
                        s=pair(a,b,s,c,7,false,log);
                        require(s.get(POOL+0x24)==NODE && s.get(POOL+0x2c)==0 && s.get(FPOOL+0x24)==FNODE && s.get(FPOOL+0x2c)==0,"Descriptor lifetime returned both nodes");
                    }
                    descriptorSequences++;
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
                        if(recoverInitialize){c.initializeService=new long[]{0,0x12345678L,MASK}[round];c.kernelStatus=round==1 ? 0x80000001L : 0;c.fileStatus=MASK;
                            s=pair(a,b,s,c,24,false,log);c.kernelStatus=0;c.fileStatus=0;}
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
            for(int i=16;i<(recoverArchives ? 20 : 18);i++)for(long pc=targetBegin[i];pc<targetLimit[i];pc+=4) {
                var ins=currentProgram.getListing().getInstructionAt(toAddr(pc));require(ins!=null && visited.contains(pc),"Unvisited service site");serviceCount++;
                serviceListing.append(String.format("%08x %s %s%n",pc,HexFormat.of().formatHex(ins.getBytes()),ins));
            }
            require(tlsReads==requests && diagnosticRequests+registerRequests+acquisitionRequests+startupRequests+initializeRequests+fileOpens+fileCloses+(recoverArchives ? openCalls+closeCalls : 0)==requests,"Every service uses TLS and kernel boundary");
            Files.writeString(out.resolve("service-original-ghidra.txt"),serviceListing);
            Files.writeString(out.resolve("services.json"),String.format(Locale.ROOT,"{\"recovered_contracts\":%d,\"original_instruction_sites\":%d,\"tls_reads_both\":%d,\"svc_requests_both\":%d,\"service_call_models_removed\":true,\"tls_svc_modeled\":true}\n",recoverArchives ? 4 : 2,serviceCount,tlsReads,requests));
        }
        if(recoverArchives) Files.writeString(out.resolve("archive-services.json"),String.format(Locale.ROOT,"{\"recovered_contracts\":2,\"original_instruction_sites\":34,\"archive_open_requests_both\":%d,\"archive_close_requests_both\":%d,\"archive_call_models_removed\":true,\"tls_svc_modeled\":true,\"stack_descriptor_addresses_relocated\":true}\n",openCalls,closeCalls));
        Files.writeString(out.resolve("comparison.json"),String.format(Locale.ROOT,"{\"cases\":%d,\"cases_by_kind\":%s,\"persistent_sequences\":%d,\"new_instruction_addresses\":%d,\"visited_new_instructions\":%d,\"file_open_calls_both\":%d,\"file_close_calls_both\":%d,\"svc_close_calls_both\":%d,\"alternate_teardown_calls_both\":%d,\"terminal_diagnostics_both\":%d,\"returning_diagnostics_both\":%d,\"max_steps\":%d,\"services_svc_locks_clear_diagnostics_modeled\":true,\"pool_registry_startup_synthetic\":true,\"live_verified\":false}\n",cases,Arrays.toString(fileKinds),sequences,count,seen,fileOpens,fileCloses,svcCalls,fileAlts,terminals,returningDiagnostics,maxSteps));
        if(recoverDescriptor) {
            StringBuilder listingDescriptor=new StringBuilder();int sites=0;
            for(int i=20;i<23;i++)for(long pc=targetBegin[i];pc<targetLimit[i];pc+=4){
                var ins=getInstructionAt(toAddr(pc));require(ins!=null && visited.contains(pc),"Unvisited descriptor factory site");sites++;
                listingDescriptor.append(String.format("%08x %s %s%n",pc,HexFormat.of().formatHex(ins.getBytes()),ins));
            }
            Files.writeString(out.resolve("descriptor-original-ghidra.txt"),listingDescriptor);
            Files.writeString(out.resolve("descriptor-factory.json"),String.format(Locale.ROOT,
                "{\"new_contracts\":3,\"factory_pairs\":%d,\"builder_pairs\":%d,\"registration_pairs\":%d,\"original_instruction_sites\":%d,\"persistent_sequences\":%d,\"opaque_descriptor_transport_checked\":true,\"service_capture_reload_checked\":true,\"archive_ipc_and_lifetime_executed\":true,\"locks_tls_svc_diagnostics_modeled\":true}\n",fileKinds[20],fileKinds[21],fileKinds[22],sites,descriptorSequences));
        }
        if(recoverInitialize){
            int sites=0;StringBuilder listingInitialize=new StringBuilder();
            for(int i=23;i<25;i++)for(long pc=targetBegin[i];pc<targetLimit[i];pc+=4){
                var ins=getInstructionAt(toAddr(pc));require(ins!=null && visited.contains(pc),"Unvisited initialize site");sites++;
                listingInitialize.append(String.format("%08x %s %s%n",pc,HexFormat.of().formatHex(ins.getBytes()),ins));
            }
            Files.writeString(out.resolve("initialize-original-ghidra.txt"),listingInitialize);
            Files.writeString(out.resolve("service-initialize.json"),String.format(Locale.ROOT,
                "{\"new_contracts\":2,\"request_pairs\":%d,\"publication_pairs\":%d,\"instruction_sites\":%d,\"requests_both\":%d,\"persistent_sequences\":%d,\"tls_svc_modeled\":true}\n",fileKinds[23],fileKinds[24],sites,initializeRequests,descriptorSequences+sequences));
        }
        if(recoverStartup){
            int sites=0;StringBuilder listingStartup=new StringBuilder();
            for(int i=25;i<29;i++)for(long pc=targetBegin[i];pc<targetLimit[i];pc+=4){
                var ins=getInstructionAt(toAddr(pc));require(ins!=null && visited.contains(pc),"Unvisited startup site "+Long.toHexString(pc));sites++;
                listingStartup.append(String.format("%08x %s %s%n",pc,HexFormat.of().formatHex(ins.getBytes()),ins));
            }
            Files.writeString(out.resolve("startup-original-ghidra.txt"),listingStartup);
            Files.writeString(out.resolve("service-startup.json"),String.format(Locale.ROOT,
                "{\"new_contracts\":3,\"reused_accessor_contracts\":1,\"startup_pairs\":%d,\"request_pairs\":%d,\"publisher_pairs\":%d,\"accessor_pairs\":%d,\"instruction_sites\":%d,\"state_requests_both\":%d,\"persistent_sequences\":%d,\"setup_length_acquisition_tls_svc_diagnostics_modeled\":true}\n",fileKinds[25],fileKinds[26],fileKinds[27],fileKinds[28],sites,startupRequests,startupSequences));
            if(recoverAcquisition){
                Path startupEvidence=out.resolve("service-startup.json");
                Files.writeString(startupEvidence,Files.readString(startupEvidence).replace("setup_length_acquisition_tls_svc_diagnostics_modeled","setup_tls_svc_diagnostics_modeled"));
            }
        }
        if(recoverAcquisition){
            int sites=0;StringBuilder listingAcquisition=new StringBuilder();
            for(long[] range:new long[][]{{0x2c1590,0x2c15b8},{0x12954c,0x1295a0},{0x2adba4,0x2adbb8},{0x2c32e4,0x2c3340}})
            for(long pc=range[0];pc<range[1];pc+=4){
                var ins=getInstructionAt(toAddr(pc));require(ins!=null && visited.contains(pc),"Unvisited acquisition site "+Long.toHexString(pc));sites++;
                listingAcquisition.append(String.format("%08x %s %s%n",pc,HexFormat.of().formatHex(ins.getBytes()),ins));
            }
            Files.writeString(out.resolve("acquisition-original-ghidra.txt"),listingAcquisition);
            Files.writeString(out.resolve("service-acquisition.json"),String.format(Locale.ROOT,
                "{\"new_contracts\":3,\"models_removed\":2,\"acquisition_pairs\":%d,\"copy_pairs\":%d,\"length_pairs\":%d,\"instruction_sites\":%d,\"requests_both\":%d,\"length_read_trace_equal\":true,\"uqsub8_host_emulation\":true,\"uqsub8_instructions\":%d,\"setup_tls_svc_locks_diagnostics_modeled\":true}\n",fileKinds[29],fileKinds[30],fileKinds[31],sites,acquisitionRequests,uqsub8Instructions));
        }
        if(recoverSetup){
            int sites=0;StringBuilder listingSetup=new StringBuilder();
            for(int i=32;i<36;i++)for(long pc=targetBegin[i];pc<targetLimit[i];pc+=4){
                var ins=getInstructionAt(toAddr(pc));require(ins!=null && visited.contains(pc),"Unvisited setup site "+Long.toHexString(pc));sites++;
                listingSetup.append(String.format("%08x %s %s%n",pc,HexFormat.of().formatHex(ins.getBytes()),ins));
            }
            for(long pc=0x2bb4f0;pc<0x2bb504;pc+=4)require(visited.contains(pc),"Consumed recovered delay site");
            Files.writeString(out.resolve("setup-original-ghidra.txt"),listingSetup);
            Files.writeString(out.resolve("service-setup.json"),String.format(Locale.ROOT,
                "{\"new_contracts\":4,\"models_removed\":1,\"setup_pairs\":%d,\"connect_pairs\":%d,\"register_pairs\":%d,\"wrapper_pairs\":%d,\"instruction_sites\":%d,\"connect_svc_both\":%d,\"register_requests_both\":%d,\"retry_sleeps_both\":%d,\"persistent_setup_sequences\":%d,\"reused_delay\":true,\"tls_kernel_sleep_locks_diagnostics_modeled\":true}\n",fileKinds[32],fileKinds[33],fileKinds[34],fileKinds[35],sites,connectCalls,registerRequests,sleepCalls,setupSequences));
            for(String file:new String[]{"service-startup.json","service-acquisition.json"}){
                Path path=out.resolve(file);Files.writeString(path,Files.readString(path).replace("setup_tls_svc", "tls_svc"));
            }
        }
        if(recoverDiagnosticWait){
            int sites=0;StringBuilder waitListing=new StringBuilder();
            for(int i=41;i<43;i++)for(long pc=targetBegin[i];pc<targetLimit[i];pc+=4){
                var ins=getInstructionAt(toAddr(pc));require(ins!=null && visited.contains(pc),"Unvisited wait site "+Long.toHexString(pc));sites++;
                waitListing.append(String.format("%08x %s %s%n",pc,HexFormat.of().formatHex(ins.getBytes()),ins));
            }
            for(long[] range:new long[][]{{0x138f44,0x138f5c},{0x2a88fc,0x2a8914}})for(long pc=range[0];pc<range[1];pc+=4)
                require(visited.contains(pc),"Unvisited reused wait dependency "+Long.toHexString(pc));
            Files.writeString(out.resolve("diagnostic-wait-original-ghidra.txt"),waitListing);
            Files.writeString(out.resolve("diagnostic-wait.json"),String.format(Locale.ROOT,
                "{\"extended_wait_r2_contract\":true,\"direct_r2_oracle_checked\":true,\"historical_initializer_and_wait_contracts\":2,\"active_call_models_removed\":2,\"initializer_pairs\":%d,\"wait_pairs\":%d,\"instruction_sites\":%d,\"exclusive_attempts_both\":%d,\"clrex_both\":%d,\"arbitrations_both\":%d,\"pending_exclusive_prefixes_both\":%d,\"connected_waits_both\":%d,\"waits_by_kind_both\":%s,\"exclusive_trace_equal\":true,\"base_initializer_and_arbitration_reused\":true,\"kernel_arbitration_exclusive_outcomes_modeled\":true}\n",
                fileKinds[41],fileKinds[42],sites,waitExclusiveAttempts,waitClears,waitArbitrations,waitPending,diagnosticWaits,Arrays.toString(diagnosticWaitsByKind)));
        }
        if(recoverDiagnostic){
            int sites=0;StringBuilder diagnosticListing=new StringBuilder();
            for(int i=36;i<41;i++)for(long pc=targetBegin[i];pc<targetLimit[i];pc+=4){
                var ins=getInstructionAt(toAddr(pc));require(ins!=null && visited.contains(pc),"Unvisited diagnostic site "+Long.toHexString(pc));sites++;
                diagnosticListing.append(String.format("%08x %s %s%n",pc,HexFormat.of().formatHex(ins.getBytes()),ins));
            }
            Files.writeString(out.resolve("diagnostic-original-ghidra.txt"),diagnosticListing);
            Files.writeString(out.resolve("diagnostic.json"),String.format(Locale.ROOT,
                "{\"new_contracts\":5,\"active_call_models_removed\":1,\"wrapper_pairs\":%d,\"delivery_pairs\":%d,\"process_pairs\":%d,\"request_pairs\":%d,\"copy_pairs\":%d,\"instruction_sites\":%d,\"requests_both\":%d,\"process_svc_both\":%d,\"lower_waits_both\":%d,\"retry_sleeps_both\":%d,\"waits_by_kind_both\":%s,\"ignored_prefetch_hints\":%d,\"record_write_trace_equal\":true,\"copy_executed\":true,\"lower_waits_tls_kernel_locks_modeled\":true}\n",
                fileKinds[36],fileKinds[37],fileKinds[38],fileKinds[39],fileKinds[40],sites,diagnosticRequests,processCalls,diagnosticWaits,diagnosticSleeps,Arrays.toString(diagnosticWaitsByKind),diagnosticPrefetchHints));
        }
        if(recoverDiagnostic){
            for(String file:new String[]{"descriptor-factory.json","service-initialize.json","service-startup.json","service-acquisition.json","service-setup.json"}){
                Path path=out.resolve(file);Files.writeString(path,Files.readString(path).replace("diagnostics_modeled", "lower_diagnostic_waits_modeled"));
            }
        }
        saveClear(out);
        println("SMT4_FILE_OWNER_COMPARE_OK");
    }
}
