// Recovered read dispatch/method/IPC and delay, with explicit platform models.
// @category SMT4
import ghidra.pcode.emu.PcodeThread;
import ghidra.pcode.utils.Utils;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.pcode.PcodeOp;
import java.nio.file.*;
import java.security.MessageDigest;
import java.util.*;
import java.io.*;

public class CompareResourceWorkerFileReadService extends CompareResourceWorkerFileRead {
    static final long[] CHAIN={0x2a4e54,0x3564a8,0x356d04,0x2adc48,0x239cd0};
    static final long[] LIMIT={0x2a4eb0,0x3564e8,0x356d58,0x2adcd0,0x239cf4};
    static final long TLS=0x920020,CMD=TLS+0x80,FB=0x921000,FO=FB+0x20,FH=FB+0x40,FV=FB+0x80,ALT=0x730100,STATE=0x44e650;
    long[] chain=new long[9];
    int directCases,delayCases,connectedCases,sequences,requests,tlsReads,queries,sleeps,alternates,diagnostics,delaySteps,chainSteps;
    @Override long readServiceTarget(boolean path) { return path ? chain[0] : CHAIN[0]; }
    boolean chainCode(long pc) {
        for(int k=0;k<CHAIN.length;k++)if(within(pc,4,CHAIN[k],LIMIT[k]))return true;
        return within(pc,4,0x2c6c64,0x2c6c94) || within(pc,4,0x2c61e4,0x2c62d4) || within(pc,4,0x2bb4f0,0x2bb518);
    }
    class ServiceMachine extends ReadMachine {
        long activeOutput, queryValue=0x1f, queryBase=-1;
        boolean switchVtable;
        int responseIndex;
        ServiceMachine(byte[] mapped,byte[] binary) { super(mapped,binary); }
        @Override public void beforeStore(PcodeThread<byte[]> t,PcodeOp op,AddressSpace space,byte[] offset,int size,byte[] value) {
            long a=Utils.bytesToLong(offset,offset.length,false);
            if(within(a,size,CMD,CMD+24) || (activeOutput!=0 && within(a,size,activeOutput,activeOutput+4)))return;
            super.beforeStore(t,op,space,offset,size,value);
        }
        @Override public void beforeLoad(PcodeThread<byte[]> t,PcodeOp op,AddressSpace space,byte[] offset,int size) {
            long a=Utils.bytesToLong(offset,offset.length,false);
            if(within(a,size,CMD,CMD+24) || within(a,size,FO,FO+8) || within(a,size,FH,FH+4) || within(a,size,FV,FV+24))return;
            super.beforeLoad(t,op,space,offset,size);
        }
        void seed(boolean path,long handle,int enabled,int query,long base,boolean alternate) {
            byte[] tls=new byte[0x140];new Random(0x356d04).nextBytes(tls);memory(TLS-32,tls);
            byte[] file=new byte[0x100];new Random(0x3564a8).nextBytes(file);memory(FB,file);
            writeWord(FO,FV);writeWord(FO+4,handle);writeWord(FH,handle);
            writeWord(FV,alternate ? ALT : path ? chain[1] : CHAIN[1]);writeWord(FV+4,0x730104);
            writeWord(FV+16,ALT);
            byte[] state=new byte[64];new Random(0x2adc48).nextBytes(state);state[16]=(byte)enabled;state[17]=(byte)query;put(state,40,base);memory(STATE-16,state);
            queryValue=0x1f;queryBase=-1;switchVtable=false;responseIndex=0;
        }
        void executeDelay(boolean path,long mode) throws Exception {
            long ret=register("lr"),sp=register("sp");long[] saved=new long[8];for(int r=4;r<=11;r++)saved[r-4]=register("r"+r);
            require(register("r0")==mode,"Delay mode forwarding");
            byte[] state=memory(STATE-16,64),expected=state.clone();
            boolean query=state[16]!=0 && state[17]!=0;
            long base=query && queryBase>=0 ? queryBase : word(state,40);
            long extra=query && (queryValue&16)!=0 ? (mode==0 ? 380 : 100)/((queryValue&15)+1) : 0;
            long duration=state[16]==0 ? 0 : ((base+extra)&0xffff)*1000000;
            int q=0,s=0,steps=0;
            while(thread.getCounter().getOffset()!=ret) {
                long pc=thread.getCounter().getOffset();
                if(pc==0x1382e4) {
                    require(++s==1 && duration!=0 && q==(query ? 1 : 0),"Delay sleep predicate/order");
                    require((register("r0")|(register("r1")<<32))==duration && (register("sp")&7)==0,"Delay duration and alignment");
                    if(switchVtable)writeWord(FO,FV+16);
                    sleeps++;trace.add("sleep:"+duration);externalReturn(0x98765432L);continue;
                }
                require(path ? within(pc,4,BUILD,BUILD+codeSize) : chainCode(pc),"Delay PC "+Long.toHexString(pc));
                if(!path)visited.add(pc);
                if(get(pc)==0xef000028L) {
                    require((path || pc==0x2adc78) && query && ++q==1 && s==0,"Delay query predicate/order");
                    require(register("r0")== (state[17]&255),"Query input byte");
                    if(queryBase>=0){writeWord(STATE+24,queryBase);put(expected,40,queryBase);}
                    queries++;trace.add("query:"+queryValue+":"+queryBase);externalReturn(queryValue);thread.overrideCounter(toAddr(pc+4));continue;
                }
                require(++steps<600,"Delay instruction budget");monitor.checkCancelled();thread.stepInstruction();
            }
            require(q==(query ? 1 : 0) && s==(duration==0 ? 0 : 1),"Delay calls");
            require(Arrays.equals(memory(STATE-16,64),expected),"Delay state and guards");
            require(register("sp")==sp,"Delay stack restoration");for(int r=4;r<=11;r++)require(register("r"+r)==saved[r-4],"Delay saved register");
            delaySteps=Math.max(delaySteps,steps);
        }
        void executeChain(boolean path,int kind,long kernel,long service,long count,boolean payload,
                boolean invalid,boolean alternate,boolean terminal) throws Exception {
            long ret=register("lr"),sp=register("sp");long[] saved=new long[8];for(int r=4;r<=11;r++)saved[r-4]=register("r"+r);
            long out=kind==0 ? register("r0") : register("r1"),cursor=register("r2")|(register("r3")<<32),buffer=get(sp),bytes=get(sp+4);
            activeOutput=out;
            byte[] tls=memory(TLS-32,0x140),file=memory(FB,0x100),output=out==0 ? null : memory(out,4);
            byte[] expectedTls=tls.clone(),expectedFile=file.clone(),expectedOutput=output==null ? null : output.clone();
            long handle=kind==2 ? get(FH) : get(FO+4);
            long expected=invalid ? 0xe0e046bcL : alternate ? service : (kernel&0x80000000L)!=0 ? kernel : service;
            int calls=0,reads=0,delays=0,diag=0,alts=0,steps=0;boolean stopped=false;
            while(thread.getCounter().getOffset()!=ret) {
                long pc=thread.getCounter().getOffset();
                if(pc==(path ? chain[3] : CHAIN[3])) {
                    require(kind==0 && !invalid && ++delays==1 && calls==0 && alts==0,"Pre-read delay order");
                    require(Arrays.equals(memory(TLS-32,0x140),tls),"Delay precedes command writes");
                    executeDelay(path,1);if(switchVtable)put(expectedFile,32,FV+16);continue;
                }
                if(pc==0x2bbd70) {
                    require(!invalid && !alternate && kind!=2 && handle==0 && ++diag==1,"Handle diagnostic predicate");
                    require(register("r0")==0xe0a046daL && register("r1")==0x239cec && (register("sp")&7)==0,"Handle diagnostic arguments");
                    diagnostics++;trace.add("diagnostic:"+terminal);
                    if(terminal){stopped=true;break;}
                    handle=0x81234567L;writeWord(FO+4,handle);put(expectedFile,36,handle);externalReturn(0x98765432L);continue;
                }
                if(pc==ALT) {
                    require(alternate && !invalid && ++alts==1 && delays==1,"Alternate read dispatch order");
                    require(register("r0")==FO && register("r1")==out && (register("r2")|(register("r3")<<32))==cursor && get(register("sp"))==buffer && get(register("sp")+4)==bytes,"Alternate read arguments");
                    if(out!=0){writeWord(out,count);put(expectedOutput,0,count);}
                    alternates++;trace.add("alternate:"+cursor+":"+buffer+":"+bytes+":"+service);externalReturn(service);continue;
                }
                require(path ? within(pc,4,BUILD,BUILD+codeSize) : chainCode(pc),"Read chain PC "+Long.toHexString(pc));
                if(!path)visited.add(pc);
                long ins=get(pc);
                if((ins&0xffff0fffL)==0xee1d0f70L) {
                    require((path || pc==0x356d14) && ++reads==1 && !invalid && !alternate,"Read TLS site/count");
                    require(delays==(kind==0 ? 1 : 0),"Read delay before TLS");
                    require(Arrays.equals(memory(TLS-32,0x140),tls),"Read command before TLS");
                    register("r"+((ins>>>12)&15),TLS);tlsReads++;thread.overrideCounter(toAddr(pc+4));continue;
                }
                if(ins==0xef000032L) {
                    require((path || pc==0x356d3c) && ++calls==1 && reads==1,"Read SVC site/count");
                    require(register("r0")==handle && (register("sp")&3)==0,"Read SVC handle/alignment");
                    long[] words={0x080200c2,cursor&MASK,cursor>>>32,bytes,((bytes*16)&MASK)|12,buffer};
                    for(int i=0;i<words.length;i++)put(expectedTls,0xa0+i*4,words[i]);
                    require(Arrays.equals(memory(TLS-32,0x140),expectedTls),"Exact read IPC request/preserved memory");
                    require(Arrays.equals(memory(FB,0x100),expectedFile) && (out==0 || Arrays.equals(memory(out,4),output)),"Read before SVC state");
                    put(expectedTls,0xa4,service);put(expectedTls,0xa8,count);put(expectedTls,0xbc,0xa5a55a5aL);memory(TLS-32,expectedTls);
                    if((kernel&0x80000000L)==0){require(out!=0,"Writable count domain");put(expectedOutput,0,count);}
                    // Scripted kernel DMA is separate from publication, including error-time writes.
                    if(payload) {
                        int n=(int)Math.min(3,bytes);if((kernel&0x80000000L)==0 && (service&0x80000000L)==0)n=(int)count;
                        require(n>=0 && n<=bytes && within(buffer,n,DATA,DATA+1024),"Read payload domain");
                        byte[] content=new byte[n];for(int i=0;i<n;i++)content[i]=(byte)((cursor+i)*17+0x39);
                        memory(buffer,content);System.arraycopy(content,0,expectedData,(int)(buffer-DBASE),n);
                    }
                    requests++;trace.add("svc:"+handle+":"+cursor+":"+buffer+":"+bytes+":"+kernel+":"+service+":"+count);
                    externalReturn(kernel);thread.overrideCounter(toAddr(pc+4));continue;
                }
                require(++steps<200,"Read chain budget");monitor.checkCancelled();thread.stepInstruction();
            }
            require(delays==(kind==0 && !invalid ? 1 : 0),"Read delay count");
            require(calls==(!invalid && !alternate && !stopped ? 1 : 0) && reads==calls,"Read request count");
            require(alts==(alternate && !invalid ? 1 : 0),"Read alternate count");
            require(diag==(!invalid && !alternate && kind!=2 && word(file,36)==0 ? 1 : 0),"Read diagnostic count");
            require(Arrays.equals(memory(TLS-32,0x140),expectedTls) && Arrays.equals(memory(FB,0x100),expectedFile),"Read TLS/file guards");
            if(out!=0)require(Arrays.equals(memory(out,4),expectedOutput),"Read count publication/preservation");
            require(Arrays.equals(memory(DBASE,DLEN),expectedData),"Read data/guards");
            require(stopped==terminal,"Read diagnostic stop");
            if(!stopped){require(register("r0")==expected && register("sp")==sp,"Read result/stack");for(int r=4;r<=11;r++)require(register("r"+r)==saved[r-4],"Read saved register");}
            activeOutput=0;chainSteps=Math.max(chainSteps,steps);
        }
        @Override void executeReadService(boolean path,long status,long received,long cursor,long buffer,long remaining,long out,boolean payload) throws Exception {
            // Select kernel versus service failure independently across calls.
            long kernel=(status&0x80000000L)!=0 && (responseIndex++&1)==0 ? status : 1;
            executeChain(path,0,kernel,status,received,payload,register("r1")==0 || buffer==0,false,false);
        }
        void prepare(boolean path) throws Exception {
            initialize(path,0,new byte[0x144]);destroyed=false;trace.clear();
            byte[] out=new byte[40];Arrays.fill(out,(byte)0x5a);memory(SIZE-16,out);
            expectedData=new byte[DLEN];new Random(OS_READ).nextBytes(expectedData);memory(DBASE,expectedData);
            register("sp",STACK-16);
        }
        void probe(boolean path,int kind,long handle,long cursor,long bytes,long kernel,long service,long count,
                int nulls,boolean alternate,boolean terminal,boolean switchAfterDelay) throws Exception {
            prepare(path);seed(path,handle,1,1,0xffff,alternate && !switchAfterDelay);
            switchVtable=switchAfterDelay;
            long buffer=(nulls&2)!=0 ? 0 : bytes<=128 ? DATA+7 : 0xfffffff8L;
            register("r0",kind==0 ? (nulls&4)!=0 ? 0 : SIZE : kind==1 ? FO : FH);
            register("r1",kind==0 ? (nulls&1)!=0 ? 0 : FO : (nulls&4)!=0 ? 0 : SIZE);
            register("r2",cursor&MASK);register("r3",cursor>>>32);writeWord(STACK-16,buffer);writeWord(STACK-12,bytes);
            thread.overrideCounter(toAddr(path ? chain[kind] : CHAIN[kind]));executing=true;
            executeChain(path,kind,kernel,service,count,bytes<=128 && buffer!=0,(nulls&3)!=0,alternate,terminal);
            for(byte v:memory(STACK-0x1000,0xe00))require(v==(byte)0x96,"Read lower stack guards");
            for(byte v:memory(SIZE-16,16))require(v==(byte)0x5a,"Read output prefix guard");
            for(byte v:memory(SIZE+4,20))require(v==(byte)0x5a,"Read output suffix guard");
            require(get(STACK-16)==buffer && get(STACK-12)==bytes,"Read caller argument preservation");
        }
    }
    void direct(ServiceMachine a,ServiceMachine b,int kind,long handle,long cursor,long bytes,long kernel,long service,long count,int nulls,boolean alt,boolean terminal,boolean change,PrintWriter log) throws Exception {
        try {
            a.probe(false,kind,handle,cursor,bytes,kernel,service,count,nulls,alt,terminal,change);
            b.probe(true,kind,handle,cursor,bytes,kernel,service,count,nulls,alt,terminal,change);
            require(a.trace.equals(b.trace),"Direct read trace agreement");
        }catch(Exception e){throw new IllegalStateException("Read service case direct="+directCases+" kind="+kind,e);}
        log.printf("direct\t%d\t%d\t%x\t%x\t%x\t%x\t%x\t%x\t%d\t%s\t%s\t%s%n",directCases++,kind,handle,cursor,bytes,kernel,service,count,nulls,alt,terminal,change);
    }
    void delay(ServiceMachine a,ServiceMachine b,long mode,int enabled,int query,long base,long value,long changedBase,PrintWriter log) throws Exception {
        try {
            for(int p=0;p<2;p++) {
                ServiceMachine m=p==0 ? a : b;m.prepare(p==1);m.seed(p==1,7,enabled,query,base,false);m.queryValue=value;m.queryBase=changedBase;
                m.register("r0",mode);m.thread.overrideCounter(toAddr(p==1 ? chain[3] : CHAIN[3]));m.executing=true;m.executeDelay(p==1,mode);
            }
            require(a.trace.equals(b.trace),"Delay trace agreement");
        }catch(Exception e){throw new IllegalStateException("Read service case delay="+delayCases,e);}
        log.printf("delay\t%d\t%x\t%d\t%d\t%x\t%x\t%x%n",delayCases++,mode,enabled,query,base,value,changedBase);
    }
    void connected(ServiceMachine a,ServiceMachine b,boolean adapter,long handle,long cursor,long buffer,long bytes,long[][] responses,boolean payload,boolean retain,PrintWriter log) throws Exception {
        try {
            if(!retain){a.seed(false,0x81234567L,1,1,0xffff,false);b.seed(true,0x81234567L,1,1,0xffff,false);}
            a.directRead(false,adapter,handle,cursor,buffer,bytes,responses,payload,retain);
            b.directRead(true,adapter,handle,cursor,buffer,bytes,responses,payload,retain);
            require(a.trace.equals(b.trace),"Connected read trace agreement");
            require(Arrays.equals(a.memory(TLS-32,0x140),b.memory(TLS-32,0x140)),"Connected read TLS agreement");
        }catch(Exception e){throw new IllegalStateException("Read service case connected="+connectedCases+" bytes="+bytes,e);}
        log.printf("connected\t%d\t%s\t%x\t%x\t%x\t%x\t%s\t%s%n",connectedCases++,adapter,handle,cursor,buffer,bytes,Arrays.deepToString(responses),retain);
    }
    @Override public void run() throws Exception {
        Path out=Path.of(getScriptArgs()[0]);byte[] mapped=new byte[0x377000];
        require(currentProgram.getMemory().getBytes(toAddr(0x100000),mapped)==mapped.length,"Map");
        require(HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(mapped)).equals("834938d18d2b7c688311c46c27bed813d0d7a9f8e3cbb61da8a6a3f23d360ebd"),"Reference hash");
        byte[] binary=Files.readAllBytes(out.resolve("read-service.bin"));codeSize=binary.length;
        var entries=Files.readAllLines(out.resolve("entries.txt"));for(int k=0;k<chain.length;k++)chain[k]=Long.parseLong(entries.get(k));
        readEntry=chain[5];methodEntries[2]=chain[6];
        StringBuilder listing=new StringBuilder();
        for(int k=0;k<4;k++) {
            var f=getFunctionAt(toAddr(CHAIN[k]));require(f!=null,"Saved function");
            if(k<3)require(f.getBody().getNumAddresses()==LIMIT[k]-CHAIN[k] && f.getBody().getMaxAddress().getOffset()==LIMIT[k]-1,"Saved extent");
            else require(f.getBody().toString().equals("[[001382bc, 001382cb] [001382e4, 001382eb] [002adc48, 002adccf]]"),"Saved disjoint delay extent");
            listing.append(f.getEntryPoint()+" "+f.getBody()+"\n");
            for(long pc=CHAIN[k];pc<LIMIT[k];pc+=4){var ins=getInstructionAt(toAddr(pc));require(ins!=null,"Instruction boundary");listing.append(ins.getAddress()+" "+ins+"\n");}
        }
        require(word(mapped,0x320998)==CHAIN[1] && word(mapped,0x1a4eb0)==0xe0e046bcL && word(mapped,0x256d58)==0x080200c2 && word(mapped,0x1adcd0)==STATE && word(mapped,0x1adcd4)==1000000,"Read literals/vtable");
        Files.writeString(out.resolve("original-read-service-ghidra.txt"),listing);
        ServiceMachine a=new ServiceMachine(mapped,binary),b=new ServiceMachine(mapped,binary);
        try(PrintWriter log=new PrintWriter(Files.newBufferedWriter(out.resolve("results.tsv")))) {
            long[] words={0,1,0x7fffffffL,0x80000000L,MASK};
            for(long mode:new long[]{0,1,MASK}) {
                for(int divisor=1;divisor<=16;divisor++)for(long base:new long[]{0,0xffff,0xffffffa0L})delay(a,b,mode,1,1,base,0x80000010L+divisor-1,-1,log);
                for(int enabled:new int[]{0,1,255})for(int query:new int[]{0,255})for(long value:new long[]{0,15,0x80000000L})delay(a,b,mode,enabled,query,0x10000,value,-1,log);
                for(long base:new long[]{1,0xffff,0x10001})delay(a,b,mode,1,0,base,0x1f,-1,log);
                delay(a,b,mode,1,255,7,0x8000000fL,-1,log);
                delay(a,b,mode,0,255,0xffff,0x1f,-1,log);
                delay(a,b,mode,1,1,0x1234,0x10,mode==0 ? 0xfe84 : 0xff9c,log); // Addition wraps to zero after query mutation.
                delay(a,b,mode,1,1,0,0x1f,0xffff,log);
            }
            for(int kind=0;kind<3;kind++)for(long kernel:words)for(long service:words)
                direct(a,b,kind,words[directCases%5],0x1234567887654321L,17,kernel,service,7,0,false,false,false,log);
            for(long bytes:new long[]{0,1,0x0fffffff,0x10000000,0x7fffffffL,0x80000000L,MASK})
                direct(a,b,2,0x81234567L,-1,bytes,1,0,bytes,0,false,false,false,log);
            for(int nulls:new int[]{1,2,3,5,6,7})direct(a,b,0,7,0,17,0,0,0,nulls,false,false,false,log);
            for(long status:words)direct(a,b,0,0,Long.MIN_VALUE,17,0,status,3,0,true,false,false,log);
            direct(a,b,0,0,Long.MAX_VALUE,17,0,MASK,3,0,true,false,true,log);
            direct(a,b,0,7,1,17,0,1,3,4,true,false,false,log); // Null count is not checked by dispatch.
            direct(a,b,2,7,1,17,MASK,0,3,4,false,false,false,log); // Kernel failure never writes count.
            for(int kind=0;kind<2;kind++)direct(a,b,kind,0,0,17,0,0,0,0,false,true,false,log);
            for(boolean adapter:new boolean[]{false,true})for(long cursor:new long[]{0,0xffffffffL,0x100000000L,Long.MAX_VALUE,Long.MIN_VALUE,-1})
            for(long bytes:new long[]{0,1,17,128,0x80000000L,MASK})for(int scenario=0;scenario<(bytes==0 ? 1 : 8);scenario++)
                connected(a,b,adapter,FO|1,cursor,bytes<=128 ? DATA+7 : 0xfffffff8L,bytes,responses(bytes,scenario),bytes<=128,false,log);
            for(long count:new long[]{0x80000000L,MASK})for(boolean adapter:new boolean[]{false,true})
                connected(a,b,adapter,FO|1,Long.MAX_VALUE,0xfffffff8L,17,new long[][]{{1,count},{0,2},{1,0}},false,false,log);
            for(long handle:new long[]{0,1})connected(a,b,false,handle,0xffffffffL,DATA+7,17,new long[][]{{0xe0e046bcL,3}},true,false,log);
            connected(a,b,true,FO|1,0,0,17,new long[][]{{0xe0e046bcL,3}},false,false,log);
            for(long cursor:new long[]{0xffffffffL,Long.MAX_VALUE}) {
                connected(a,b,false,FO|1,cursor,DATA+7,17,new long[][]{{1,5},{0,0}},true,false,log);
                connected(a,b,true,FO|1,0,DATA+12,12,new long[][]{{0,3},{MASK,9}},true,true,log);
                connected(a,b,false,FO|1,0,DATA+15,9,new long[][]{{0,4},{1,5}},true,true,log);
                connected(a,b,true,FO|1,0,DATA+24,0,new long[][]{},true,true,log);sequences++;
            }
        }
        int sites=0;for(int k=0;k<4;k++)for(long pc=CHAIN[k];pc<LIMIT[k];pc+=4){require(visited.contains(pc),"Unvisited read chain site "+Long.toHexString(pc));sites++;}
        Files.writeString(out.resolve("comparison.json"),String.format(Locale.ROOT,
            "{\"direct_cases\":%d,\"delay_cases\":%d,\"connected_cases\":%d,\"persistent_sequences\":%d,\"new_instruction_sites\":%d,\"tls_reads_both\":%d,\"svc_requests_both\":%d,\"queries_both\":%d,\"sleeps_both\":%d,\"alternates_both\":%d,\"diagnostics_both\":%d,\"max_chain_steps\":%d,\"max_delay_steps\":%d,\"max_read_steps\":%d,\"tls_svc_sleep_diagnostics_modeled\":true,\"synthetic_file_vtable\":true,\"live_verified\":false}\n",
            directCases,delayCases,connectedCases,sequences,sites,tlsReads,requests,queries,sleeps,alternates,diagnostics,chainSteps,delaySteps,readSteps));
        println("SMT4_READ_SERVICE_COMPARE_OK");
    }
}
