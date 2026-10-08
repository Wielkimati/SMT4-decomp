// File-size dispatch/method/IPC, reusing the independent cache/seek oracle.
// @category SMT4
import ghidra.pcode.emu.PcodeThread;
import ghidra.pcode.utils.Utils;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.pcode.PcodeOp;
import java.nio.file.*;
import java.security.MessageDigest;
import java.util.*;
import java.io.*;

public class CompareResourceWorkerFileSize extends CompareResourceWorkerFilePosition {
    static final long[] CHAIN={0x2a8914,0x3dfca8,0x356de8,0x239cd0};
    static final long[] LIMIT={0x2a893c,0x3dfcc8,0x356e1c,0x239cf4};
    static final long TLS=0x920020,CMD=TLS+0x80,FB=0x921000,FO=FB+0x20,FH=FB+0x40,FV=FB+0x80,ALT=0x730100;
    long[] chain=new long[4];
    long connectedHandle=FO|1;
    int directCases,connectedCases,requests,tlsReads,alternates,handleDiagnostics,sequences;
    @Override long sizeServiceTarget(boolean path) { return path ? chain[0] : CHAIN[0]; }
    @Override boolean originalCode(long pc) {
        for(int k=0;k<CHAIN.length;k++) if(within(pc,4,CHAIN[k],LIMIT[k])) return true;
        return super.originalCode(pc);
    }
    class SizeMachine extends PositionMachine {
        long activeOutput, replacement=0x81234567L;
        int query;
        SizeMachine(byte[] mapped,byte[] binary) { super(mapped,binary); }
        @Override public void beforeStore(PcodeThread<byte[]> t,PcodeOp op,AddressSpace space,byte[] offset,int size,byte[] value) {
            long a=Utils.bytesToLong(offset,offset.length,false);
            if(within(a,size,CMD,CMD+4) || (activeOutput!=0 && within(a,size,activeOutput,activeOutput+8))) return;
            super.beforeStore(t,op,space,offset,size,value);
        }
        @Override public void beforeLoad(PcodeThread<byte[]> t,PcodeOp op,AddressSpace space,byte[] offset,int size) {
            long a=Utils.bytesToLong(offset,offset.length,false);
            if(within(a,size,CMD,CMD+16) || within(a,size,FO,FO+8) || within(a,size,FH,FH+4) || within(a,size,FV,FV+16)) return;
            super.beforeLoad(t,op,space,offset,size);
        }
        void seed(boolean path,long handle,boolean alternate) {
            byte[] tls=new byte[0x140]; new Random(0x356de8).nextBytes(tls); memory(TLS-32,tls);
            byte[] file=new byte[0x100];new Random(0x3dfca8).nextBytes(file);memory(FB,file);
            writeWord(FO,FV);writeWord(FO+4,handle);writeWord(FH,handle);
            writeWord(FV+8,alternate ? ALT : path ? chain[1] : CHAIN[1]);
            writeWord(FV+12,0x730104); // A wrong virtual slot cannot silently call the same body.
        }
        // The kernel response is independent from both executable implementations.
        // Preserve all command words except the chosen response words; do not normalize output.
        boolean executeChain(boolean path,int kind,long kernel,long service,long value,
                boolean invalid,boolean alternate,boolean terminal) throws Exception {
            long returnPc=register("lr"),sp=register("sp");
            long[] saved=new long[8];for(int r=4;r<=11;r++)saved[r-4]=register("r"+r);
            long out=kind==0 ? register("r0") : register("r1");activeOutput=out;
            byte[] tls=memory(TLS-32,0x140),file=memory(FB,0x100),output=out==0 ? null : memory(out,8);
            byte[] expectedTls=tls.clone(),expectedFile=file.clone(),expectedOutput=output==null ? null : output.clone();
            int calls=0,reads=0,diagnostics=0,alts=0,steps=0;boolean stopped=false;
            long handle=kind==2 ? get(FH) : get(FO+4);
            long expected=invalid ? 0xe0e046bcL : (kernel&0x80000000L)!=0 ? kernel : service;
            if(alternate && !invalid) expected=service;
            while(thread.getCounter().getOffset()!=returnPc) {
                long pc=thread.getCounter().getOffset();
                if(pc==0x2bbd70) {
                    require(!invalid && !alternate && kind!=2 && handle==0 && ++diagnostics==1,"Handle diagnostic predicate");
                    require(register("r0")==0xe0a046daL && register("r1")==0x239cec && (register("sp")&7)==0,"Handle diagnostic args");
                    require(Arrays.equals(memory(TLS-32,0x140),tls) && Arrays.equals(memory(FB,0x100),file),"Before diagnostic state");
                    handleDiagnostics++;trace.add("handle-diagnostic:"+terminal);
                    if(terminal) {stopped=true;break;}
                    handle=replacement;writeWord(FO+4,handle);put(expectedFile,0x24,handle);
                    externalReturn(0x98765432L);continue;
                }
                if(pc==ALT) {
                    require(alternate && !invalid && ++alts==1 && register("r0")==FO && register("r1")==out,"Alternate virtual dispatch");
                    writeWord(out,value&MASK);writeWord(out+4,value>>>32);pair(expectedOutput,0,value);
                    alternates++;trace.add("alternate:"+service+":"+value);externalReturn(service);continue;
                }
                require(path ? within(pc,4,BUILD,BUILD+codeSize) : originalCode(pc),"Size chain PC "+Long.toHexString(pc));
                if(!path)visited.add(pc);
                long ins=get(pc);
                if((ins&0xffff0fffL)==0xee1d0f70L) {
                    require((path || pc==0x356df0) && ++reads==1 && !invalid && !alternate,"TLS site/count");
                    require(Arrays.equals(memory(TLS-32,0x140),tls),"Command preserved before TLS");
                    register("r"+((ins>>>12)&15),TLS);tlsReads++;thread.overrideCounter(toAddr(pc+4));continue;
                }
                if(ins==0xef000032L) {
                    require((path || pc==0x356e00) && ++calls==1 && reads==1,"SVC site/count");
                    require(register("r0")==handle && (register("sp")&3)==0,"SVC captured handle/alignment");
                    put(expectedTls,0xa0,0x08040000);
                    require(Arrays.equals(memory(TLS-32,0x140),expectedTls),"Exact IPC header and preserved command memory");
                    require(Arrays.equals(memory(FB,0x100),expectedFile) && Arrays.equals(memory(out,8),output),"Before SVC input/output preservation");
                    // A modeled kernel failure may still alter response memory.
                    put(expectedTls,0xa4,service);pair(expectedTls,0xa8,value);put(expectedTls,0xb0,0xa5a55a5aL);
                    memory(TLS-32,expectedTls);
                    if((kernel&0x80000000L)==0) pair(expectedOutput,0,value);
                    requests++;trace.add("svc:"+handle+":"+kernel+":"+service+":"+value);
                    externalReturn(kernel);thread.overrideCounter(toAddr(pc+4));continue;
                }
                require(++steps<160,"Size chain budget");monitor.checkCancelled();thread.stepInstruction();
            }
            require(calls==(!invalid && !alternate && !stopped ? 1 : 0) && reads==calls,"Service path count");
            require(alts==(alternate && !invalid ? 1 : 0),"Virtual path count");
            require(diagnostics==(!invalid && !alternate && kind!=2 && word(file,0x24)==0 ? 1 : 0),"Handle diagnostic count");
            require(Arrays.equals(memory(TLS-32,0x140),expectedTls) && Arrays.equals(memory(FB,0x100),expectedFile),"Final TLS/file guards");
            if(out!=0)require(Arrays.equals(memory(out,8),expectedOutput),"Full size publication / failure preservation");
            if(!stopped) {
                require(register("r0")==expected,"Exact kernel/service/argument result");
                require(register("sp")==sp,"Size stack restoration");
                for(int r=4;r<=11;r++)require(register("r"+r)==saved[r-4],"Size saved register");
            }
            maxSteps=Math.max(maxSteps,steps);activeOutput=0;return !stopped;
        }
        @Override void executeSizeService(boolean path,long status,long value) throws Exception {
            // The parent oracle predicts logical service status/cache/cursor effects.
            // Alternate negative results between kernel failure and service failure.
            long kernel=(status&0x80000000L)!=0 && (query++&1)==0 ? status : 1;
            require(executeChain(path,0,kernel,status,value,register("r1")==0,false,false),"Connected return");
        }
        void probe(boolean path,int kind,long handle,long kernel,long service,long value,
                int nulls,boolean alternate,boolean terminal) throws Exception {
            initialize(path,0,new byte[0x144]);destroyed=false;trace.clear();seed(path,handle,alternate);
            byte[] guard=new byte[40];Arrays.fill(guard,(byte)0x5a);memory(SIZE-16,guard);
            register("r0",kind==0 ? (nulls&1)!=0 ? 0 : SIZE : kind==1 ? FO : FH);
            register("r1",kind==0 ? (nulls&2)!=0 ? 0 : FO : SIZE);
            thread.overrideCounter(toAddr(path ? chain[kind] : CHAIN[kind]));executing=true;
            boolean returned=executeChain(path,kind,kernel,service,value,nulls!=0,alternate,terminal);
            require(returned!=terminal,"Terminal diagnostic boundary");
            require(Arrays.equals(memory(SIZE-16,16),Arrays.copyOf(guard,16)) && Arrays.equals(memory(SIZE+8,16),Arrays.copyOf(guard,16)),"Direct output guards");
            for(byte v:memory(STACK-0x1000,0xf00))require(v==(byte)0x96,"Direct stack guards");
        }
    }
    void probePair(SizeMachine a,SizeMachine b,int kind,long handle,long kernel,long service,long value,
            int nulls,boolean alternate,boolean terminal,PrintWriter log) throws Exception {
        try {
            a.probe(false,kind,handle,kernel,service,value,nulls,alternate,terminal);
            b.probe(true,kind,handle,kernel,service,value,nulls,alternate,terminal);
            require(a.trace.equals(b.trace),"Direct trace agreement");
        } catch(Exception e) {throw new IllegalStateException("File size case direct="+directCases+" kind="+kind,e);}
        log.printf("direct\t%d\t%d\t%x\t%x\t%x\t%x\t%d\t%s\t%s%n",directCases++,kind,handle,kernel,service,value,nulls,alternate,terminal);
    }
    void connected(SizeMachine a,SizeMachine b,int kind,long cursor,long cache,long offset,long origin,
            long[] statuses,long[] values,boolean retain,PrintWriter log) throws Exception {
        try {
            if(!retain) {a.seed(false,0x81234567L,false);b.seed(true,0x81234567L,false);a.query=b.query=0;}
            a.direct(false,kind,connectedHandle,cursor,cache,offset,origin,statuses,values,retain);
            b.direct(true,kind,connectedHandle,cursor,cache,offset,origin,statuses,values,retain);
            require(a.trace.equals(b.trace),"Connected trace agreement");
            require(Arrays.equals(a.memory(TLS-32,0x140),b.memory(TLS-32,0x140)),"Connected command state agreement");
        } catch(Exception e) {throw new IllegalStateException("File size case connected="+connectedCases+" kind="+kind,e);}
        log.printf("connected\t%d\t%d\t%x\t%x\t%x\t%d\t%x\t%x\t%x\t%x\t%s%n",connectedCases++,kind,cursor,cache,offset,origin,statuses[0],values[0],statuses[1],values[1],retain);
    }
    @Override public void run() throws Exception {
        Path out=Path.of(getScriptArgs()[0]);
        byte[] mapped=new byte[0x377000];require(currentProgram.getMemory().getBytes(toAddr(0x100000),mapped)==mapped.length,"Map");
        require(HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(mapped)).equals("834938d18d2b7c688311c46c27bed813d0d7a9f8e3cbb61da8a6a3f23d360ebd"),"Reference hash");
        byte[] binary=Files.readAllBytes(out.resolve("size.bin"));codeSize=binary.length;
        var lines=Files.readAllLines(out.resolve("entries.txt"));
        for(int k=0;k<4;k++)chain[k]=Long.parseLong(lines.get(k));
        for(int k=0;k<3;k++)positionEntries[k]=Long.parseLong(lines.get(4+k));
        for(int k=0;k<2;k++)methodEntries[k]=Long.parseLong(lines.get(7+k));
        StringBuilder listing=new StringBuilder();
        for(int k=0;k<4;k++) {
            var f=getFunctionAt(toAddr(CHAIN[k]));require(f!=null && f.getBody().getNumAddresses()==LIMIT[k]-CHAIN[k] && f.getBody().getMaxAddress().getOffset()==LIMIT[k]-1,"Saved extent");
            listing.append(f.getEntryPoint()+" "+f.getBody()+"\n");
            for(var ins:currentProgram.getListing().getInstructions(f.getBody(),true))listing.append(ins.getAddress()+" "+ins+"\n");
        }
        require(word(mapped,0x3209a0)==CHAIN[1] && word(mapped,0x1a893c)==0xe0e046bcL && word(mapped,0x256e1c)==0x08040000,"Vtable and literal evidence");
        Files.writeString(out.resolve("original-size-ghidra.txt"),listing);
        SizeMachine a=new SizeMachine(mapped,binary),b=new SizeMachine(mapped,binary);
        try(PrintWriter log=new PrintWriter(Files.newBufferedWriter(out.resolve("results.tsv")))) {
            long[] words={0,1,0x7fffffffL,0x80000000L,MASK};
            long[] values={0,1,0x100000000L,0x1234567887654321L,Long.MIN_VALUE,-1};
            for(int kind=0;kind<3;kind++)for(long kernel:words)for(long service:words) {
                long value=values[directCases%values.length],handle=words[directCases%words.length];
                probePair(a,b,kind,handle,kernel,service,value,0,false,false,log);
            }
            // Explicit width extremes, independent from status combinations.
            for(long value:values)probePair(a,b,2,0x76543210,0,0,value,0,false,false,log);
            for(int nulls=1;nulls<=3;nulls++)probePair(a,b,0,7,MASK,1,-1,nulls,false,false,log);
            for(long service:words)probePair(a,b,0,0,0,service,0x1234567887654321L,0,true,false,log);
            for(int kind=0;kind<2;kind++)probePair(a,b,kind,0,0,0,1,0,false,true,log);
            long[] positions={0,1,0xffffffffL,0x100000000L,Long.MAX_VALUE,Long.MIN_VALUE,-1};
            for(int kind=0;kind<5;kind++)for(int i=0;i<positions.length;i++)for(int s=0;s<words.length;s++) {
                long[] origins=kind==1 || kind==4 ? new long[]{0,1,2,3,MASK} : new long[]{0};
                for(long origin:origins)connected(a,b,kind,positions[(i+1)%7],positions[(i+2)%7],positions[i],origin,
                    new long[]{words[s],words[(s+1)%5]},new long[]{positions[(i+3)%7],positions[(i+4)%7]},false,log);
            }
            // Null and tag-only lower handles reach the recovered argument failure,
            // clear stale caches, preserve cursor/output and never issue IPC.
            for(long handle:new long[]{0,1}) {
                connectedHandle=handle;
                for(int kind=0;kind<5;kind++)connected(a,b,kind,0x100000001L,1,2,2,
                    new long[]{0xe0e046bcL,0},new long[]{7,9},false,log);
            }
            connectedHandle=FO|1;
            // Persist cache, cursor and TLS across hit, equality, kernel/service failure,
            // recovery and end-relative second-query shrinkage/failure.
            for(long cursor:new long[]{0,0xffffffffL}) {
                connected(a,b,0,cursor,99,0,0,new long[]{0,0},new long[]{10,10},false,log);
                for(long[] step:new long[][]{{2,5,0,0,20,0,20},{2,10,0,0,20,0,20},
                    {2,20,0,MASK,30,0,30},{2,0,0,MASK,30,0,30},{0,0,0,1,7,0,7},
                    {1,0,2,0,7,MASK,8},{1,0,2,0,7,0,6},{1,-1,2,0,7,0,9},{1,0,3,0,100,0,100}})
                    connected(a,b,(int)step[0],0,0,step[1],step[2],new long[]{step[3],step[5]},new long[]{step[4],step[6]},true,log);
                sequences++;
            }
        }
        int sites=0;for(int k=0;k<3;k++)for(long pc=CHAIN[k];pc<LIMIT[k];pc+=4) {require(visited.contains(pc),"Unvisited size site");sites++;}
        for(long pc=CHAIN[3];pc<LIMIT[3];pc+=4)require(visited.contains(pc),"Unvisited accessor site");
        Files.writeString(out.resolve("comparison.json"),String.format(Locale.ROOT,
            "{\"direct_cases\":%d,\"connected_cases\":%d,\"persistent_sequences\":%d,\"new_instruction_sites\":%d,\"retained_accessor_sites\":9,\"tls_reads_both\":%d,\"svc_requests_both\":%d,\"alternate_dispatches_both\":%d,\"handle_diagnostics_both\":%d,\"max_chain_steps\":%d,\"max_position_steps\":%d,\"size_service_calls_both\":%d,\"tls_svc_diagnostics_modeled\":true,\"synthetic_file_object_vtable\":true,\"live_verified\":false}\n",
            directCases,connectedCases,sequences,sites,tlsReads,requests,alternates,handleDiagnostics,maxSteps,positionSteps,osCalls));
        println("SMT4_FILE_SIZE_COMPARE_OK");
    }
}
