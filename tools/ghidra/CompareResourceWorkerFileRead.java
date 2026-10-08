// Recovered read loop and worker adapter; explicit scripted OS read boundary.
// @category SMT4
import java.nio.file.*;
import java.util.*;
import java.io.*;

public class CompareResourceWorkerFileRead extends CompareResourceWorkerFilePosition {
    static final long READ=0x2bb864, READ_END=0x2bb8ec, OS_READ=0x2a4e54;
    long readEntry;
    long readServiceTarget(boolean path) { return OS_READ; }
    int readCases, readCalls, connectedReads, readSteps, readSequences;
    @Override boolean originalCode(long pc) { return within(pc,4,READ,READ_END) || super.originalCode(pc); }
    @Override long lowerTarget(boolean path,int kind) {
        return path && kind==2 ? readEntry : super.lowerTarget(path,kind);
    }
    @Override IoMachine makeMachine(byte[] mapped,byte[] binary) { return new ReadMachine(mapped,binary); }
    // Independent Java arithmetic oracle: cast each returned word to signed int
    // for the cursor; keep total, remaining and address modulo 2^32.
    class ReadPlan {
        byte[] object;
        long result=0,total=0;
        List<Long> buffers=new ArrayList<>(), remaining=new ArrayList<>(), cursors=new ArrayList<>();
        List<byte[]> objects=new ArrayList<>();
        ReadPlan(byte[] initial,long buffer,long bytes,long[][] responses) {
            object=initial.clone();
            while(bytes!=0) {
                int i=buffers.size(); require(i<responses.length,"Read oracle response exhaustion");
                buffers.add(buffer); remaining.add(bytes); cursors.add(pair(object,8)); objects.add(object.clone());
                long status=responses[i][0],count=responses[i][1];
                if((status&0x80000000L)!=0) { result=status; return; }
                total=(total+count)&MASK; pair(object,8,pair(object,8)+(int)count);
                if(count==bytes || count==0) return;
                buffer=(buffer+count)&MASK; bytes=(bytes-count)&MASK;
            }
        }
    }
    class ReadMachine extends PositionMachine {
        ReadMachine(byte[] mapped,byte[] binary) { super(mapped,binary); }
        @Override void modelReadPayload() {} // Payload now comes from each OS response.
        @Override void call(boolean path,byte[] initial,long open,long read,long handle,
                long length,long allocation,int profile,int effect) throws Exception {
            // A zero-length loop cannot observe the supplied negative OS status.
            super.call(path,initial,open,length==0 ? 0 : read,handle,length,allocation,profile,effect);
        }
        // Optional recovered service chain; default keeps the historical model.
        void executeReadService(boolean path,long status,long received,long cursor,
                long buffer,long remaining,long out,boolean payload) throws Exception {
            // On failure, odd statuses write poison and even statuses leave output alone.
            if((status&0x80000000L)==0 || (status&1)!=0) writeWord(out,received);
            if(payload && (status&0x80000000L)==0) {
                long address=buffer;
                require(received<=remaining && within(address,(int)received,DATA,DATA+1024),"Bounded OS payload domain");
                byte[] content=new byte[(int)received];
                for(int i=0;i<content.length;i++) content[i]=(byte)((cursor+i)*17+0x39);
                memory(address,content); System.arraycopy(content,0,expectedData,(int)(address-DBASE),content.length);
            }
            externalReturn(status);
        }
        void executeRead(boolean path,long countOut,long data,long bytes,long[][] responses,boolean payload) throws Exception {
            long savedSp=register("sp"),returnPc=register("lr"),oldCount=get(countOut);
            long[] saved=new long[8]; for(int r=4;r<=11;r++) saved[r-4]=register("r"+r);
            ReadPlan p=new ReadPlan(memory(OBJ,24),data,bytes,responses);
            int query=0,steps=0;
            while(thread.getCounter().getOffset()!=returnPc) {
                long pc=thread.getCounter().getOffset();
                if(pc==readServiceTarget(path)) {
                    require(query<p.buffers.size(),"Unexpected OS read call");
                    require(Arrays.equals(memory(OBJ,24),p.objects.get(query)),"Read cursor/cache before service");
                    long sp=register("sp"),out=register("r0"),cursor=register("r2")|(register("r3")<<32);
                    require(register("r1")== (word(p.object,4)&~1L),"Read untagged handle");
                    require(cursor==p.cursors.get(query),"Read service cursor");
                    require((sp&7)==0 && (out&3)==0 && within(out,4,sp+8,savedSp),"Read service stack/output layout");
                    require(get(sp)==p.buffers.get(query) && get(sp+4)==p.remaining.get(query),"Read buffer/remaining stack arguments");
                    long status=responses[query][0],received=responses[query][1];
                    trace.add("os-read:"+query+":"+register("r1")+":"+Long.toUnsignedString(cursor)+":"+get(sp)+":"+get(sp+4)+":"+status+":"+received);
                    executeReadService(path,status,received,cursor,get(sp),get(sp+4),out,payload);
                    query++; readCalls++; dependencyCalls++; continue;
                }
                require(path ? within(pc,4,BUILD,BUILD+codeSize) :
                    within(pc,4,READ,READ_END) || within(pc,4,METHODS[2],METHOD_END[2]),"Read PC "+Long.toHexString(pc));
                if(!path) visited.add(pc);
                require(++steps<512,"Read instruction budget"); monitor.checkCancelled(); thread.stepInstruction();
            }
            require(query==p.buffers.size(),"Read termination/call count");
            require(register("r0")==p.result,"Read exact status / success normalization");
            require(get(countOut)==((p.result&0x80000000L)==0 ? p.total : oldCount),"Read count output/failure preservation");
            require(Arrays.equals(memory(OBJ,24),p.object),"Read signed cursor/cache oracle");
            require(Arrays.equals(memory(DBASE,DLEN),expectedData),"Read payload/guards");
            require(register("sp")==savedSp,"Read stack restoration");
            for(int r=4;r<=11;r++) require(register("r"+r)==saved[r-4],"Read saved register");
            finalFileState=p.object; readSteps=Math.max(readSteps,steps);
            trace.add("read-end:"+p.result+":"+get(countOut)+":"+HexFormat.of().formatHex(p.object)+":"+HexFormat.of().formatHex(expectedData));
        }
        @Override boolean executeMethod(boolean path,int kind,long result,long lo,long hi,
                long origin,long count,long data,long size,boolean terminalFailure) throws Exception {
            if(kind!=2) return super.executeMethod(path,kind,result,lo,hi,origin,count,data,size,terminalFailure);
            long first=size>1 ? size/2 : 0;
            long[][] responses;
            if((result&0x80000000L)!=0) responses=cases%2==0 ? new long[][]{{result,0xdeadbeefL}} :
                new long[][]{{1,first==0 ? size : first},{result,0xdeadbeefL}};
            else responses=switch(cases%3) {
                case 0 -> new long[][]{{0x7fffffffL,size}};
                case 1 -> new long[][]{{1,first},{0,size-first}};
                default -> new long[][]{{0,first},{1,0}};
            };
            // With size one, a prior successful byte would finish before failure.
            if(size==1 && (result&0x80000000L)!=0) responses=new long[][]{{result,0xdeadbeefL}};
            executeRead(path,count,data,size,responses,true);
            writeWord(LOCK,0x81234567L); // Retained independent lock-interference fixture.
            connectedReads++; return true;
        }
        void directRead(boolean path,boolean adapter,long handle,long cursor,long buffer,long bytes,
                long[][] responses,boolean payload,boolean retain) throws Exception {
            initialize(path,0,new byte[0x144]); destroyed=false; trace.clear();
            if(!retain) {
                byte[] guard=new byte[OLEN]; new Random(READ).nextBytes(guard); memory(OBASE,guard);
                byte[] object=new byte[24]; put(object,0,0xa55a1234L); put(object,4,handle);
                pair(object,8,cursor); pair(object,16,0x87654321abcdef01L); memory(OBJ,object);
                expectedData=new byte[DLEN]; new Random(OS_READ).nextBytes(expectedData); memory(DBASE,expectedData);
            }
            byte[] guardBefore=memory(OBASE,OLEN),out=new byte[40]; Arrays.fill(out,(byte)0x5a); memory(SIZE-16,out);
            register("sp",STACK-16); writeWord(STACK-16,0xfedcba98L);
            register("r0",adapter ? OBJ : OBJ+4); register("r1",SIZE); register("r2",buffer); register("r3",bytes);
            thread.overrideCounter(toAddr(path ? (adapter ? methodEntries[2] : readEntry) : (adapter ? METHODS[2] : READ))); executing=true;
            executeRead(path,SIZE,buffer,bytes,responses,payload);
            System.arraycopy(finalFileState,0,guardBefore,(int)(OBJ-OBASE),24);
            require(Arrays.equals(memory(OBASE,OLEN),guardBefore),"Read object guards");
            put(out,16,get(SIZE)); require(Arrays.equals(memory(SIZE-16,40),out),"Read count output guards");
            for(byte value:memory(STACK-0x1000,0xf00)) require(value==(byte)0x96,"Read stack guard");
            require(get(STACK-16)==0xfedcba98L,"Read caller stack preservation");
        }
    }
    long[][] responses(long size,int scenario) {
        long part=size>1 ? size/2 : 0;
        return switch(scenario) {
            case 0 -> new long[][]{{0,size}};
            case 1 -> new long[][]{{0x7fffffffL,size}};
            case 2 -> new long[][]{{1,0}};
            case 3 -> new long[][]{{1,part},{0,size-part}};
            case 4 -> new long[][]{{0,part},{1,0}};
            case 5 -> new long[][]{{0x80000000L,0x87654321L}};
            case 6 -> new long[][]{{MASK,0xdeadbeefL}};
            default -> new long[][]{{0,part},{MASK,0xdeadbeefL}};
        };
    }
    void compareRead(ReadMachine a,ReadMachine b,boolean adapter,long cursor,long buffer,long bytes,
            long[][] responses,boolean payload,boolean retain,PrintWriter log) throws Exception {
        long handle=new long[]{0,1,0x80000000L,MASK,0x4561}[readCases%5];
        try {
            a.directRead(false,adapter,handle,cursor,buffer,bytes,responses,payload,retain);
            b.directRead(true,adapter,handle,cursor,buffer,bytes,responses,payload,retain);
            require(a.trace.equals(b.trace),"Read original/rebuilt service/state/payload trace");
        } catch(Exception e) { throw new IllegalStateException("Worker I/O case read="+readCases+" size="+bytes+" cursor="+cursor+" responses="+Arrays.deepToString(responses),e); }
        log.printf("%d\t%s\t%d\t%d\t%d\t%s\t%s\t%s%n",++readCases,adapter,cursor,buffer,bytes,Arrays.deepToString(responses),payload,retain);
    }
    @Override String extraChecks(byte[] mapped,byte[] binary,Path out) throws Exception {
        String inherited=super.extraChecks(mapped,binary,out);
        ReadMachine a=new ReadMachine(mapped,binary),b=new ReadMachine(mapped,binary);
        try(PrintWriter log=new PrintWriter(Files.newBufferedWriter(out.resolve("read-results.tsv")))) {
            log.println("case\tadapter\tcursor\tbuffer\tbytes\tresponses\tpayload\tretain");
            for(boolean adapter:new boolean[]{false,true})
            for(long cursor:new long[]{0,0xffffffffL,0x100000000L,Long.MAX_VALUE,Long.MIN_VALUE,-1})
            for(long size:new long[]{0,1,2,17,128,0x7fffffffL,0x80000000L,MASK})
            for(int scenario=0;scenario<(size==0 ? 1 : 8);scenario++) {
                boolean payload=size<=128;
                long buffer=payload ? DATA+7 : new long[]{0,1,0x7fffffffL,0x80000000L,MASK}[scenario%5];
                compareRead(a,b,adapter,cursor,buffer,size,responses(size,scenario),payload,false,log);
            }
            // Deliberately nonconforming OS counts: bounded termination exposes signed
            // extension, total wrap, address wrap and remaining underflow without huge writes.
            for(boolean adapter:new boolean[]{false,true}) for(long cursor:new long[]{0,0xffffffffL,Long.MIN_VALUE,-1})
            for(long count:new long[]{0x80000000L,MASK}) {
                compareRead(a,b,adapter,cursor,0xfffffff8L,17,new long[][]{{1,count},{0,2},{1,0}},false,false,log);
                compareRead(a,b,adapter,cursor,0xfffffff8L,17,new long[][]{{0,count},{0x80000000L,7}},false,false,log);
            }
            // Retain cursor/cache and destination bytes across success, failure and retry.
            for(long cursor:new long[]{0xffffffffL,Long.MAX_VALUE}) {
                compareRead(a,b,false,cursor,DATA+7,17,new long[][]{{1,5},{0,0}},true,false,log);
                compareRead(a,b,true,0,DATA+12,12,new long[][]{{0,3},{MASK,9}},true,true,log);
                compareRead(a,b,false,0,DATA+15,9,new long[][]{{0,4},{1,5}},true,true,log);
                compareRead(a,b,true,0,DATA+24,0,new long[][]{},true,true,log);
                readSequences++;
            }
        }
        StringBuilder listing=new StringBuilder(); int newVisited=0;
        var f=getFunctionAt(toAddr(READ)); require(f!=null && f.getBody().getMaxAddress().getOffset()==READ_END-1,"Read Ghidra extent");
        for(long pc=READ;pc<READ_END;pc+=4) {
            require(visited.contains(pc),"Unvisited read instruction "+Long.toHexString(pc)); newVisited++;
            var ins=currentProgram.getListing().getInstructionAt(toAddr(pc)); require(ins!=null,"Read instruction boundary");
            listing.append(String.format("%08x %s%n",pc,ins));
        }
        require(currentProgram.getMemory().getInt(toAddr(0x2bb8bc))==0xe0a34fcc,"Signed read count ADC instruction");
        Files.writeString(out.resolve("original-read-ghidra.txt"),listing);
        return inherited+String.format(Locale.ROOT,",\"direct_read_cases\":%d,\"persistent_read_sequences\":%d,\"connected_read_calls_both_paths\":%d,\"os_read_calls_both_paths\":%d,\"read_max_steps\":%d,\"new_read_instruction_addresses\":%d,\"read_loop_recovered\":true,\"os_read_service_modeled\":true",
            readCases,readSequences,connectedReads,readCalls,readSteps,newVisited);
    }
    @Override public void run() throws Exception {
        readEntry=Long.parseLong(Files.readAllLines(Path.of(getScriptArgs()[0]).resolve("entries.txt")).get(10));
        super.run();
    }
}
