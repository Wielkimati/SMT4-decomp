// Retained node passes, optionally inside the continuous recovered outer worker.
// @category SMT4
import ghidra.pcode.emu.PcodeThread;
import ghidra.pcode.utils.Utils;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.pcode.PcodeOp;
import java.nio.file.*;
import java.security.MessageDigest;
import java.util.*;
import java.io.*;

public class CompareResourceWorkerCompletion extends CompareResourceWorker {
    static final long PACKET=0x905000, HEAP=0x465120;
    static final long[] ORIGINAL_ENTRIES={BEGIN,0x155b30,0x19f990,0x14e634,0x2b0468,FREE};
    static final long[][] ADDED={{0x155b30,0x155bbc},{0x19f990,0x19f99c},
        {0x14e634,0x14e648},{0x2b0468,0x2b0478},{FREE,0x2c4424}};
    int scenarios, passes, completions, publications, releases, converted, ioExecutions;
    long ioEntry, ioCalls;
    boolean recoverIo;
    boolean recoverLoop;
    long loopEntry, nodeVisits, outerCalls, errorChecks;
    static final long WAIT=0x2c367c, RESET=0x138f5c, DELAY=0x2bb4f0;
    int ioVariant;
    static final long OBJ=0x903000, VT=0x903100, LOCK=0x465124, TABLE=0x420870;
    @Override boolean originalCode(long pc) {
        if(recoverLoop && (within(pc,4,0x113d58,0x113de8) || within(pc,4,0x114340,0x114370))) return true;
        if(super.originalCode(pc)) return true;
        if(recoverIo && (within(pc,4,0x113e80,0x114070) || within(pc,4,0x114098,0x114134))) return true;
        for(long[] range:ADDED) if(within(pc,4,range[0],range[1])) return true;
        return false;
    }
    class IntegratedMachine extends WorkerMachine {
        boolean rebuiltPath, packetFreed;
        int completionCount, publicationCount, releaseCount, convertCount, phase;
        long releasing, selected;
        IoSession io;
        List<Long> released=new ArrayList<>();
        List<Long> nodes=new ArrayList<>();
        List<String> outerEvents=new ArrayList<>();
        long activeNode, nodeReturn, descriptorNext;
        int totalSteps;
        IntegratedMachine(byte[] mapped,byte[] binary) { super(mapped,binary); }
        @Override public void beforeLoad(PcodeThread<byte[]> t,PcodeOp op,AddressSpace space,byte[] offset,int size) {
            long address=Utils.bytesToLong(offset,offset.length,false);
            if(recoverLoop && address==GLOBAL) require(size==1,"Stop byte width");
            if(recoverIo && within(address,size,OBJ,OBJ+0x200)) {
                require(io==null || !io.destroyed || !within(address,size,OBJ,OBJ+24),"Object read after destruction"); return;
            }
            if(within(address,size,PACKET,PACKET+24)) {
                require(!packetFreed,"Read after packet free"); return;
            }
            if(within(address,size,REG,REG+16)) return;
            super.beforeLoad(t,op,space,offset,size);
        }
        @Override public void beforeStore(PcodeThread<byte[]> t,PcodeOp op,AddressSpace space,byte[] offset,int size,byte[] value) {
            long address=Utils.bytesToLong(offset,offset.length,false);
            if(recoverIo && address==DESC && size==4) stateWrites.add(Utils.bytesToLong(value,4,false)&MASK);
            if(recoverIo && (within(address,size,OBJ,OBJ+24) || (address==GLOBAL+4 && size==4))) {
                require(io==null || !io.destroyed || !within(address,size,OBJ,OBJ+24),"Object write after destruction"); return;
            }
            if(within(address,size,REG+4,REG+12)) return;
            super.beforeStore(t,op,space,offset,size,value);
        }
        long entry(int index) { return rebuiltPath ? entries[index] : ORIGINAL_ENTRIES[index]; }
        byte[] descriptor() {
            byte[] bytes=memory(DESC,0x800);
            if(word(bytes,0x130)==entry(1)) put(bytes,0x130,ORIGINAL_ENTRIES[1]);
            return bytes;
        }
        byte[] packet() {
            byte[] bytes=memory(PACKET,24);
            if(word(bytes,4)==entry(2)) put(bytes,4,ORIGINAL_ENTRIES[2]);
            return bytes;
        }
        @Override void event(String name) {
            trace.add(name+":"+HexFormat.of().formatHex(descriptor())+":"+
                HexFormat.of().formatHex(packet())+":"+HexFormat.of().formatHex(memory(REG,16))+":"+
                HexFormat.of().formatHex(memory(GLOBAL,0x20))+":"+HexFormat.of().formatHex(memory(HEAP,0x40)));
        }
        void setup(boolean rebuilt,byte[] initial,byte[] globals,byte[] packet,byte[] registry,int profile) {
            rebuiltPath=rebuilt; packetFreed=false; completionCount=0; publicationCount=0;
            releaseCount=0; convertCount=0; phase=0; released.clear(); io=null; stateWrites.clear();
            init(rebuilt,initial,globals);
            nodes.clear(); outerEvents.clear(); activeNode=0; totalSteps=0;
            if(recoverLoop) {
                for(int r=4;r<=11;r++) register("r"+r,0x12340000L+r);
                register("sp",STACK);
                thread.overrideCounter(toAddr(rebuilt ? loopEntry : 0x113d58));
            }
            memory(PACKET,packet); memory(REG,registry); memory(HEAP,new byte[0x40]);
            writeWord(DESC+0x130,entry(1));
            if(get(PACKET+4)!=0) writeWord(PACKET+4,entry(2));
            writeWord(HEAP+4,0x45670000);
            if(profile==0) { writeWord(HEAP+0x24,0); writeWord(HEAP+0x34,MASK); }
            if(profile==1 || profile==3) { writeWord(HEAP+0x24,0xfffffff0L); writeWord(HEAP+0x34,32); }
            if(profile==2) { writeWord(HEAP+0x24,PACKET); writeWord(HEAP+0x28,DESC); }
        }
        // Lower fixtures mirror the standalone I/O checker, but all instructions
        // share this machine with completion and retained allocator/list state.
        class IoSession {
            byte[] initial;
            long open, read, handle, length, allocation, statePtr, pathPtr, returnPc;
            int profile, effect, adjustment, count, failure, successful, converted, cursor, measures, conversions;
            boolean closes, destroy, destroyed, started, done;
            List<Long> calls=new ArrayList<>(), expectedCalls;
            IoSession(byte[] source,long open,long read,long handle,long length,long allocation,int profile,int effect) {
                initial=source.clone(); this.open=open; this.read=read; this.handle=handle;
                this.length=length; this.allocation=allocation; this.profile=profile; this.effect=effect;
                byte[] obj=new byte[0x200]; Arrays.fill(obj,(byte)0xa6); memory(OBJ,obj);

                adjustment=effect%2==0 ? 0 : 20;
                writeWord(TABLE,VT); writeWord(TABLE+12,adjustment==0 ? VT+0x80 : 0xabcddcbaL);
                writeWord(VT-48,adjustment);
                for(long v:new long[]{VT,VT+0x80}) {
                    writeWord(v+4,0x730000); writeWord(v+12,0x730004);
                    writeWord(v+36,0x730008); writeWord(v+40,0x73000c);
                }
                count=new int[]{0,1,4,2,4,120}[profile];
                failure=profile==3 ? 0 : profile==4 ? 2 : -1;
                expectedCalls=new ArrayList<>(List.of(0x2c244cL,0x2b9486L));
                successful=failure>=0 ? failure : count;
                for(int i=0;i<successful;i++) expectedCalls.addAll(List.of(0x2b9468L,0x2c63dcL));
                expectedCalls.add(0x2b9468L);
                if(failure>=0) expectedCalls.add(0x2c63dcL);
                expectedCalls.addAll(List.of(0x2bb944L,0x730008L,0x730004L));
                if(word(initial,12)==0) expectedCalls.add(0x2bf7ecL);
                expectedCalls.addAll(List.of(0x2c3afcL,0x73000cL,0x2c3a78L));
                closes=(handle & ~1L)!=0;
                if(closes) {
                    if((handle&1)!=0) expectedCalls.add(0x2bce9cL);
                    expectedCalls.add(0x2b9450L);
                }
                destroy=!(effect==3 && closes);
                if(destroy) expectedCalls.add(0x730000L);

            }
            boolean handle(long pc) {
                long result=0;
                if(rebuiltPath) {
                    if(pc==0x710000) pc=0x2b9486;
                    else if(pc==0x710004) pc=0x2b9468;
                    else if(pc==0x710008) pc=0x2c63dc;
                }
                boolean ext=true;
                if(pc==0x2c244c) { require(register("r0")==24,"Object allocation size"); result=OBJ; }
                else if(pc==0x2b9486) {
                    byte[] expected=new byte[24]; put(expected,0,adjustment==0 ? VT+0x80 : VT);
                    if(adjustment!=0) put(expected,adjustment,0xabcddcbaL);
                    require(Arrays.equals(expected,memory(OBJ,24)) && get(DESC+0x12c)==OBJ,"Object construction oracle");
                    statePtr=register("r0"); require(get(statePtr)==0 && get(statePtr+4)==0,"Initial conversion state");
                    writeWord(statePtr,0xfeed1234L); writeWord(statePtr+4,0x98760000L);
                } else if(pc==0x2b9468) {
                    require(register("r0")==DESC+0x2c+cursor && register("r1")==0x105 && register("r2")==statePtr,"Measure arguments");
                    require(get(statePtr)==0xfeed1234L+converted && get(statePtr+4)==0x98760000L+converted,"Conversion state continuity");
                    result=converted==count ? 0 : 1+converted%3; measures++;
                } else if(pc==0x2c63dc) {
                    if(conversions==0) pathPtr=register("r0");
                    require(register("r0")==pathPtr+2*converted && register("r1")==DESC+0x2c+cursor &&
                        register("r2")==1+converted%3 && register("r3")==statePtr,"Convert arguments");
                    require(within(pathPtr,2*(successful+1),register("sp"),STACK-16),"Path scratch bounds");
                    int ch=0x8100+converted;
                    memory(register("r0"),new byte[]{(byte)ch,(byte)(ch>>8)});
                    conversions++;
                    if(converted!=failure) {
                        result=converted%2==0 ? 1 : MASK; cursor+=1+converted%3; converted++;
                        writeWord(statePtr,0xfeed1234L+converted); writeWord(statePtr+4,0x98760000L+converted);
                    }
                } else if(pc==0x2bb944) {
                    require(register("r0")==OBJ+4 && register("r2")==1,"Open arguments");
                    if(pathPtr==0) pathPtr=register("r1");
                    require(register("r1")==pathPtr,"Open path pointer");
                    byte[] expected=new byte[2*(successful+1)];
                    for(int i=0;i<successful;i++) { expected[2*i]=(byte)i; expected[2*i+1]=(byte)0x81; }
                    require(Arrays.equals(expected,memory(pathPtr,expected.length)),"Converted path/terminator oracle");
                    for(int off=4;off<24;off+=4) require(get(OBJ+off)==0,"Open object reset");
                    writeWord(OBJ+4,handle); result=open;
                } else if(pc==0x730008) { require(register("r0")==OBJ,"Size receiver"); result=length; }
                else if(pc==0x730004) {
                    require(register("r0")==OBJ && register("r2")==0 && register("r3")==0 && get(register("sp"))==0,"Seek arguments");
                } else if(pc==0x2bf7ec) {
                    long flags=word(initial,36);
                    require(register("r0")==((flags==1 || flags==17) ? 0x10000 : 0x100) &&
                        register("r1")==0x100 && register("r2")==0 && register("r3")==length,"Data allocation registers");
                    require(get(register("sp"))==word(initial,40) && get(register("sp")+4)==((flags==16 || flags==17) ? 0 : 1),"Data allocation stack arguments");
                    result=allocation;
                } else if(pc==0x2c3afc || pc==0x2c3a78) {
                    require(register("r0")==get(LOCK),"I/O lock handle reload");
                    require(get(GLOBAL+4)==(pc==0x2c3afc ? 0x1234 : 0),"Busy flag at lock boundary");
                    writeWord(LOCK,(get(LOCK)+0x101)&MASK);
                } else if(pc==0x73000c) {
                    long data=word(initial,12)==0 ? allocation : word(initial,12);
                    require(register("r0")==OBJ && register("r2")==data && register("r3")==length && get(GLOBAL+4)==1,"Read arguments and busy flag");
                    require(within(register("r1"),4,register("sp"),STACK-16),"Read count out pointer");
                    writeWord(register("r1"),length^MASK); writeWord(LOCK,0x81234567L); result=read;
                } else if(pc==0x2bce9c) {
                    require(register("r0")==handle,"Preclose handle");
                    if(effect==2) writeWord(OBJ+4,0x81234561L);
                } else if(pc==0x2b9450) {
                    long expected=effect==2 && (handle&1)!=0 ? 0x81234560L : handle&~1L;
                    require(register("r0")==expected,"Close handle reload/mask");
                    if(effect==3) writeWord(DESC+0x12c,0);
                } else if(pc==0x730000) {
                    require(register("r0")==OBJ && get(GLOBAL+4)==0,"Destructor receiver/busy");
                    destroyed=true;
                } else ext=false;
                if(ext) {
                    require((register("sp")&7)==0,"Lower call alignment");
                    calls.add(pc); ioCalls++; event("io-lower:"+pc+":"+HexFormat.of().formatHex(memory(OBJ,24))); externalReturn(result); return true;
                }

                return false;
            }
            void check() {
                require(calls.equals(expectedCalls),"I/O dependency sequence");
                require(converted==successful && measures==successful+1 && conversions==successful+(failure>=0 ? 1 : 0),"Conversion count");
                List<Long> expectedStates=new ArrayList<>();
                if((open&0x80000000L)!=0) expectedStates.add(5L);
                if((read&0x80000000L)!=0) expectedStates.add(5L);
                require(stateWrites.equals(expectedStates),"State write sequence");
                byte[] expected=initial.clone();
                if(!expectedStates.isEmpty()) put(expected,0,5);
                put(expected,12,word(initial,12)==0 ? allocation : word(initial,12));
                put(expected,24,length); put(expected,0x12c,destroy ? OBJ : 0);
                require(Arrays.equals(expected,descriptor()),"Final descriptor oracle");
                byte[] expectedObj=new byte[24]; put(expectedObj,0,adjustment==0 ? VT+0x80 : VT);
                put(expectedObj,4,closes ? 0 : handle);
                require(Arrays.equals(expectedObj,memory(OBJ,24)),"Final object oracle");
                require(destroyed==destroy && get(GLOBAL+4)==0 && get(LOCK)==0x81234668L,"Final lower state");

            }
        }
        boolean accepts(long address) {
            for(int offset:new int[]{0x24,0x28}) {
                long start=get(HEAP+offset), end=start+get(HEAP+offset+16);
                if(end<=MASK && address>=start && address<=end) return true;
            }
            return false;
        }
        long onePass(int mode,int profile,boolean first) throws Exception {
            require(recoverLoop || !freed,"Cannot schedule freed descriptor");
            byte[] initial=memory(DESC,0x800),globals=memory(GLOBAL,0x20);
            if(!recoverLoop) init(rebuiltPath,initial,globals);
            nodes.clear();
            int steps=0;
            while(recoverLoop || thread.getCounter().getOffset()!=(rebuiltPath ? RETURN : BOUNDARY)) {
                long pc=thread.getCounter().getOffset();
                if(recoverLoop) {
                    if(activeNode!=0 && pc==nodeReturn) {
                        if(activeNode==DESC) descriptorNext=register(rebuiltPath ? "r0" : "r7");
                        activeNode=0;
                    }
                    if(pc==(rebuiltPath ? entries[0] : BEGIN)) {
                        require(activeNode==0,"Nested node");
                        activeNode=register(rebuiltPath ? "r0" : "r7");
                        require(activeNode==PREV || activeNode==NEXT || (activeNode==DESC && !freed),"Live traversal node");
                        nodeReturn=rebuiltPath ? register("lr") : BOUNDARY;
                        require((register("sp")&7)==0,"Node boundary alignment");
                        nodes.add(activeNode); nodeVisits++; event("node:"+activeNode);
                    }
                    if(pc==WAIT || pc==RESET || pc==DELAY) {
                        outerCall(pc);
                        if(pc==RESET) break;
                        continue;
                    }
                    require(pc!=RETURN,"Premature outer worker return");
                }
                if(recoverIo && first && mode==0) {
                    if(pc==(rebuiltPath ? ioEntry : 0x113e80)) {
                        require(io!=null && !io.started,"I/O execution once");
                        if(rebuiltPath) require(register("r0")==DESC,"I/O descriptor argument");
                        io.started=true; io.returnPc=rebuiltPath ? register("lr") : 0x114070;
                        ioExecutions++; event("io");
                    }
                    if(io.started && !io.done && pc==io.returnPc) { io.check(); io.done=true; }
                    if(io.started && !io.done && io.handle(pc)) continue;
                }
                if(pc==entry(1)) {
                    require(first && !packetFreed && ++completionCount==1 && register("r0")==PACKET,"Completion dispatch/lifetime");
                    event("completion");
                }
                if(pc==entry(2)) {
                    require(++publicationCount==1 && register("r1")==REG,"Registry callback context/count");
                    long data=mode==2 ? 0 : get(DESC+12), size=mode==2 ? 0 : get(DESC+24);
                    require(register("r0")==data && register("r2")==size,"Publication arguments");
                    require(get(PACKET+20)==0 || get(REG+4)==data,"Output precedes callback");
                    require(get(DESC+8)==0,"Publication precedes cleanup mark");
                    event("publication");
                }
                if(pc==entry(5)) {
                    require(phase==0,"Nested allocator routing");
                    releasing=register("r0"); releaseCount++; phase=1;
                    require(releasing==PACKET || releasing==DESC || releasing==get(DESC+12),"Release identity");
                    if(releasing==PACKET) require(!packetFreed && get(DESC+8)==1,"Packet released after cleanup mark");
                    if(releasing==DESC) require(get(DESC+12)==0,"Data cleared before descriptor free");
                    event("release:"+releasing);
                }
                if(pc==ACQUIRE || pc==UNLOCK) { lockCall(pc,recoverLoop && profile==3 ? 3 : 0); continue; }
                if(recoverLoop && pc==CHECK) {
                    require(profile==3 && register("r0")==0x80000042L && register("r1")==1,"Returning synchronization checker");
                    require((register("sp")&7)==0,"Checker stack alignment");
                    errorChecks++; event("check"); externalReturn(0xf1234567L); continue;
                }
                if(pc==PRE) {
                    require(first && mode==2 && register("r0")==DESC+0x2c,"Path callback");
                    event("path-callback"); writeWord(DESC,5); externalReturn(0); continue;
                }
                if(!recoverIo && pc==(rebuiltPath ? IO : 0x113e80)) {
                    require(first && mode==0,"I/O block selection");
                    if(rebuiltPath) require(register("r0")==DESC,"I/O argument");
                    event("io"); writeWord(DESC,5); writeWord(DESC+0x12c,0x903000);
                    if(rebuiltPath) externalReturn(0); else thread.overrideCounter(toAddr(0x114070));
                    continue;
                }
                if(pc==0x2c3afc || pc==0x2c3a78 || pc==0x1245f0 || pc==0x1244e8) {
                    require((register("sp")&7)==0,"Allocator stack alignment");
                    long result=0;
                    if(pc==0x2c3afc) {
                        require(phase==1 && register("r0")==get(HEAP+4),"Heap acquire");
                        event("heap-acquire");
                        if(profile==3) {
                            writeWord(HEAP+0x24,0); writeWord(HEAP+0x34,releaseCount%2==0 ? MASK : 0);
                        }
                        selected=accepts(releasing) ? releasing : (releasing^0x80000000L);
                        phase=selected==releasing ? 3 : 2;
                    } else if(pc==0x1245f0) {
                        require(phase==2 && register("r0")==releasing,"Conversion selection");
                        event("convert:"+releasing); result=selected; phase=3; convertCount++;
                    } else if(pc==0x1244e8) {
                        require(phase==3 && register("r0")==selected,"Lower free selection");
                        event("heap-free:"+selected); released.add(releasing); phase=4;
                        if(releasing==PACKET) packetFreed=true;
                        if(releasing==DESC) freed=true;
                        writeWord(HEAP+4,(get(HEAP+4)+7)&MASK);
                        writeWord(GLOBAL+16,(get(GLOBAL+16)+11)&MASK);
                    } else {
                        require(phase==4 && register("r0")==get(HEAP+4),"Heap release handle reload");
                        event("heap-release"); phase=0;
                    }
                    dependencyCalls++; externalReturn(result); continue;
                }
                if(recoverIo) {
                    require(rebuiltPath ? within(pc,4,BUILD,BUILD+codeSize) : originalCode(pc),"Unexpected PC "+Long.toHexString(pc));
                    if(!rebuiltPath) visited.add(pc);
                    require(++steps<=6000,"Integrated instruction budget"); monitor.checkCancelled(); thread.stepInstruction();
                } else step(rebuiltPath,++steps);
            }
            require(phase==0,"Incomplete allocator call");
            if(recoverLoop) {
                require(activeNode==0,"Node returned before reset");
                totalSteps+=steps; maxSteps=Math.max(maxSteps,totalSteps);
            } else if(rebuiltPath) finish(steps);
            else { require(register("sp")==STACK-0x300,"Region SP"); maxSteps=Math.max(maxSteps,steps); }
            for(byte value:memory(STACK-0x1000,0x800)) require(value==(byte)0x96,"Stack guard");
            return recoverLoop ? descriptorNext : register(rebuiltPath ? "r0" : "r7");
        }
        void outerCall(long pc) {
            require((register("sp")&7)==0,"Outer lower alignment");
            String name=pc==WAIT ? "wait" : pc==RESET ? "reset" : "delay";
            if(pc==DELAY) require(register("r0")==3000000 && register("r1")==0,"Outer delay argument");
            else require(register("r0")==GLOBAL+0x24,"Outer event argument");
            outerEvents.add(name); outerCalls++; event(name); externalReturn(0);
        }
        void stopWorker(int rounds) throws Exception {
            int steps=0;
            while(thread.getCounter().getOffset()!=RETURN) {
                long pc=thread.getCounter().getOffset();
                if(pc==DELAY || pc==WAIT) {
                    outerCall(pc);
                    if(pc==WAIT) memory(GLOBAL,new byte[]{(byte)0x80});
                    continue;
                }
                require(rebuiltPath ? within(pc,4,BUILD,BUILD+codeSize) : originalCode(pc),"Stop instruction escape");
                if(!rebuiltPath) visited.add(pc);
                require(++steps<100,"Stop instruction budget"); thread.stepInstruction();
            }
            finish(totalSteps+steps);
            List<String> expected=new ArrayList<>();
            for(int i=0;i<rounds;i++) expected.addAll(List.of("wait","reset","delay"));
            expected.add("wait");
            require(outerEvents.equals(expected),"Outer event sequence");
            for(byte value:memory(STACK-0x1000,0x800)) require(value==(byte)0x96,"Final stack guard");
        }
    }
    void scenario(IntegratedMachine a,IntegratedMachine b,int links,int mode,long data,int owned,int refs,int outputs,int profile,Random rng,PrintWriter log) throws Exception {
        try {
            byte[] initial=new byte[0x800], globals=new byte[0x20],packet=new byte[24],registry=new byte[16];
            rng.nextBytes(initial); rng.nextBytes(globals); rng.nextBytes(packet); rng.nextBytes(registry);
            put(initial,0,mode==0 ? 0 : mode==1 ? 3 : 1); put(initial,4,refs); put(initial,8,0);
            put(initial,12,data); put(initial,16,owned); put(initial,24,0x87654321L);
            put(initial,0x130,ORIGINAL_ENTRIES[1]); put(initial,0x134,PACKET); put(initial,0x138,mode==2 ? PRE : 0);
            long prev=(links&1)==0 ? 0 : PREV, next=(links&2)==0 ? 0 : NEXT;
            put(initial,0x140,prev); put(initial,0x13c,next);
            put(initial,0x200+0x13c,DESC); put(initial,0x400+0x140,DESC);
            put(globals,12,prev==0 ? DESC : PREV);
            if(recoverLoop) {
                globals[0]=0;
                for(int offset:new int[]{0x200,0x400}) {
                    put(initial,offset,1); put(initial,offset+0x130,0); put(initial,offset+0x138,0);
                }
                put(initial,0x200+0x140,0); put(initial,0x400+0x13c,0);
            }
            if(recoverIo && mode==0) {
                put(globals,4,0x1234);
                put(initial,36,new long[]{0,1,16,17,2,0x101,0x80000011L,MASK}[(outputs+3*owned+(refs==4 ? 4 : 0))%8]);
            }
            put(packet,0,DESC); put(packet,4,outputs==1 ? 0 : ORIGINAL_ENTRIES[2]);
            put(packet,8,REG); put(packet,20,outputs==2 ? 0 : REG+4);
            a.setup(false,initial,globals,packet,registry,profile); b.setup(true,initial,globals,packet,registry,profile);
            long publishedData=data, publishedSize=0x87654321L;
            if(recoverIo && mode==0) {
                long open=(profile&1)==0 ? 0 : 0x80000001L, read=(profile&2)==0 ? 0 : MASK;
                long handle=new long[]{0,1,0x4560,0x4561,0x80000000L,MASK}[outputs+3*owned];
                long length=new long[]{0,1,0x80000000L,MASK,0x321}[(links+refs)%5];
                long allocation=new long[]{0,0x904000,0x81234560L}[profile%3];
                a.io=a.new IoSession(initial,open,read,handle,length,allocation,ioVariant,links);
                b.io=b.new IoSession(initial,open,read,handle,length,allocation,ioVariant,links);
                publishedData=data==0 ? allocation : data; publishedSize=length;
            }
            byte[] expected=initial.clone(), expectedRegistry=registry.clone();
            if(recoverIo && mode==0) put(expected,24,publishedSize);
            put(expected,0,mode==2 ? 5 : 4); put(expected,8,1); put(expected,0x138,0);
            if(mode==0) put(expected,0x12c,0);
            if(mode!=2) put(expected,12,0);
            put(expectedRegistry,4,mode==2 ? 0 : publishedData);
            if(outputs!=1) put(expectedRegistry,8,mode==2 ? 0 : publishedSize);
            for(int pass=0;pass<=refs+(recoverLoop ? 1 : 0);pass++) {
                long x=a.onePass(mode,profile,pass==0),y=b.onePass(mode,profile,pass==0);
                require(x==next && y==next,"Next link oracle");
                require(a.trace.equals(b.trace),"Dependency order/snapshot comparison");
                if(pass>0) put(expected,4,Math.max(0,refs-pass));
                if(pass>=refs) {
                    put(expected,12,0);
                    if(prev!=0) put(expected,0x200+0x13c,next);
                    if(next!=0) put(expected,0x400+0x140,prev);
                }
                require(Arrays.equals(expected,a.descriptor()) && Arrays.equals(expected,b.descriptor()),"Descriptor/neighbor oracle pass="+pass);
                require(Arrays.equals(packet,a.packet()) && Arrays.equals(packet,b.packet()),"Packet preservation");
                require(Arrays.equals(expectedRegistry,a.memory(REG,16)) && Arrays.equals(expectedRegistry,b.memory(REG,16)),"Registry oracle");
                require(Arrays.equals(a.memory(GLOBAL,0x20),b.memory(GLOBAL,0x20)),"Worker globals comparison");
                require(Arrays.equals(a.memory(HEAP,0x40),b.memory(HEAP,0x40)),"Allocator state comparison");
                long head=prev==0 ? pass>=refs ? next : DESC : PREV;
                require(a.get(GLOBAL+12)==head && b.get(GLOBAL+12)==head,"List head oracle");
                byte[] actualGlobals=a.memory(GLOBAL,0x20);
                if(recoverIo && mode==0) {
                    require(word(actualGlobals,4)==0,"Busy clear through retained passes");
                    put(actualGlobals,4,word(globals,4));
                    List<Long> expectedStates=new ArrayList<>();
                    if((profile&1)!=0) expectedStates.add(5L);
                    if((profile&2)!=0) expectedStates.add(5L);
                    List<Long> originalStates=new ArrayList<>(expectedStates);
                    originalStates.addAll(List.of(3L,4L));
                    // GCC removes the intermediate state-three store with no intervening call.
                    // Check each instruction trace explicitly; concurrent observation is unclaimed.
                    expectedStates.add(4L);
                    require(a.stateWrites.equals(originalStates) && b.stateWrites.equals(expectedStates),"Integrated state-store oracle");
                    require(a.io.done && b.io.done,"I/O boundary reached");
                }
                put(actualGlobals,12,word(globals,12)); put(actualGlobals,16,word(globals,16));
                require(Arrays.equals(actualGlobals,globals),"Opaque globals preservation");
                require(a.freed==(pass>=refs) && b.freed==(pass>=refs),"Descriptor lifetime");
                require(a.packetFreed && b.packetFreed,"Packet lifetime");
                List<Long> expectedFree=new ArrayList<>(List.of(PACKET));
                if(pass>=refs) {
                    if(mode==2 && owned==0 && data!=0) expectedFree.add(data);
                    expectedFree.add(DESC);
                }
                require(a.released.equals(expectedFree) && b.released.equals(expectedFree),"Ownership/release sequence");
                if(recoverLoop) {
                    List<Long> expectedNodes=new ArrayList<>();
                    if(prev!=0) expectedNodes.add(prev);
                    if(pass<=refs) expectedNodes.add(DESC);
                    if(next!=0) expectedNodes.add(next);
                    require(a.nodes.equals(expectedNodes) && b.nodes.equals(expectedNodes),"Retained list traversal oracle");
                }
                passes++;
            }
            if(recoverLoop) {
                a.stopWorker(refs+2); b.stopWorker(refs+2);
                require(a.trace.equals(b.trace),"Final continuous trace comparison");
                require(Arrays.equals(a.memory(GLOBAL,0x20),b.memory(GLOBAL,0x20)),"Final stop state");
            }
            require(a.completionCount==1 && b.completionCount==1,"One completion across retained passes");
            require(a.publicationCount==(outputs==1 ? 0 : 1) && a.publicationCount==b.publicationCount,"Publication count");
            completions+=a.completionCount+b.completionCount; publications+=a.publicationCount+b.publicationCount;
            releases+=a.releaseCount+b.releaseCount; converted+=a.convertCount+b.convertCount;
        } catch(Exception ex) { throw new IllegalStateException("Worker completion scenario "+scenarios+" links="+links+" mode="+mode+" data="+data+" owned="+owned+" refs="+refs+" outputs="+outputs+" profile="+profile+" ioVariant="+ioVariant,ex); }
        log.printf("%d\t%d\t%d\t%d\t%d\t%d\t%d\t%d\t%d%n",++scenarios,links,mode,data,owned,refs,outputs,profile,ioVariant);
    }
    @Override public void run() throws Exception {
        recoverIo=getScriptArgs().length>1 && Boolean.parseBoolean(getScriptArgs()[1]);
        recoverLoop=getScriptArgs().length>2 && Boolean.parseBoolean(getScriptArgs()[2]);
        Path out=Path.of(getScriptArgs()[0]); require(!Files.exists(out.resolve("comparison.json")),"Output exists");
        byte[] mapped=new byte[0x377000];
        require(currentProgram.getMemory().getBytes(toAddr(0x100000),mapped)==mapped.length,"Map");
        require(HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(mapped)).equals(
            "834938d18d2b7c688311c46c27bed813d0d7a9f8e3cbb61da8a6a3f23d360ebd"),"Reference hash");
        byte[] binary=Files.readAllBytes(out.resolve("worker-completion.bin")); codeSize=binary.length;
        require(codeSize>0 && codeSize<=0x2000,"Binary size");
        List<String> lines=Files.readAllLines(out.resolve("entries.txt"));
        for(int i=0;i<6;i++) entries[i]=Long.parseLong(lines.get(i));
        if(recoverIo) ioEntry=Long.parseLong(lines.get(6));
        if(recoverLoop) loopEntry=Long.parseLong(lines.get(7));
        IntegratedMachine a=new IntegratedMachine(mapped,binary),b=new IntegratedMachine(mapped,binary);
        Random rng=new Random(0x155b30);
        try(PrintWriter log=new PrintWriter(Files.newBufferedWriter(out.resolve("scenarios.tsv")))) {
            log.println("scenario\tlinks\tmode\tdata\towned\trefs\toutputs\tprofile\tio_variant");
            for(int links=0;links<4;links++) for(int mode=0;mode<3;mode++)
            for(long data:new long[]{0,0x904000,0x80004000L}) for(int owned=0;owned<2;owned++)
            for(int refs:new int[]{1,4}) for(int outputs=0;outputs<3;outputs++) for(int profile=0;profile<4;profile++)
                for(ioVariant=0;ioVariant<(recoverIo && mode==0 ? 6 : 1);ioVariant++)
                    scenario(a,b,links,mode,data,owned,refs,outputs,profile,rng,log);
        }
        for(long[] range:ADDED) for(long pc=range[0];pc<range[1];pc+=4)
            require(visited.contains(pc),"Unvisited integrated instruction "+Long.toHexString(pc));
        if(recoverIo) for(long[] range:new long[][]{{0x113e80,0x114070},{0x114098,0x114134}})
            for(long pc=range[0];pc<range[1];pc+=4) require(visited.contains(pc),"Unvisited I/O instruction "+Long.toHexString(pc));
        if(recoverLoop) for(long[] range:new long[][]{{0x113d58,0x113e70},{0x113e80,0x1142e8},{0x114340,0x114370}})
            for(long pc=range[0];pc<range[1];pc+=4) require(visited.contains(pc),"Unvisited worker instruction "+Long.toHexString(pc));
        StringBuilder listing=new StringBuilder();
        for(long pc:visited) {
            var instruction=currentProgram.getListing().getInstructionAt(toAddr(pc));
            require(instruction!=null,"Missing Ghidra instruction");
            listing.append(String.format("%08x %s%n",pc,instruction));
        }
        Files.writeString(out.resolve("original-executed-ghidra.txt"),listing);
        Files.writeString(out.resolve("original-addresses.txt"),visited.toString());
        Files.writeString(out.resolve("comparison.json"),String.format(Locale.ROOT,
            "{\"scenarios\":%d,\"worker_passes\":%d,\"completions_both_paths\":%d,\"publications_both_paths\":%d,\"releases_both_paths\":%d,\"converted_both_paths\":%d,\"lower_allocator_calls\":%d,\"original_instruction_addresses\":%d,\"binary_bytes\":%d,\"max_steps\":%d,\"full_worker_recovered\":false,\"state0_io_modeled\":%s,\"io_executions_both_paths\":%d,\"lower_io_calls_both_paths\":%d,\"live_verified\":false}\n",
            scenarios,passes,completions,publications,releases,converted,dependencyCalls,visited.size(),codeSize,maxSteps,!recoverIo,ioExecutions,ioCalls));
        if(recoverLoop) {
            require(nodeVisits==73728 && outerCalls==133632 && errorChecks>0,"Continuous traversal/call corpus totals");
            Path report=out.resolve("comparison.json");
            String json=Files.readString(report).trim();
            Files.writeString(report,json.substring(0,json.length()-1)+String.format(Locale.ROOT,
                ",\"outer_loop_recovered\":true,\"node_visits_both_paths\":%d,\"outer_calls_both_paths\":%d,\"returning_error_checks_both_paths\":%d}\n",nodeVisits,outerCalls,errorChecks));
        }
        println("SMT4_WORKER_COMPLETION_OK");
    }
}
