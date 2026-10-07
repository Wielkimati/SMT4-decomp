// Submission and worker execute on the same retained machine; only lower calls are models.
// @category SMT4
import ghidra.pcode.emu.PcodeThread;
import ghidra.pcode.utils.Utils;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.pcode.PcodeOp;
import java.nio.file.*;
import java.security.MessageDigest;
import java.util.*;
import java.io.*;

public class CompareResourceRegistryWorker extends CompareResourceRegistryRequest {
    static final long GLOBAL=0x465000, OBJ=0x940000, VT=0x940100, TABLE=0x420870;
    static final long WAIT=0x2c367c, RESET=0x138f5c, DELAY=0x2bb4f0;
    long loopEntry, nodeEntry, ioEntry, visits, traversals, ioExecutions, lowerIoCalls;
    boolean resubmit;
    boolean recoverAllocation;
    boolean recoverConversion;
    long conversionEntry, conversionSelectorCalls;
    static final long ACCOUNT_STATE=0x980000, HEAP_INDEX=0x2b3340;
    final Set<Integer> conversionTopologies=new TreeSet<>();
    long allocationEntry, allocationExecutions, allocationZeroCalls, metadataConversions;
    final Set<Long> rawResidues=new TreeSet<>();
    static final long RAW_ALLOC=0x2b26f0, ACCOUNT=0x2b260c, ZERO=0x2c3b9c;
    long reusedAllocations, repeatedNullRequests, loadedSkips, interleavedLists;
    @Override boolean originalCode(long pc) {
        return (recoverConversion && within(pc,4,CONVERT,0x1246f0)) ||
            (recoverAllocation && (within(pc,4,ALLOC,0x2c4c40) || within(pc,4,0x2c5544,0x2c5634))) ||
            super.originalCode(pc) || within(pc,4,0x113d58,0x113e70) ||
            within(pc,4,0x113e80,0x1142e8) || within(pc,4,0x114340,0x114370);
    }
    class ConnectedMachine extends RegistryMachine {
        final Set<Long> dead=new HashSet<>();
        final List<Long> live=new ArrayList<>(), seen=new ArrayList<>();
        final List<String> events=new ArrayList<>();
        final List<Long> states=new ArrayList<>();
        final List<Long> requests=new ArrayList<>(), packets=new ArrayList<>();
        final List<Long> reuseDescriptors=new ArrayList<>(), reusePackets=new ArrayList<>();
        final Map<Long,Long> rawPointers=new HashMap<>();
        final List<Long> headers=new ArrayList<>();
        final Set<Long> conversionStores=new HashSet<>();
        long allocatingRaw, allocatingUser;
        int batch;
        boolean worker, destroyed;
        long active, nodeReturn, ioReturn, releasing;
        int round, variant, callbackIndex, phase, ioStage, cursor, ioIndex;
        String path;
        long length, data, handleValue, statePointer, outputPath;
        ConnectedMachine(byte[] mapped,byte[] binary) { super(mapped,binary); }
        @Override long packetAddress(int index) {
            return batch==0 ? (recoverAllocation ? PACKETS+index*0x400 : super.packetAddress(index)) : reusePackets.get(index);
        }
        @Override long newDescriptorAddress(int index) {
            return batch==0 ? super.newDescriptorAddress(index) : reuseDescriptors.get(index);
        }
        @Override void allocationRegion(long address,int size,Random rng) {
            if(recoverAllocation) {
                if(batch==0) region(address-192,size+448,rng);
                else require(dead.contains(address) && expected.get(address-192).length==size+448,
                    "Reused raw allocation retains metadata, payload and guards");
                return;
            }
            if(batch==0) super.allocationRegion(address,size,rng);
            else require(dead.contains(address) && expected.get(address-16).length==size+32,
                "Reused allocation retains freed bytes and guards");
        }
        @Override void allocated(long address,int size) {
            if(batch!=0) {
                require(dead.remove(address),"Reuse only at allocator return"); reusedAllocations++;
                events.add("reuse:"+address);
            } else require(!dead.contains(address),"Fresh allocation lifetime");
        }
        @Override long allocationEntry() {
            return recoverAllocation && rebuiltPath ? CompareResourceRegistryWorker.this.allocationEntry : ALLOC;
        }
        @Override boolean executeAllocation(long address,int size) throws Exception {
            if(!recoverAllocation) return super.executeAllocation(address,size);
            long stop=register("lr"), sp=register("sp"), fifth=get(sp);
            long[] saved=new long[8]; for(int i=0;i<8;i++) saved[i]=register("r"+(i+4));
            // All 32 word-aligned raw residues; the returned user pointer is fixed by the fixture.
            long raw=address-184+4*((seed+ids.size()*7+size+batch*11)%32);
            long rounded=((size+315)/128)*128;
            require(((raw+60+127)/128)*128==address,"Independent aligned address oracle");
            rawResidues.add(raw%128);
            long[] calls={HEAP_ACQUIRE,HEAP_ACQUIRE,RAW_ALLOC,ACCOUNT,ZERO,HEAP_RELEASE,ZERO,HEAP_RELEASE};
            int next=0,depth=0,steps=0;
            allocatingRaw=raw; allocatingUser=address;
            while(thread.getCounter().getOffset()!=stop) {
                long pc=thread.getCounter().getOffset();
                if(List.of(HEAP_ACQUIRE,HEAP_RELEASE,RAW_ALLOC,ACCOUNT,ZERO).contains(pc)) {
                    require(next<calls.length && calls[next++]==pc,"Nested allocator call/clear order");
                    require((register("sp")&7)==0,"Allocator boundary alignment");
                    if(pc==ACCOUNT) {
                        set(raw,4,rounded,true); set(raw+4,2,128,true); set(raw+6,2,0,true);
                        set(address-4,4,raw,true);
                    }
                    compareMemory("Allocation boundary "+Long.toHexString(pc));
                    long result=0xface1234L;
                    if(pc==HEAP_ACQUIRE || pc==HEAP_RELEASE) {
                        require(register("r0")==get(HEAP+4),"Allocator reloads lock handle");
                        depth+=pc==HEAP_ACQUIRE ? 1 : -1;
                        require(depth>=0 && depth<=2,"Recursive allocator depth");
                    } else if(pc==RAW_ALLOC) {
                        require(depth==2 && register("r0")==256 && register("r1")==256 &&
                            register("r2")==0 && register("r3")==rounded && get(register("sp"))==fifth,
                            "Raw allocation preserves caller arguments and rounded size");
                        allocated(address,size); rawPointers.put(address,raw); result=raw;
                    } else if(pc==ACCOUNT) {
                        require(depth==2 && register("r0")==raw,"Accounting uses raw pointer under nested lock");
                        // Accounting owns these header fields, distinct from the user payload/backlink.
                        for(int i=8;i<32;i+=4) model(raw+i,4,(seed+batch*0x100+i)^0x87654321L);
                        if(recoverConversion) registerHeader(raw,rounded);
                    } else {
                        require(register("r0")==address && register("r1")==size && depth==(next==5 ? 2 : 1),
                            "Both clearing calls retain user pointer, size and lock depth");
                        memory(address,new byte[size]); setBytes(address,new byte[size]); allocationZeroCalls++;
                    }
                    // Deliberate dependency effect checks every subsequent state reload.
                    model(HEAP+4,4,(get(HEAP+4)^pc^next^0x87654321L)&MASK);
                    events.add("alloc:"+Long.toHexString(pc)+":"+(pc==RAW_ALLOC || pc==ACCOUNT ? raw : address)+":"+depth);
                    dependencyCalls++; externalReturn(result); continue;
                }
                step(rebuiltPath,++steps);
            }
            require(next==calls.length && depth==0 && register("r0")==address && register("sp")==sp,
                "Allocator returns aligned payload and restores stack");
            for(int i=0;i<8;i++) require(saved[i]==register("r"+(i+4)),"Allocator callee-saved register");
            compareMemory("Allocator return"); allocatingRaw=0; allocatingUser=0;
            allocationExecutions++; maxSteps=Math.max(maxSteps,steps); return true;
        }
        int heapIndex(long raw) { return (int)((seed+raw/4)%8); }
        void registerHeader(long raw,long rounded) {
            boolean prepend=seed%2!=0;
            long tail=prepend || headers.isEmpty() ? 0 : headers.get(headers.size()-1)+12;
            long next=!prepend || headers.isEmpty() ? 0 : headers.get(0)+12;
            int tag=(int)((seed+headers.size()+batch)%3)==0 ? 0x8108 : 0xff03;
            model(raw+8,2,tag); model(raw+12,4,tail); model(raw+16,4,next);
            if(tail==0) model(ACCOUNT_STATE,4,raw+12); else model(tail+4,4,raw+12);
            if(next==0) model(ACCOUNT_STATE+4,4,raw+12); else model(next,4,raw+12);
            if(seed%3==0) model(ACCOUNT_STATE+8,4,raw+12);
            model(ACCOUNT_STATE+24,4,(get(ACCOUNT_STATE+24)+1)&MASK);
            model(ACCOUNT_STATE+28,4,(get(ACCOUNT_STATE+28)+rounded)&MASK);
            if((tag&255)<8) {
                int index=heapIndex(raw);
                model(ACCOUNT_STATE+60+index*4,4,(get(ACCOUNT_STATE+60+index*4)+rounded)&MASK);
                model(ACCOUNT_STATE+92+index*4,4,(get(ACCOUNT_STATE+92+index*4)+rounded-128-60)&MASK);
            }
            headers.add(prepend ? 0 : headers.size(),raw);
        }
        void conversionSet(long a,int size,long value) {
            set(a,size,value,true);
            for(int i=0;i<size;i++) conversionStores.add(a+i);
        }
        void unlinkHeader(long raw) {
            int position=headers.indexOf(raw); require(position>=0,"Only registered headers released");
            long previous=position==0 ? 0 : headers.get(position-1)+12;
            long next=position+1==headers.size() ? 0 : headers.get(position+1)+12;
            require(get(raw+12)==previous && get(raw+16)==next,"Retained allocation list edges");
            conversionTopologies.add((previous!=0 ? 1 : 0)|(next!=0 ? 2 : 0));
            conversionSet(previous==0 ? ACCOUNT_STATE : previous+4,4,next);
            conversionSet(next==0 ? ACCOUNT_STATE+4 : next,4,previous);
            if(get(ACCOUNT_STATE+8)==raw+12) conversionSet(ACCOUNT_STATE+8,4,0);
            conversionSet(raw+8,2,0); headers.remove(position);
        }
        int executeConversion() throws Exception {
            require(phase==2 && register("r0")==releasing,"Recovered conversion argument/order");
            long raw=get(releasing-4), stop=register("lr"), sp=register("sp");
            require(rawPointers.containsKey(releasing) && raw==rawPointers.get(releasing),"Retained raw backlink");
            long[] saved=new long[8]; for(int i=0;i<8;i++) saved[i]=register("r"+(i+4));
            compareMemory("Before recovered conversion"); conversionStores.clear();
            conversionSet(ACCOUNT_STATE+24,4,(get(ACCOUNT_STATE+24)-1)&MASK);
            conversionSet(ACCOUNT_STATE+28,4,(get(ACCOUNT_STATE+28)-get(raw))&MASK);
            boolean selected=(memory(raw+8,1)[0]&255)<8;
            if(!selected) unlinkHeader(raw);
            int calls=0,steps=0;
            while(thread.getCounter().getOffset()!=stop) {
                long pc=thread.getCounter().getOffset();
                if(pc==HEAP_INDEX) {
                    require(selected && calls<2 && register("r0")==raw,"Conversion heap selector");
                    require((register("sp")&7)==0,"Conversion selector stack alignment");
                    compareMemory("Conversion accounting stage "+calls);
                    int index=heapIndex(raw);
                    long slot=ACCOUNT_STATE+(calls==0 ? 60 : 92)+index*4;
                    long size=get(raw), amount=calls==0 ? size : size-128-60;
                    conversionSet(slot,4,(get(slot)-amount)&MASK);
                    if(++calls==2) unlinkHeader(raw);
                    conversionSelectorCalls++; dependencyCalls++; externalReturn(index); continue;
                }
                step(rebuiltPath,++steps);
            }
            require(calls==(selected ? 2 : 0) && register("r0")==raw && register("sp")==sp,"Conversion return/selector count");
            for(int i=0;i<8;i++) require(register("r"+(i+4))==saved[i],"Conversion callee-saved register");
            compareMemory("After recovered conversion"); conversionStores.clear();
            phase=3; metadataConversions++; convertedReleases++;
            events.add("convert:"+raw+":"+calls);
            return steps;
        }
        @Override void submit(long id) throws Exception {
            int before=ids.size(); super.submit(id);
            if(ids.size()!=before) {
                requests.add(descriptors.get(descriptors.size()-1)); packets.add(packetAddress(before));
            }
        }
        void appendPending(int index) {
            // Explicit fixture insertion while the worker is stopped. Requests still append by instructions.
            long d=POOL+0x8000+index*0x400, tail=descriptors.isEmpty() ? 0 : descriptors.get(descriptors.size()-1);
            require(!descriptors.contains(d),"Distinct pending fixture");
            region(d-16,0x164,new Random(seed+index+999));
            model(d,4,1); model(d+0x130,4,0); model(d+0x138,4,0);
            model(d+0x13c,4,0); model(d+0x140,4,tail);
            if(tail==0) model(HEAD,4,d); else model(tail+0x13c,4,d);
            descriptors.add(d); initialNodes++;
        }
        void nextBatch() {
            require(resubmit && batch==0 && dead.size()==requests.size()*2,"First batch fully freed");
            for(long d:requests) require(dead.contains(d),"Every old descriptor freed");
            for(long p:packets) require(dead.contains(p),"Every old packet freed");
            compareMemory("Before retained resubmission");
            reuseDescriptors.addAll(requests); Collections.reverse(reuseDescriptors);
            reusePackets.addAll(packets); Collections.rotate(reusePackets,1);
            descriptors.clear(); descriptors.addAll(live);
            requests.clear(); packets.clear(); ids.clear(); freed.clear();
            handle=get(HANDLE); batch=1;
            // Restart is a scheduler model; all descriptor/registry/heap memory stays retained.
            model(GLOBAL,1,0);
        }
        @Override void externalReturn(long result) {
            if(worker) require((register("sp")&7)==0,"Worker lower boundary alignment");
            super.externalReturn(result);
        }
        long get(long a) { return word(memory(a,4),0); }
        void model(long a,int size,long value) {
            set(a,size,value,false);
            byte[] b=new byte[size]; for(int i=0;i<size;i++) b[i]=(byte)(value >>> (8*i)); memory(a,b);
        }
        void lifetime(long a,int size) {
            for(long p:dead) require(!(a<p+(p>=PACKETS ? 24 : 0x144) && a+size>p),"Access after free "+Long.toHexString(a));
        }
        @Override public void beforeLoad(PcodeThread<byte[]> t,PcodeOp op,AddressSpace space,byte[] offset,int size) {
            long a=Utils.bytesToLong(offset,offset.length,false); lifetime(a,size);
            if(worker && a==GLOBAL) require(size==1,"Stop byte width");
            if(within(a,size,OBJ,OBJ+0x200)) {
                require(!destroyed || !within(a,size,OBJ,OBJ+24),"Destroyed object read"); return;
            }
            super.beforeLoad(t,op,space,offset,size);
        }
        @Override public void beforeStore(PcodeThread<byte[]> t,PcodeOp op,AddressSpace space,byte[] offset,int size,byte[] value) {
            long a=Utils.bytesToLong(offset,offset.length,false); lifetime(a,size);
            if(recoverConversion && conversionStores.contains(a)) {
                for(int i=0;i<size;i++) require(conversionStores.contains(a+i),"Conversion store width");
                CompareResourceCreate.record(writes,a,size,Utils.bytesToLong(value,size,false)); return;
            }
            if(allocatingRaw!=0 && (within(a,size,allocatingRaw,allocatingRaw+8) || within(a,size,allocatingUser-4,allocatingUser))) {
                require(rawPointers.getOrDefault(allocatingUser,0L)==allocatingRaw,"Metadata writes follow raw allocation");
                CompareResourceCreate.record(writes,a,size,Utils.bytesToLong(value,size,false)); return;
            }
            if(worker && a==active && size==4) states.add(Utils.bytesToLong(value,4,false)&MASK);
            if(within(a,size,OBJ,OBJ+24)) { require(!destroyed,"Destroyed object store"); return; }
            if(worker && a==GLOBAL+4) { require(size==4,"Busy width"); return; }
            super.beforeStore(t,op,space,offset,size,value);
        }
        void prepare(boolean rebuilt,int mode,long seed,int neighbors,int v) {
            worker=false; dead.clear(); live.clear(); seen.clear(); events.clear(); destroyed=false;
            batch=0; requests.clear(); packets.clear(); reuseDescriptors.clear(); reusePackets.clear();
            rawPointers.clear(); allocatingRaw=0; allocatingUser=0;
            headers.clear(); conversionStores.clear();
            setup(rebuilt,mode,seed,neighbors); variant=v;
            for(long d:descriptors) {
                model(d,4,1); model(d+0x130,4,0); model(d+0x138,4,0);
                live.add(d);
            }
            region(GLOBAL,8,new Random(seed)); model(GLOBAL,1,0); model(GLOBAL+4,4,0);
            region(GLOBAL+0x24,4,new Random(seed)); model(GLOBAL+0x24,4,0x76543210);
            // Same heap lock is consumed by I/O and release; mutate it at lower boundaries.
            model(HEAP+4,4,0x12345678);
            if(recoverConversion) {
                region(ACCOUNT_STATE-16,0xa0,new Random(seed)); model(HEAP+8,4,ACCOUNT_STATE);
                for(int offset:new int[]{0,4,8,24,28}) model(ACCOUNT_STATE+offset,4,0);
                for(int offset=60;offset<124;offset+=4) model(ACCOUNT_STATE+offset,4,0);
            }
            heapRanges(!recoverAllocation && v%2==0 ? new long[]{0,MASK,0,0} : new long[]{0,0,0,0});
        }
        void startIo() {
            require(ioStage==0 && !dead.contains(active),"I/O starts once on live node");
            ioIndex=requests.indexOf(active);
            require(ioIndex>=0,"Only submitted descriptors enter I/O");
            path=string(active+0x2c); cursor=0; statePointer=0; outputPath=0;
            length=new long[]{0,1,0x80000000L,MASK}[(variant+ioIndex)%4];
            data=(variant+ioIndex+batch)%3==0 ? 0 : 0x950000+batch*0x10000+ioIndex*0x1000;
            handleValue=(variant+ioIndex)%2==0 ? 0x4560 : 0x4561;
            ioReturn=rebuiltPath ? register("lr") : 0x114070;
            if(rebuiltPath) require(register("r0")==active,"I/O descriptor");
            destroyed=false; memory(OBJ,new byte[0x200]);
            writeWord(TABLE,VT); writeWord(TABLE+12,VT); writeWord(VT-48,0);
            for(int off:new int[]{4,12,36,40}) writeWord(VT+off,0x730000+off);
            ioStage=1; ioExecutions++; events.add("io:"+active);
        }
        boolean ioCall(long pc) {
            if(ioStage==0) return false;
            if(rebuiltPath && pc>=0x710000 && pc<=0x710008)
                pc=new long[]{0x2b9486,0x2b9468,0x2c63dc}[(int)((pc-0x710000)/4)];
            long result=0;
            if(pc==0x2c244c) {
                require(ioStage==1 && register("r0")==24,"Object allocation"); result=OBJ; ioStage=2;
            } else if(pc==0x2b9486) {
                require(ioStage==2 && get(active+0x12c)==OBJ && get(OBJ)==VT,"Object construction");
                for(int off=4;off<24;off+=4) require(get(OBJ+off)==0,"Object zeroing");
                statePointer=register("r0"); require(get(statePointer)==0 && get(statePointer+4)==0,"Conversion state zeroing"); ioStage=3;
            } else if(pc==0x2b9468) {
                require(ioStage==3 && register("r0")==active+0x2c+cursor && register("r1")==0x105 && register("r2")==statePointer,"Path measure");
                result=cursor==path.length() ? 0 : 1; ioStage=result==0 ? 5 : 4;
            } else if(pc==0x2c63dc) {
                require(ioStage==4 && register("r1")==active+0x2c+cursor && register("r2")==1 && register("r3")==statePointer,"Path conversion");
                if(cursor==0) outputPath=register("r0");
                require(register("r0")==outputPath+2*cursor && within(outputPath,2*(path.length()+1),register("sp"),STACK-16),"Conversion scratch");
                memory(register("r0"),new byte[]{(byte)path.charAt(cursor),0}); cursor++; result=1; ioStage=3;
            } else if(pc==0x2bb944) {
                require(ioStage==5 && register("r0")==OBJ+4 && register("r2")==1,"File open");
                if(outputPath==0) outputPath=register("r1");
                require(register("r1")==outputPath,"Converted path pointer");
                byte[] want=new byte[2*(path.length()+1)]; for(int i=0;i<path.length();i++) want[2*i]=(byte)path.charAt(i);
                require(Arrays.equals(want,memory(outputPath,want.length)),"Converted path bytes/terminator");
                writeWord(OBJ+4,handleValue); result=(variant&1)==0 ? 0 : 0x80000001L; ioStage=6;
            } else if(pc==0x730024) {
                require(ioStage==6 && register("r0")==OBJ,"File size"); result=length; ioStage=7;
            } else if(pc==0x73000c) {
                require(ioStage==7 && register("r0")==OBJ && register("r2")==0 && register("r3")==0 && get(register("sp"))==0,"Seek"); ioStage=8;
            } else if(pc==0x2bf7ec) {
                require(ioStage==8 && register("r0")==256 && register("r1")==256 && register("r2")==0 && register("r3")==length && get(register("sp"))==4 && get(register("sp")+4)==1,"Constructed flags/parameter allocation");
                result=data; ioStage=9;
            } else if(pc==HEAP_ACQUIRE) {
                require(ioStage==9 && register("r0")==get(HEAP+4) && get(GLOBAL+4)==0,"I/O acquire");
                model(HEAP+4,4,(get(HEAP+4)+1)&MASK); ioStage=10;
            } else if(pc==0x730028) {
                require(ioStage==10 && register("r0")==OBJ && register("r2")==data && register("r3")==length && get(GLOBAL+4)==1,"File read/busy");
                require(within(register("r1"),4,register("sp"),STACK-16),"Read count output");
                writeWord(register("r1"),length^MASK); result=(variant&2)==0 ? 0 : MASK; ioStage=11;
            } else if(pc==HEAP_RELEASE) {
                require(ioStage==11 && register("r0")==get(HEAP+4) && get(GLOBAL+4)==0,"I/O unlock"); ioStage=(handleValue&1)!=0 ? 12 : 13;
            } else if(pc==0x2bce9c) {
                require(ioStage==12 && register("r0")==handleValue,"Preclose"); ioStage=13;
            } else if(pc==0x2b9450) {
                require(ioStage==13 && register("r0")==(handleValue&~1L),"Close"); ioStage=14;
            } else if(pc==0x730004) {
                require(ioStage==14 && register("r0")==OBJ && get(OBJ+4)==0,"Destruction"); destroyed=true; ioStage=15;
            } else return false;
            require((register("sp")&7)==0,"I/O alignment"); lowerIoCalls++; externalReturn(result); return true;
        }
        void endIo() {
            require(ioStage==15 && destroyed && cursor==path.length(),"I/O completed lower sequence");
            List<Long> wantStates=new ArrayList<>();
            if((variant&1)!=0) wantStates.add(5L); if((variant&2)!=0) wantStates.add(5L);
            require(states.equals(wantStates),"I/O error stores");
            int prefix=recoverAllocation ? 192 : 16;
            byte[] want=expected.get(active-prefix).clone();
            put(want,prefix,wantStates.isEmpty() ? 0 : 5); put(want,prefix+12,data); put(want,prefix+24,length); put(want,prefix+0x12c,OBJ);
            require(Arrays.equals(want,memory(active-prefix,want.length)),"I/O descriptor and guards");
            set(active,4,4,false); set(active+12,4,data,false); set(active+24,4,length,false);
            ioStage=0;
        }
        void runWorker() throws Exception {
            live.clear(); live.addAll(descriptors); round=0; phase=0; ioStage=0; active=0; callbackIndex=-1;
            boolean pendingBetween=false;
            for(int i=1;i<descriptors.size()-1;i++)
                pendingBetween|=!requests.contains(descriptors.get(i)) &&
                    descriptors.subList(0,i).stream().anyMatch(requests::contains) &&
                    descriptors.subList(i+1,descriptors.size()).stream().anyMatch(requests::contains);
            if(pendingBetween) interleavedLists++;
            begin(rebuiltPath ? loopEntry : 0x113d58,0); worker=true;
            int steps=0, nextNode=0, outer=0;
            while(thread.getCounter().getOffset()!=RETURN) {
                long pc=thread.getCounter().getOffset();
                if(active!=0 && pc==nodeReturn) { active=0; }
                if(pc==(rebuiltPath ? nodeEntry : 0x113de8)) {
                    require(active==0 && nextNode<seen.size(),"Traversal extent");
                    active=register(rebuiltPath ? "r0" : "r7"); nodeReturn=rebuiltPath ? register("lr") : 0x113dd4;
                    require(active==seen.get(nextNode++),"Traversal order"); visits++; states.clear();
                    if(round==1 && requests.contains(active)) {
                        callbackIndex=requests.indexOf(active);
                        require(get(active)==4 && get(active+4)==1 && get(active+8)==1,"Terminal cleanup state");
                        long previous=get(active+0x140), next=get(active+0x13c);
                        set(active+4,4,0,false);
                        if(previous==0) set(HEAD,4,next,false); else set(previous+0x13c,4,next,false);
                        if(next!=0) set(next+0x140,4,previous,false);
                        live.remove(active);
                    }
                }
                if(pc==(rebuiltPath ? ioEntry : 0x113e80)) startIo();
                if(ioStage!=0 && pc==ioReturn) endIo();
                if(ioCall(pc)) continue;
                if(pc==(rebuiltPath ? linked[2] : 0x155b30)) {
                    callbackIndex=requests.indexOf(active);
                    long packet=packets.get(callbackIndex);
                    require(round==0 && callbackIndex>=0 && register("r0")==packet && !dead.contains(packet),"Distinct completion packet");
                    List<Long> wantStates=new ArrayList<>();
                    if((variant&1)!=0) wantStates.add(5L); if((variant&2)!=0) wantStates.add(5L);
                    if(!rebuiltPath) wantStates.add(3L); wantStates.add(4L);
                    require(states.equals(wantStates),"Worker transition stores");
                    compareMemory("Completion dispatch");
                    set(REG+ids.get(callbackIndex)*16+4,4,data,true); completions++;
                }
                if(pc==(rebuiltPath ? linked[1] : 0x19f990)) {
                    long e=REG+ids.get(callbackIndex)*16;
                    require(register("r0")==data && register("r1")==e && register("r2")==length,"Publication identity/data/size");
                    compareMemory("Publication before callback");
                    set(e+4,4,data,true); set(e+8,4,length,true);
                    set(active+12,4,0,false); set(active+8,4,1,false);
                }
                if(pc==(rebuiltPath ? linked[4] : FREE)) {
                    require(phase==0,"Release nesting"); releasing=register("r0");
                    require(!dead.contains(releasing) && (releasing==active || releasing==packets.get(callbackIndex)),"Release identity/lifetime");
                    require(get(active+12)==0 && get(active+8)==1,"Ownership detached and cleanup marked");
                    compareMemory("Before release"); phase=1; releaseExecutions++;
                    events.add("release:"+releasing);
                }
                if(recoverConversion && pc==(rebuiltPath ? conversionEntry : CONVERT)) {
                    steps+=executeConversion(); continue;
                }
                if(phase!=0 && List.of(HEAP_ACQUIRE,CONVERT,HEAP_FREE,HEAP_RELEASE).contains(pc)) {
                    long result=0;
                    if(pc==HEAP_ACQUIRE) {
                        require(phase==1 && register("r0")==get(HEAP+4),"Heap acquire"); phase=!recoverAllocation && variant%2==0 ? 3 : 2;
                    } else if(pc==CONVERT) {
                        require(phase==2 && register("r0")==releasing,"Heap conversion"); result=releasing^0x80000000L; phase=3; convertedReleases++;
                        if(recoverAllocation) {
                            result=get(releasing-4);
                            require(rawPointers.containsKey(releasing) && result==rawPointers.get(releasing),"Release consumes preserved allocation backlink");
                            metadataConversions++;
                        }
                    } else if(pc==HEAP_FREE) {
                        require(phase==3 && register("r0")== (recoverAllocation ? rawPointers.get(releasing) : variant%2==0 ? releasing : releasing^0x80000000L),"Heap free");
                        dead.add(releasing); model(HEAP+4,4,(get(HEAP+4)+7)&MASK); phase=4;
                        if(!recoverAllocation && variant%2==0) directReleases++;
                    } else { require(phase==4 && register("r0")==get(HEAP+4),"Heap unlock reload"); phase=0; }
                    dependencyCalls++; externalReturn(result); continue;
                }
                if(pc==ACQUIRE || pc==RELEASE || pc==CHECK) {
                    long result=variant==3 ? 0x80000042L : 0;
                    if(pc==ACQUIRE) {
                        require(register("r2")==1 && register("r3")==0 && get(register("r1"))==get(HANDLE) && get(register("sp"))==MASK && get(register("sp")+4)==MASK,"Worker acquire");
                        require(within(register("r0"),4,register("sp"),STACK-16),"Acquire output");
                        writeWord(register("r0"),0); model(HANDLE,4,(get(HANDLE)+1)&MASK);
                    } else if(pc==RELEASE) {
                        require(register("r1")==get(HANDLE) && register("r2")==1 && within(register("r0"),4,register("sp"),STACK-16),"Worker unlock"); writeWord(register("r0"),0);
                    } else require(variant==3 && register("r0")==result && register("r1")==1,"Returning check");
                    dependencyCalls++; externalReturn(result); continue;
                }
                if(pc==WAIT || pc==RESET || pc==DELAY) {
                    require(active==0 && (register("sp")&7)==0,"Outer boundary");
                    require(pc==new long[]{WAIT,RESET,DELAY}[outer],"Outer call order");
                    if(pc==DELAY) require(register("r0")==3000000 && register("r1")==0,"Delay value");
                    else require(register("r0")==GLOBAL+0x24,"Event address");
                    if(pc==WAIT) {
                        if(round==3) model(GLOBAL,1,0x80);
                        seen.clear(); seen.addAll(live); nextNode=0;
                    } else if(pc==RESET) {
                        require(nextNode==seen.size() && phase==0 && ioStage==0,"Completed traversal");
                        compareMemory("Retained traversal "+round); traversals++;
                    } else round++;
                    outer=(outer+1)%3; externalReturn(0); continue;
                }
                require(rebuiltPath ? within(pc,4,BUILD,BUILD+codeSize) : originalCode(pc),"Instruction escape "+Long.toHexString(pc));
                require(++steps<20000,"Continuous instruction budget");
                if(!rebuiltPath) visited.add(pc); monitor.checkCancelled(); thread.stepInstruction();
            }
            require(round==3 && outer==1 && live.size()==initialNodes && dead.size()==2*ids.size(),"Worker completion and lifetime counts");
            compareMemory("Worker return");
            if(recoverConversion) {
                require(headers.isEmpty(),"All registered allocations unlinked");
                for(int offset:new int[]{0,4,8,24,28}) require(get(ACCOUNT_STATE+offset)==0,"Empty heap accounting/list");
                for(int offset=60;offset<124;offset+=4) require(get(ACCOUNT_STATE+offset)==0,"Empty per-heap accounting");
            }
            require(registryWrites.equals(wantRegistry),"Registry output/callback publication store order");
            require(register("sp")==STACK-16,"Worker SP");
            for(int r=4;r<=11;r++) require(register("r"+r)==0x12340000L+r,"Worker callee-saved register");
            require(register("s16")==0x81234567L && register("s17")==0xfedcba98L,"Worker d8 preservation");
            for(byte b:memory(STACK-16,16)) require(b==(byte)0x96,"Caller stack preservation");
            for(byte b:memory(STACK-0x1000,0x800)) require(b==(byte)0x96,"Stack guard");
            maxSteps=Math.max(maxSteps,steps); worker=false;
        }
    }
    @Override public void run() throws Exception {
        resubmit=Arrays.asList(getScriptArgs()).contains("resubmit");
        recoverAllocation=Arrays.asList(getScriptArgs()).contains("allocation");
        recoverConversion=Arrays.asList(getScriptArgs()).contains("conversion");
        require(!recoverConversion || recoverAllocation,"Conversion requires retained allocation");
        Path out=Path.of(getScriptArgs()[0]); require(!Files.exists(out.resolve("comparison.json")),"Output exists");
        byte[] mapped=new byte[0x377000]; require(currentProgram.getMemory().getBytes(toAddr(0x100000),mapped)==mapped.length,"Map");
        require(HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(mapped)).equals(
            "834938d18d2b7c688311c46c27bed813d0d7a9f8e3cbb61da8a6a3f23d360ebd"),"Hash");
        byte[] binary=Files.readAllBytes(out.resolve("registry-worker.bin")); codeSize=binary.length;
        require(codeSize>0 && codeSize<=0x2000,"Binary extent");
        List<String> lines=Files.readAllLines(out.resolve("entries.txt")); require(lines.size()==(recoverConversion ? 10 : recoverAllocation ? 9 : 8),"Entries");
        long[] all=lines.stream().mapToLong(Long::parseLong).toArray();
        for(long entry:all) require(within(entry,4,BUILD,BUILD+codeSize),"Entry extent");
        System.arraycopy(all,0,linked,0,5); loopEntry=all[5]; nodeEntry=all[6]; ioEntry=all[7]; recoverRelease=true;
        if(recoverAllocation) allocationEntry=all[8];
        if(recoverConversion) conversionEntry=all[9];
        ConnectedMachine[] machines={new ConnectedMachine(mapped,binary),new ConnectedMachine(mapped,binary)};
        try(PrintWriter log=new PrintWriter(Files.newBufferedWriter(out.resolve("results.tsv")))) {
            log.println("scenario\trequests_per_batch\tneighbors\tvariant\tmode\tid_pattern\tfinal_batch_ids\tfinal_descriptors\tfinal_packets\tevents");
            for(int count:new int[]{1,2,3}) for(int neighbors:new int[]{0,1,2})
            for(int v=0;v<4;v++) for(int mode:new int[]{0,1,255}) for(int pattern=0;pattern<3;pattern++) {
                try {
                    for(int side=0;side<2;side++) {
                        ConnectedMachine m=machines[side]; m.prepare(side==1,mode,0x774400L+scenarios,resubmit ? 0 : neighbors,v);
                        for(int i=0;i<count;i++) {
                            m.submit(pattern==0 ? i : pattern==1 ? 66-i : 0);
                            if(resubmit && i<neighbors) m.appendPending(i);
                        }
                        if(resubmit) for(int i=count;i<neighbors;i++) m.appendPending(i);
                        m.entryState(65,0,255); m.submit(65); m.submit(67); m.submit(MASK);
                        m.runWorker();
                        if(resubmit) {
                            List<Integer> previousIds=new ArrayList<>(m.ids);
                            for(int id:new LinkedHashSet<>(previousIds)) if(m.get(REG+id*16+4)!=0) {
                                int before=m.ids.size(); m.submit(id);
                                require(m.ids.size()==before,"Loaded registry skips allocation after cleanup"); loadedSkips++;
                            }
                            m.nextBatch();
                            for(int i=0;i<count;i++) {
                                int previousId=previousIds.get(i);
                                boolean eligible=m.get(REG+previousId*16+4)==0 && m.memory(REG+previousId*16+12,1)[0]==0;
                                if(eligible) repeatedNullRequests++;
                                m.submit(eligible ? previousId : 10+i);
                            }
                            m.runWorker();
                        }
                    }
                    require(machines[0].events.equals(machines[1].events),"Paired I/O and release order");
                } catch(Exception ex) { throw new IllegalStateException("Registry worker scenario "+scenarios+" count="+count+" neighbors="+neighbors+" variant="+v+" mode="+mode+" pattern="+pattern,ex); }
                log.printf("%d\t%d\t%d\t%d\t%d\t%d\t%s\t%s\t%s\t%s%n",++scenarios,count,neighbors,v,mode,pattern,
                    machines[0].ids,machines[0].requests,machines[0].packets,machines[0].events);
            }
        }
        require(scenarios==324 && submissions==(resubmit ? 2592 : 1296) && completions==submissions &&
            ioExecutions==submissions && releaseExecutions==submissions*2 && traversals==scenarios*(resubmit ? 12 : 6) &&
            (recoverAllocation ? directReleases==0 : directReleases>0) && convertedReleases>0,"Complete corpus counts");
        if(recoverAllocation) {
            require(allocationExecutions==submissions*2 && allocationZeroCalls==allocationExecutions*2 &&
                metadataConversions==releaseExecutions && rawResidues.size()==32,"Allocation corpus counts");
            for(long pc=ALLOC;pc<0x2c4c40;pc+=4) require(visited.contains(pc),"Unvisited wrapper instruction");
            // Special routes are not used by these constructors; direct allocator corpus covers those.
            for(long pc=0x2c5544;pc<0x2c55f8;pc+=4)
                require(visited.contains(pc),"Unvisited ordinary allocation instruction "+Long.toHexString(pc));
        }
        require(!resubmit || (reusedAllocations==2592 && repeatedNullRequests>0 && loadedSkips>0 && interleavedLists==288),
            "Retained reuse and interleaving corpus");
        Files.writeString(out.resolve("visited.txt"),String.join("\n",visited.stream().map(v->String.format("%08x",v)).toList())+"\n");
        try(PrintWriter listing=new PrintWriter(Files.newBufferedWriter(out.resolve("original-executed.txt")))) {
            for(long pc:visited) listing.printf("%08x %s%n",pc,currentProgram.getListing().getInstructionAt(toAddr(pc)));
        }
        Files.writeString(out.resolve("comparison.json"),String.format(Locale.ROOT,
            "{\"scenarios\":%d,\"submissions_both_paths\":%d,\"completions_both_paths\":%d,\"skipped_calls_both_paths\":%d,\"traversals_both_paths\":%d,\"node_visits_both_paths\":%d,\"io_executions_both_paths\":%d,\"release_executions_both_paths\":%d,\"lower_io_calls_both_paths\":%d,\"original_instruction_addresses\":%d,\"max_steps\":%d,\"resubmission\":%b,\"reused_allocations_both_paths\":%d,\"null_resubmissions_both_paths\":%d,\"loaded_skips_both_paths\":%d,\"interleaved_lists_both_paths\":%d,\"live_verified\":false}\n",
            scenarios,submissions,completions,skipped,traversals,visits,ioExecutions,releaseExecutions,lowerIoCalls,visited.size(),maxSteps,
            resubmit,reusedAllocations,repeatedNullRequests,loadedSkips,interleavedLists));
        if(recoverAllocation) Files.writeString(out.resolve("allocation.json"),String.format(Locale.ROOT,
            "{\"allocation_executions_both_paths\":%d,\"zero_calls_both_paths\":%d,\"metadata_conversions_both_paths\":%d,\"raw_residues\":%d}\n",
            allocationExecutions,allocationZeroCalls,metadataConversions,rawResidues.size()));
        if(recoverConversion) {
            require(conversionTopologies.size()==4 && conversionSelectorCalls>0,"Conversion topology coverage");
            for(long pc=CONVERT;pc<0x1246f0;pc+=4) require(visited.contains(pc),"Unvisited conversion instruction");
            Files.writeString(out.resolve("conversion.json"),String.format(Locale.ROOT,
                "{\"conversion_executions_both_paths\":%d,\"selector_calls_both_paths\":%d,\"list_topologies\":%d}\n",
                metadataConversions,conversionSelectorCalls,conversionTopologies.size()));
        }
        println("SMT4_REGISTRY_WORKER_OK");
    }
}
