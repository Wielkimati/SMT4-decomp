// Concrete copy execution and constructed-registry reload integration.
// @category SMT4
import ghidra.pcode.emu.*;
import ghidra.pcode.exec.*;
import ghidra.pcode.utils.Utils;
import ghidra.program.model.address.*;
import ghidra.program.model.pcode.PcodeOp;
import java.nio.file.*;
import java.util.*;
import java.io.*;

public class CompareTableResourceCopy extends CompareTableResourceReload {
    static final long[][] COPY={{0x2c6048,0x2c60d0},{0x2bcfac,0x2bd020}};
    int directPairs,alignedPairs,integratedCalls,prefetchHints;
    @Override ReloadMachine newMachine(byte[] map,byte[] binary){return new CopyMachine(map,binary);}
    @Override long copyEntry(boolean rebuilt){return rebuilt?entries[5]:COPY[0][0];}
    @Override String modelFields(){return "\"copy_recovered\":true,\"file_release_modeled\":true,\"copy_pairs\":"+directPairs+
        ",\"aligned_pairs\":"+alignedPairs+",\"integrated_copy_calls\":"+integratedCalls+",\"original_prefetch_hints\":"+prefetchHints;}
    static String access(boolean read,long address,int width){return (read?"R:":"W:")+Long.toHexString(address)+":"+width;}
    void group(List<String> e,long d,long s,int width,int count){
        for(int i=0;i<count;i++)e.add(access(true,s+i*width,width));
        for(int i=0;i<count;i++)e.add(access(false,d+i*width,width));
    }
    List<String> schedule(long d,long s,int n,boolean aligned){
        List<String> e=new ArrayList<>();
        if(!aligned&&n>3){int residue=(int)(d&3);
            if(residue!=0){
                e.add(access(true,s++,1));if(residue<=2)e.add(access(true,s++,1));
                e.add(access(false,d++,1));if(residue==1)e.add(access(true,s++,1));
                if(residue<=2)e.add(access(false,d++,1));if(residue==1)e.add(access(false,d++,1));
                n-=4-residue;
            }
            aligned=(s&3)==0;
        }
        if(aligned){
            while(n>=32){group(e,d,s,4,8);d+=32;s+=32;n-=32;}
            for(int block:new int[]{16,8,4})if((n&block)!=0){group(e,d,s,4,block/4);d+=block;s+=block;}
            if((n&2)!=0)e.add(access(true,s,2));if((n&1)!=0)e.add(access(true,s+(n&2),1));
            if((n&2)!=0)e.add(access(false,d,2));if((n&1)!=0)e.add(access(false,d+(n&2),1));
        }else{
            while(n>=8){group(e,d,s,4,2);d+=8;s+=8;n-=8;}
            if((n&4)!=0){group(e,d,s,4,1);d+=4;s+=4;}
            group(e,d,s,1,n&3);
        }
        return e;
    }
    class CopyMachine extends ReloadMachine {
        boolean copying;long source,destination;int count;
        List<String> actual=new ArrayList<>(),expected;
        CopyMachine(byte[] map,byte[] binary){super(map,binary);}
        void observe(boolean read,long at,int size){
            require(within(at,size,read?source:destination,(read?source:destination)+count),"Copy access extent");
            actual.add(access(read,at,size));
            int i=actual.size()-1;
            require(i<expected.size()&&actual.get(i).equals(expected.get(i)),"Copy access order at "+i+": "+actual.get(i)+" expected "+(i<expected.size()?expected.get(i):"end"));
        }
        @Override public void beforeLoad(PcodeThread<byte[]> t,PcodeOp op,AddressSpace space,byte[] offset,int size){
            long at=Utils.bytesToLong(offset,offset.length,false);
            if(copying&&!within(at,size,STACK-4096,STACK)&&!within(at,size,BUILD,BUILD+codeSize)&&!within(at,size,0x100000,0x477000)){
                observe(true,at,size);return;
            }
            super.beforeLoad(t,op,space,offset,size);
        }
        @Override public void beforeStore(PcodeThread<byte[]> t,PcodeOp op,AddressSpace space,byte[] offset,int size,byte[] value){
            long at=Utils.bytesToLong(offset,offset.length,false);
            if(copying&&!within(at,size,STACK-4096,STACK)){observe(false,at,size);return;}
            super.beforeStore(t,op,space,offset,size,value);
        }
        @Override public boolean handleMissingUserop(PcodeThread<byte[]> t,PcodeOp op,PcodeFrame frame,String name,PcodeUseropLibrary<byte[]> library){
            long pc=thread.getCounter().getOffset();
            if(copying&&name.equals("HintPreloadData")&&(pc==0x2bcfbc||pc==0x2bcfd4)){
                require(word(memory(pc,4),0)==0xf5d1f040L,"Pinned PLD");prefetchHints++;return true;
            }
            return super.handleMissingUserop(t,op,frame,name,library);
        }
        @Override void instruction(boolean rebuilt,boolean initializer,int steps)throws Exception{
            long pc=thread.getCounter().getOffset();
            if(!rebuilt&&copying){
                boolean allowed=false;for(long[] r:COPY)allowed|=within(pc,4,r[0],r[1]);
                require(allowed&&steps<20000,"Copy PC/budget "+Long.toHexString(pc));
                visited.add(pc);thread.stepInstruction();
            }else super.instruction(rebuilt,initializer,steps);
        }
        void executeCopy(boolean rebuilt,boolean aligned)throws Exception{
            destination=register("r0");source=register("r1");count=(int)register("r2");
            require(count>=0&&count<=1024,"Bounded copy count");
            actual.clear();expected=schedule(destination,source,count,aligned);
            long end=register("lr"),sp=register("sp");long[] saved=new long[8];
            for(int i=0;i<8;i++)saved[i]=register("r"+(i+4));
            copying=true;int steps=0;
            while(thread.getCounter().getOffset()!=end)instruction(rebuilt,false,++steps);
            copying=false;require(actual.equals(expected),"Missing copy access");require(register("sp")==sp,"Copy SP");
            for(int i=0;i<8;i++)require(register("r"+(i+4))==saved[i],"Copy saved register");
        }
        @Override void copyCall(boolean rebuilt,long replacement,long size)throws Exception{
            require(size==0||replacement!=0&&size<=128,"Reload copy domain");
            executeCopy(rebuilt,false);integratedCalls++;
        }
        List<String> direct(boolean rebuilt,boolean aligned,long d,long s,int n)throws Exception{
            trace=false;executing=false;
            byte[] src=new byte[n+32],dst=new byte[n+32];
            for(int i=0;i<src.length;i++){src[i]=(byte)(i*37+(i>>3)+n);dst[i]=(byte)(i*13+0xa7);}
            memory(s-16,src);memory(d-16,dst);byte[] want=dst.clone();System.arraycopy(src,16,want,16,n);
            setup(rebuilt?entries[aligned?6:5]:COPY[aligned?1:0][0],d);register("r1",s);register("r2",n);
            executeCopy(rebuilt,aligned);finish();
            if(aligned)require(register("r0")==d+n,"Aligned copy end pointer");
            require(Arrays.equals(memory(s-16,src.length),src),"Source guards/preservation");
            require(Arrays.equals(memory(d-16,dst.length),want),"Destination/guards");
            return new ArrayList<>(actual);
        }
    }
    @Override void extraComparisons(ReloadMachine first,ReloadMachine second,Path out)throws Exception{
        CopyMachine a=(CopyMachine)first,b=(CopyMachine)second;
        // The mode executes only these two original copy bodies; membership and ARM context are pinned.
        StringBuilder listing=new StringBuilder();
        for(long[] range:COPY){
            var f=getFunctionAt(toAddr(range[0]));require(f!=null&&f.getBody().getMinAddress().getOffset()==range[0]&&f.getBody().getMaxAddress().getOffset()==range[1]-1,"Copy membership");
            for(long pc=range[0];pc<range[1];pc+=4){
                require(getInstructionAt(toAddr(pc))!=null&&currentProgram.getProgramContext().getValue(currentProgram.getRegister("TMode"),toAddr(pc),false).signum()==0,"Copy ARM instruction");
                listing.append(Long.toHexString(pc)+" "+getInstructionAt(toAddr(pc))+"\n");
            }
        }
        Files.writeString(out.resolve("copy-membership.txt"),listing);
        int[] lengths={0,1,2,3,4,5,6,7,8,9,15,16,17,23,24,25,31,32,33,47,48,49,63,64,65,95,96,97,127,128,129,255,256,257,1024};
        try(PrintWriter log=new PrintWriter(Files.newBufferedWriter(out.resolve("copy-results.tsv")))){
            log.println("aligned\tdestination\tsource\tsize\taccesses");
            for(int dr=0;dr<4;dr++)for(int sr=0;sr<4;sr++)for(int n:lengths)
                pair(a,b,log,false,0x900020+dr,0x902020+sr,n);
            // Reversed allocation order and high-bit addresses exercise unsigned pointer bindings.
            for(int dr=0;dr<4;dr++)for(int sr=0;sr<4;sr++)for(int n:new int[]{3,33,65,257})
                pair(a,b,log,false,0x89004020L+dr,0x89000020L+sr,n);
            for(int n:lengths)pair(a,b,log,true,0x900020,0x902020,n);
        }
        for(long[] range:COPY)for(long pc=range[0];pc<range[1];pc+=4)require(visited.contains(pc),"Unvisited copy instruction "+Long.toHexString(pc));
    }
    void pair(CopyMachine a,CopyMachine b,PrintWriter log,boolean aligned,long d,long s,int n)throws Exception{
        try{require(a.direct(false,aligned,d,s,n).equals(b.direct(true,aligned,d,s,n)),"Copy pair");}
        catch(Exception e){throw new IllegalStateException("Copy aligned="+aligned+" d="+Long.toHexString(d)+" s="+Long.toHexString(s)+" n="+n,e);}
        if(aligned)alignedPairs++;else directPairs++;
        log.printf("%b\t%x\t%x\t%d\t%d%n",aligned,d,s,n,a.actual.size());
    }
}
