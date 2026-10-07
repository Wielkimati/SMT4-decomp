// Controlled ARM comparisons with explicit backend interception, not real I/O.
// @category SMT4
import ghidra.app.script.GhidraScript;
import ghidra.pcode.emu.*;
import ghidra.pcode.exec.*;
import ghidra.pcode.exec.PcodeExecutorStatePiece.Reason;
import ghidra.pcode.utils.Utils;
import ghidra.program.model.address.*;
import ghidra.program.model.lang.*;
import ghidra.program.model.pcode.PcodeOp;
import java.math.BigInteger;
import java.nio.file.*;
import java.security.MessageDigest;
import java.util.*;
import java.io.*;

public class CompareResourceLifecycle extends GhidraScript {
    static final long REG = 0x49382c, BUILD = 0x600000, STACK = 0xa01000, RETURN = 0x700000;
    static final long[] ORIGINAL = {0x297714, 0x33c844, 0x2a49e0, 0x19f990};
    static final long[] END = {0x297768, 0x33c898, 0x2a4a30, 0x19f99c};
    long[] rebuilt = new long[4];
    int codeSize, maxSteps;
    Set<Long> visited = new TreeSet<>();
    static long word(byte[] b, int off) {
        return (b[off] & 255L) | ((b[off+1] & 255L) << 8) |
               ((b[off+2] & 255L) << 16) | ((b[off+3] & 255L) << 24);
    }
    static void put(byte[] b, int off, long v) {
        for (int i = 0; i < 4; ++i) b[off+i] = (byte)(v >>> (8*i));
    }
    static boolean within(long a, int n, long lo, long hi) { return a >= lo && a+n <= hi; }
    void require(boolean ok, String message) { if (!ok) throw new IllegalStateException(message); }

    class Machine implements PcodeEmulationCallbacks<byte[]> {
        final PcodeEmulator machine = new PcodeEmulator(currentProgram.getLanguage(), this);
        final PcodeThread<byte[]> thread = machine.newThread();
        boolean executing;
        long writableEntry;
        int stores;
        @Override public void beforeStore(PcodeThread<byte[]> t, PcodeOp op,
                AddressSpace space, byte[] offset, int size, byte[] value) {
            long a = Utils.bytesToLong(offset, offset.length, false);
            require(within(a,size,STACK-0x1000,STACK) ||
                    within(a,size,writableEntry+4,writableEntry+12), "Unexpected write " + Long.toHexString(a));
            if (!within(a,size,STACK-0x1000,STACK)) stores++;
        }
        @Override public void beforeLoad(PcodeThread<byte[]> t, PcodeOp op,
                AddressSpace space, byte[] offset, int size) {
            long a = Utils.bytesToLong(offset, offset.length, false);
            require(within(a,size,0x100000,0x477000) || within(a,size,BUILD,BUILD+codeSize) ||
                    within(a,size,REG,REG+67*16) || within(a,size,STACK-0x1000,STACK),
                    "Unexpected read " + Long.toHexString(a));
        }
        @Override public <A,U> AddressSetView readUninitialized(PcodeThread<byte[]> t,
                PcodeExecutorStatePiece<A,U> piece, AddressSetView set, Reason reason) {
            require(!executing, "Uninitialized read " + set);
            return set;
        }
        void memory(long a, byte[] b) {
            machine.getSharedState().setVar(toAddr(a).getAddressSpace(),a,b.length,true,b);
        }
        byte[] memory(long a, int n) {
            return machine.getSharedState().getVar(toAddr(a).getAddressSpace(),a,n,true,Reason.INSPECT);
        }
        void register(Register r, long v) {
            thread.getState().setVar(r, machine.getArithmetic().fromConst(v,r.getMinimumByteSize()));
        }
        void register(String r, long v) { register(currentProgram.getRegister(r),v); }
        long register(String r) {
            byte[] b = thread.getState().getVar(currentProgram.getRegister(r),Reason.INSPECT);
            return Utils.bytesToLong(b,b.length,false) & 0xffffffffL;
        }
        void writeWord(long a, long v) { byte[] b = new byte[4]; put(b,0,v); memory(a,b); }
        Machine(byte[] mapped, byte[] binary) {
            memory(0x100000,mapped);
            memory(BUILD,new byte[0x2000]); // decoder prefetch only; PC range is checked separately
            memory(BUILD,binary);
            memory(STACK-0x1000,new byte[0x1000]);
        }
        long call(int kind, boolean isRebuilt, long id, byte[] initial, int backendMode,
                  long result, long size) throws Exception {
            executing = false;
            stores = 0;
            memory(REG,initial);
            for (var r : currentProgram.getLanguage().getRegisters())
                if (r.isBaseRegister() && !r.isProcessorContext()) register(r,0);
            for (int r=0; r<=12; ++r) register("r"+r,0x12340000L+r);
            register("cpsr",0x10); register("sp",STACK); register("lr",RETURN);
            writableEntry = id < 67 ? REG+id*16 : 0x900000;
            register("r0",kind == 3 ? result : id);
            if (kind == 3) { register("r1",writableEntry); register("r2",size); }
            thread.overrideContext(new RegisterValue(currentProgram.getProgramContext().getBaseContextRegister(), BigInteger.ZERO));
            thread.overrideCounter(toAddr(isRebuilt ? rebuilt[kind] : ORIGINAL[kind]));
            executing = true;
            int steps=0, calls=0;
            boolean valid = id < 67;
            int off = valid ? (int)id*16 : 0;
            long loaded = valid ? word(initial,off+4) : 0;
            boolean backendExpected = kind < 3 && valid && initial[off+12] == 0 &&
                                      (kind == 2 ? loaded != 0 : loaded == 0);
            while (thread.getCounter().getOffset() != RETURN) {
                long pc = thread.getCounter().getOffset();
                if (pc == 0x2c3344 || pc == 0x2b6820 || pc == 0x2c43b4) {
                    require(backendExpected && ++calls == 1, "Unexpected backend call");
                    require(pc == (kind == 0 ? 0x2c3344 : kind == 1 ? 0x2b6820 : 0x2c43b4), "Wrong backend");
                    require(stores == 0 && Arrays.equals(memory(REG,initial.length),initial), "Registry changed before backend");
                    require(register("r0") == (kind == 2 ? loaded : word(initial,off)), "Backend r0");
                    if (kind < 2) {
                        require(register("r1") == writableEntry+(kind == 0 ? 8 : 4) && register("r2") == 0, "Backend r1/r2");
                        if (kind == 1) {
                            require(register("r3") == (isRebuilt ? rebuilt[3] : ORIGINAL[3]), "Completion callback");
                            require(word(memory(register("sp"),4),0) == writableEntry, "Fifth backend argument");
                        }
                        if (backendMode != 0) writeWord(writableEntry+(kind == 0 ? 8 : 4),kind == 0 ? size : result);
                    }
                    long lr = register("lr");
                    for (String r : new String[]{"r0","r1","r2","r3","r12"}) register(r,0xdeadbeefL);
                    register("r0",result);
                    thread.overrideCounter(toAddr(lr));
                    continue;
                }
                require(isRebuilt ? within(pc,4,BUILD,BUILD+codeSize) : within(pc,4,ORIGINAL[kind],END[kind]),
                        "Unexpected instruction " + Long.toHexString(pc));
                if (!isRebuilt) visited.add(pc);
                require(++steps <= 256,"Instruction budget");
                monitor.checkCancelled();
                thread.stepInstruction();
            }
            require(calls == (backendExpected ? 1 : 0),"Missing backend call");
            require(register("sp") == STACK,"SP not restored");
            for (int r=4;r<=11;++r) require(register("r"+r)==0x12340000L+r,"Callee saved register");
            maxSteps=Math.max(maxSteps,steps);
            byte[] expected=initial.clone();
            long expectedReturn;
            if (kind == 3) {
                put(expected,off+4,result); put(expected,off+8,size); expectedReturn=0;
            } else {
                expectedReturn = !valid ? 0 : (kind == 2 ? loaded == 0 : loaded != 0) ? 1 :
                                 initial[off+12] == 0 ? 1 : 0;
                if (backendExpected) {
                    if (kind == 0) put(expected,off+4,result);
                    if (kind == 2) put(expected,off+4,0);
                    if (kind < 2 && backendMode != 0)
                        put(expected,off+(kind == 0 ? 8 : 4),kind == 0 ? size : result);
                }
                require(register("r0")==expectedReturn,"Return mismatch kind="+kind+" id="+id);
            }
            require(Arrays.equals(memory(REG,expected.length),expected),"Registry mismatch kind="+kind+" id="+id);
            return kind == 3 ? 0 : register("r0"); // callback is void; incidental registers unclaimed
        }
    }

    @Override public void run() throws Exception {
        Path out=Path.of(getScriptArgs()[0]);
        require(!Files.exists(out.resolve("comparison.json")),"Output exists");
        byte[] mapped=new byte[0x377000];
        require(currentProgram.getMemory().getBytes(toAddr(0x100000),mapped)==mapped.length,"Map");
        String hash=HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(mapped));
        require(hash.equals("834938d18d2b7c688311c46c27bed813d0d7a9f8e3cbb61da8a6a3f23d360ebd"),"Hash");
        byte[] binary=Files.readAllBytes(out.resolve("resource-lifecycle.bin"));
        codeSize=binary.length;
        require(codeSize>0 && codeSize<=0x1000,"Binary size");
        List<String> entries=Files.readAllLines(out.resolve("entries.txt"));
        require(entries.size()==4,"Entry count");
        for (int i=0;i<4;++i) {
            rebuilt[i]=Long.parseLong(entries.get(i));
            require(within(rebuilt[i],4,BUILD,BUILD+codeSize),"Entry extent");
        }
        Machine original=new Machine(mapped,binary), recovered=new Machine(mapped,binary);
        int[] counts=new int[4];
        Random rng=new Random(0x493840);
        List<Long> ids=new ArrayList<>();
        for (long id=0;id<67;++id) ids.add(id);
        ids.addAll(List.of(67L,68L,0x7fffffffL,0x80000000L,0xffffffffL));
        try (PrintWriter log=new PrintWriter(Files.newBufferedWriter(out.resolve("results.tsv")))) {
            log.println("kind\tid\tloaded\tpolicy\tbackend_mode\tbackend_result\tsize\toriginal\trebuilt");
            for (int kind=0;kind<4;++kind) for (long id:ids) {
                if (kind==3 && id>=67) continue;
                for (long loaded:new long[]{0,0x81234560L}) for (int flag:new int[]{0,1,0x80,255})
                for (int mode=0;mode<2;++mode) for (long result:new long[]{0,0x87654320L}) {
                    byte[] initial=new byte[67*16]; rng.nextBytes(initial);
                    long size=Integer.toUnsignedLong(rng.nextInt());
                    if (id<67) { put(initial,(int)id*16+4,loaded); initial[(int)id*16+12]=(byte)flag; }
                    long a=original.call(kind,false,id,initial,mode,result,size);
                    long b=recovered.call(kind,true,id,initial,mode,result,size);
                    require(a==b,"Original/rebuilt mismatch");
                    counts[kind]++;
                    log.printf("%d\t%d\t%d\t%d\t%d\t%d\t%d\t%d\t%d%n",kind,id,loaded,flag,mode,result,size,a,b);
                }
            }
        }
        for (int kind=0;kind<4;++kind) for (long pc=ORIGINAL[kind];pc<END[kind];pc+=4)
            require(visited.contains(pc),"Unvisited original instruction "+Long.toHexString(pc));
        Files.writeString(out.resolve("comparison.json"),String.format(Locale.ROOT,
            "{\"load_cases\":%d,\"request_cases\":%d,\"release_cases\":%d,\"callback_cases\":%d,\"original_instruction_addresses\":%d,\"max_steps\":%d,\"backend_intercepted\":true,\"live_verified\":false}\n",
            counts[0],counts[1],counts[2],counts[3],visited.size(),maxSteps));
        println("SMT4_LIFECYCLE_COMPARE_OK");
    }
}
