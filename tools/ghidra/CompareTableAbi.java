// Bounded ABI research, reusing the project PcodeEmulator checking pattern.
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
public class CompareTableAbi extends GhidraScript {
    private static final long Q = 0x2c6c64, COUNT = 0x2c0ea0, BASE = 0x600000;
    private static final long TABLE = 0x800000, STACK = 0xa01000, RETURN = 0x700000;
    private byte[] mapped, binary;
    private long rebuiltQ, rebuiltCount;
    private final Set<Long> visited = new TreeSet<>();
    private final long[][] stats = new long[4][5]; // calls, max steps, depth, loads, stores

    private boolean divisionPC(long pc) {
        return (pc >= Q && pc < Q + 0x30) || (pc >= 0x2c61e4 && pc < 0x2c62d4);
    }
    private class Machine implements PcodeEmulationCallbacks<byte[]> {
        final PcodeEmulator emu = new PcodeEmulator(currentProgram.getLanguage(), this);
        final PcodeThread<byte[]> t = emu.newThread();
        boolean executing;
        long sp, depth, loads, stores;
        void mem(long a, byte[] bytes) {
            emu.getSharedState().setVar(toAddr(a).getAddressSpace(), a, bytes.length, true, bytes);
        }
        void word(long a, long v) { mem(a, emu.getArithmetic().fromConst(v, 4)); }
        void reg(Register r, long v) { t.getState().setVar(r, emu.getArithmetic().fromConst(v, r.getMinimumByteSize())); }
        void reg(String n, long v) { reg(currentProgram.getRegister(n), v); }
        long reg(String n) {
            byte[] b = t.getState().getVar(currentProgram.getRegister(n), Reason.INSPECT);
            return Utils.bytesToLong(b, b.length, false) & 0xffffffffL;
        }
        @Override public void beforeStore(PcodeThread<byte[]> th, PcodeOp op,
                AddressSpace space, byte[] offset, int size, byte[] value) {
            long a = Utils.bytesToLong(offset, offset.length, false);
            if (a < sp - 64 || a + size > sp) throw new IllegalStateException("stack write boundary");
            stores++; depth = Math.max(depth, sp - a);
        }
        @Override public void beforeLoad(PcodeThread<byte[]> th, PcodeOp op,
                AddressSpace space, byte[] offset, int size) {
            long a = Utils.bytesToLong(offset, offset.length, false);
            boolean stack = a >= sp - 64 && a + size <= sp;
            if (!(stack || (a >= TABLE && a + size <= TABLE + 16) ||
                  (a >= COUNT && a + size <= COUNT + 0x38) ||
                  (a >= BASE && a + size <= BASE + binary.length)))
                throw new IllegalStateException("data read boundary " + Long.toHexString(a));
            if (stack) { loads++; depth = Math.max(depth, sp - a); }
        }
        @Override public <A,U> AddressSetView readUninitialized(PcodeThread<byte[]> th,
                PcodeExecutorStatePiece<A,U> piece, AddressSetView set, Reason reason) {
            if (executing) throw new IllegalStateException("uninitialized read " + set);
            return set;
        }
        Machine() {
            mem(0x100000, mapped);
            mem(BASE, new byte[0x1000]); mem(BASE, binary);
        }
        long[] call(int kind, long a, long b, int profile, int header) throws Exception {
            // Two distinct core-register/flag seeds and separated aligned stacks.
            sp = STACK - profile * 0x100;
            depth = loads = stores = 0;
            executing = false;
            for (Register r : currentProgram.getLanguage().getRegisters())
                if (r.isBaseRegister() && !r.isProcessorContext()) reg(r, 0);
            for (int r = 0; r <= 12; r++) reg("r" + r, seed(r, profile));
            reg("cpsr", profile == 0 ? 0x10 : 0xf0000010L);
            for (String n : new String[]{"NG", "ZR", "CY", "OV"}) reg(n, profile);
            reg("sp", sp); reg("lr", RETURN);
            byte[] guard = new byte[128]; Arrays.fill(guard, (byte)(0xa5 ^ profile));
            mem(sp - 96, guard);
            word(TABLE, header == 2 ? 0x314c4255L : 0x314c4254L);
            word(TABLE + 4, a); word(TABLE + 8, b); word(TABLE + 12, 0xdeadc0deL);
            boolean count = kind >= 2, original = (kind & 1) == 0;
            reg("r0", count ? (header == 1 ? 0 : TABLE) : a);
            reg("r1", count ? seed(1, profile) : b);
            long entry = count ? (original ? COUNT : rebuiltCount) : (original ? Q : rebuiltQ);
            t.overrideContext(new RegisterValue(currentProgram.getProgramContext().getBaseContextRegister(), BigInteger.ZERO));
            t.overrideCounter(toAddr(entry)); executing = true;
            int steps = 0, qcalls = 0;
            while (t.getCounter().getOffset() != RETURN) {
                long pc = t.getCounter().getOffset();
                if (original ? !(divisionPC(pc) || (count && pc >= COUNT && pc < COUNT + 0x34))
                             : !(pc >= BASE && pc < BASE + binary.length))
                    throw new IllegalStateException("execution boundary " + Long.toHexString(pc));
                if (original) visited.add(pc);
                if (pc == (original ? Q : rebuiltQ)) {
                    qcalls++;
                    if (reg("r0") != a || reg("r1") != b || b == 0 || reg("lr") != RETURN)
                        throw new IllegalStateException("quotient arguments/tail LR");
                    if ((reg("sp") & 7) != 0) throw new IllegalStateException("call alignment");
                }
                long now = reg("sp");
                if (now > sp || now < sp - 64 || (now & 3) != 0)
                    throw new IllegalStateException("stack pointer boundary");
                depth = Math.max(depth, sp - now);
                if (++steps > 512) throw new IllegalStateException("instruction budget");
                monitor.checkCancelled(); t.stepInstruction();
            }
            executing = false;
            long expected = count && (header != 0 || b == 0) ? 0 : a / b;
            if (reg("r0") != expected) throw new IllegalStateException("quotient result");
            if (!count && original && reg("r1") != a % b) throw new IllegalStateException("remainder result");
            if (qcalls != (count && (header != 0 || b == 0) ? 0 : 1))
                throw new IllegalStateException("quotient call count");
            for (int r = 4; r <= 11; r++)
                if (reg("r" + r) != seed(r, profile)) throw new IllegalStateException("preserved r" + r);
            if (reg("sp") != sp) throw new IllegalStateException("restored SP");
            // Record extra observed preservation; it is not required of a C quotient replacement.
            if (original && (reg("r12") != seed(12, profile) || reg("lr") != RETURN))
                throw new IllegalStateException("original r12/LR preservation");
            if (original && (depth != 0 || loads != 0 || stores != 0))
                throw new IllegalStateException("original stack-free path");
            for (int i = 0; i < guard.length; i++) {
                long addr = sp - 96 + i;
                if (addr >= sp - depth && addr < sp) continue;
                byte[] value = emu.getSharedState().getVar(toAddr(addr).getAddressSpace(), addr, 1, true, Reason.INSPECT);
                if (value[0] != guard[i]) throw new IllegalStateException("stack guard");
            }
            stats[kind][0]++; stats[kind][1] = Math.max(stats[kind][1], steps);
            stats[kind][2] = Math.max(stats[kind][2], depth);
            stats[kind][3] += loads; stats[kind][4] += stores;
            return new long[]{reg("r0"), reg("r1"), reg("r2"), reg("r3"), reg("r12"), reg("lr"), depth, steps};
        }
    }
    private long seed(int r, int profile) {
        return ((profile == 0 ? 0x12340000L : 0xdecafe00L) + r * 0x101L) & 0xffffffffL;
    }
    private void negative(PrintWriter out, String name, long pc, long word, int kind, String expected) throws Exception {
        Machine m = new Machine(); m.word(pc, word);
        try { m.call(kind, 17, 5, 0, 0); }
        catch (Exception e) {
            // P-code wraps callback failures; require the exact expected root cause.
            Throwable cause = e;
            while (cause.getCause() != null) cause = cause.getCause();
            if (!(cause instanceof IllegalStateException) || !cause.getMessage().equals(expected)) throw e;
            out.printf("%s\t%08x\t%08x\t%s%n", name, pc, word, cause.getMessage()); return;
        }
        throw new IllegalStateException("mutant survived: " + name);
    }
    @Override public void run() throws Exception {
        Path out = Path.of(getScriptArgs()[0]), unit = Path.of(getScriptArgs()[1]);
        if (Files.exists(out.resolve("abi.json"))) throw new IllegalArgumentException("Existing evidence");
        mapped = new byte[0x377000];
        if (currentProgram.getMemory().getBytes(toAddr(0x100000), mapped) != mapped.length)
            throw new IllegalStateException("reference extent");
        if (!HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(mapped)).equals(
                "834938d18d2b7c688311c46c27bed813d0d7a9f8e3cbb61da8a6a3f23d360ebd"))
            throw new IllegalStateException("reference identity");
        binary = Files.readAllBytes(unit.resolve("nkm-sort-index.bin"));
        rebuiltQ = Long.parseLong(Files.readString(unit.resolve("quotient-entry.txt")));
        for (String row : Files.readAllLines(unit.resolve("helper-entries.tsv")))
            if (row.startsWith("tbl1_entry_count\t")) rebuiltCount = Long.parseLong(row.split("\t")[2]);
        if (binary.length == 0 || binary.length > 0x1000 || rebuiltQ < BASE || rebuiltQ >= BASE + binary.length ||
                rebuiltCount < BASE || rebuiltCount >= BASE + binary.length) throw new IllegalStateException("unit entries");
        try (PrintWriter listing = new PrintWriter(Files.newBufferedWriter(out.resolve("abi-listing.txt")))) {
            for (long[] range : new long[][]{{COUNT, COUNT + 0x34}, {0x2c61b0, 0x2c62d4}, {Q, Q + 0x30}})
                for (long pc = range[0]; pc < range[1]; pc += 4) {
                    var insn = getInstructionAt(toAddr(pc));
                    if (insn == null) throw new IllegalStateException("missing instruction");
                    listing.printf("%08x %s %s%n", pc, HexFormat.of().formatHex(insn.getBytes()), insn);
                }
        }
        Machine[] machines = {new Machine(), new Machine(), new Machine(), new Machine()};
        int cases = 0;
        try (PrintWriter rows = new PrintWriter(Files.newBufferedWriter(out.resolve("abi-results.tsv")))) {
            rows.println("kind\tprofile\theader\tdividend\tdivisor\tr0\tr1\tr2\tr3\tr12\tlr\tstack_depth\tsteps");
            var corpus = Files.readAllLines(unit.resolve("fixtures/divisions.tsv"));
            for (String row : corpus.subList(1, corpus.size())) {
                String[] c = row.split("\t"); long a = Long.parseLong(c[0]), b = Long.parseLong(c[1]);
                if (a < 0 || a > 0xffffffffL || b <= 0 || b > 0xffffffffL || a / b != Long.parseLong(c[2]))
                    throw new IllegalArgumentException("invalid corpus");
                for (int profile = 0; profile < 2; profile++) for (int kind = 0; kind < 4; kind++) {
                    rows.printf("%d\t%d\t0\t%d\t%d", kind, profile, a, b);
                    for (long value : machines[kind].call(kind, a, b, profile, 0)) rows.print("\t" + value);
                    rows.println(); cases++;
                }
            }
            for (int header = 0; header <= 2; header++) for (int profile = 0; profile < 2; profile++)
                for (int kind = 2; kind < 4; kind++) {
                    long b = header == 0 ? 0 : 5;
                    rows.printf("%d\t%d\t%d\t17\t%d", kind, profile, header, b);
                    for (long value : machines[kind].call(kind, 17, b, profile, header)) rows.print("\t" + value);
                    rows.println(); cases++;
                }
        }
        try (PrintWriter outNeg = new PrintWriter(Files.newBufferedWriter(out.resolve("negatives.tsv")))) {
            outNeg.println("mutant\taddress\tword\trejection");
            negative(outNeg, "wrong-remainder", 0x2c62c4, 0xe0501000L, 0, "remainder result");
            negative(outNeg, "clobber-r4", rebuiltQ + 0x34, 0xe8bd8020L, 1, "preserved r4");
            negative(outNeg, "write-above-stack", rebuiltQ + 4, 0xe58d4000L, 1, "stack write boundary");
        }
        String[] labels = {"original_quotient", "rebuilt_quotient", "original_count", "rebuilt_count"};
        StringBuilder json = new StringBuilder("{\n  \"calls\": " + cases + ",\n  \"profiles\": 2,\n  \"mutants_rejected\": 3,\n");
        for (int i = 0; i < 4; i++) json.append("  \"").append(labels[i]).append("\": ")
            .append(Arrays.toString(stats[i])).append(",\n");
        json.append("  \"stat_columns\": [\"calls\",\"max_steps\",\"max_stack_depth\",\"stack_loads\",\"stack_stores\"],\n")
            .append("  \"original_visited_instruction_addresses\": ").append(visited.size()).append("\n}\n");
        Files.writeString(out.resolve("abi-coverage.txt"), visited.toString() + "\n");
        Files.writeString(out.resolve("abi.json"), json.toString());
        println("SMT4_TABLE_ABI_OK");
    }
}
