// Execute original and rebuilt ARM routines with controlled, local-only memory.
// This is an instruction-level harness, not a live game or a recovered loader.
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

public class CompareNkmLookup extends GhidraScript {
    private static final long ORIGINAL = 0x2883e8, REBUILT = 0x600000;
    private static final long TABLE = 0x800000, STACK = 0xa01000, RETURN = 0x700000;
    private int maxSteps = 0;
    private byte[] mapped;
    private int codeSize;
    private boolean recoveredHelpers;
    private long rebuiltQuotient;
    private final Set<Long> divisionPCs = new TreeSet<>();
    private final Set<Long> pairPCs = new TreeSet<>();

    private class StrictEmulator implements PcodeEmulationCallbacks<byte[]> {
        final PcodeEmulator machine;
        final PcodeThread<byte[]> thread;
        final int tableSize;
        boolean executing;
        StrictEmulator(int tableSize) {
            this.tableSize = tableSize;
            machine = new PcodeEmulator(currentProgram.getLanguage(), this);
            thread = machine.newThread();
        }
        @Override public void beforeStore(PcodeThread<byte[]> t, PcodeOp op,
                AddressSpace space, byte[] offset, int size, byte[] value) {
            long address = Utils.bytesToLong(offset, offset.length, false);
            if (address < STACK - 0x1000 || address + size > STACK)
                throw new IllegalStateException("Non-stack write: " + Long.toHexString(address));
        }
        @Override public void beforeLoad(PcodeThread<byte[]> t, PcodeOp op,
                AddressSpace space, byte[] offset, int size) {
            long a = Utils.bytesToLong(offset, offset.length, false);
            if (!((a >= 0x100000 && a + size <= 0x477000) ||
                  (a >= REBUILT && a + size <= REBUILT + codeSize) ||
                  (a >= TABLE && a + size <= TABLE + tableSize) ||
                  (a >= 0x49382c && a + size <= 0x49382c + 67 * 16) ||
                  (a >= STACK - 0x1000 && a + size <= STACK)))
                throw new IllegalStateException("Out-of-fixture read: " + Long.toHexString(a));
        }
        @Override public <A, U> AddressSetView readUninitialized(PcodeThread<byte[]> t,
                PcodeExecutorStatePiece<A, U> piece, AddressSetView set, Reason reason) {
            if (executing) throw new IllegalStateException("Uninitialized read: " + set);
            return set;
        }
        void writeMemory(Address a, byte[] bytes) {
            machine.getSharedState().setVar(a.getAddressSpace(), a.getOffset(),
                                           bytes.length, true, bytes);
        }
        void writeMemoryValue(Address a, int size, long value) {
            writeMemory(a, machine.getArithmetic().fromConst(value, size));
        }
        void writeRegister(Register r, BigInteger value) {
            thread.getState().setVar(r, machine.getArithmetic().fromConst(value, r.getMinimumByteSize()));
        }
        void writeRegister(String name, long value) {
            writeRegister(currentProgram.getRegister(name), BigInteger.valueOf(value));
        }
        BigInteger readRegister(String name) {
            byte[] value = thread.getState().getVar(currentProgram.getRegister(name), Reason.INSPECT);
            return BigInteger.valueOf(Utils.bytesToLong(value, value.length, false));
        }
        void start(long entry) {
            thread.overrideContext(new RegisterValue(
                currentProgram.getProgramContext().getBaseContextRegister(), BigInteger.ZERO));
            thread.overrideCounter(toAddr(entry));
            executing = true;
        }
        Address getExecutionAddress() { return thread.getCounter(); }
        void step() { thread.stepInstruction(); }
        void dispose() { /* No database or native resources owned by PcodeEmulator. */ }
    }

    private StrictEmulator make(byte[] binary, byte[] table) {
        StrictEmulator emu = new StrictEmulator(table.length);
        emu.writeMemory(toAddr(0x100000), mapped);
        // Decoder prefetch can read past the last instruction. Padding is never
        // executable: call() checks the exact binary extent before every step.
        emu.writeMemory(toAddr(REBUILT), new byte[0x2000]);
        emu.writeMemory(toAddr(REBUILT), binary);
        emu.writeMemory(toAddr(TABLE), table);
        emu.writeMemory(toAddr(0x49382c), new byte[67 * 16]);
        emu.writeMemoryValue(toAddr(0x49382c + 16 + 4), 4, TABLE);
        emu.writeMemory(toAddr(STACK - 0x1000), new byte[0x1000]);
        return emu;
    }

    private long call(StrictEmulator emu, long entry, long r0, long r1) throws Exception {
        return call(emu, entry, r0, r1, 512);
    }

    private long call(StrictEmulator emu, long entry, long r0, long r1, int budget) throws Exception {
        // SLEIGH models some flags separately from cpsr. Initialize the complete
        // register bank explicitly; unknown memory reads still fail closed.
        for (var register : currentProgram.getLanguage().getRegisters())
            if (register.isBaseRegister() && !register.isProcessorContext())
                emu.writeRegister(register, java.math.BigInteger.ZERO);
        for (int r = 0; r <= 12; ++r) emu.writeRegister("r" + r, 0x12340000L + r);
        emu.writeRegister("cpsr", 0x10);
        emu.writeRegister("sp", STACK);
        emu.writeRegister("lr", RETURN);
        emu.writeRegister("r0", r0);
        emu.writeRegister("r1", r1);
        emu.start(entry);
        int steps = 0;
        while (emu.getExecutionAddress().getOffset() != RETURN) {
            long pc = emu.getExecutionAddress().getOffset();
            if (!((pc >= 0x100000 && pc < 0x3fe69c) ||
                  (pc >= REBUILT && pc < REBUILT + codeSize)))
                throw new IllegalStateException("Unexpected PC: " + Long.toHexString(pc));
            if (rebuiltQuotient != 0 && entry >= REBUILT && pc < REBUILT)
                throw new IllegalStateException("Original code on rebuilt path: " + Long.toHexString(pc));
            if (entry == 0x2c6c64) {
                if (!((pc >= 0x2c6c64 && pc < 0x2c6c94) ||
                      (pc >= 0x2c61e4 && pc < 0x2c62d4)))
                    throw new IllegalStateException("Unexpected division target: " + Long.toHexString(pc));
                divisionPCs.add(pc);
            }
            if (recoveredHelpers && entry >= REBUILT && pc < REBUILT &&
                !((pc >= 0x2c6c64 && pc < 0x2c6c94) ||
                  (pc >= 0x2c61e4 && pc < 0x2c62d4)))
                throw new IllegalStateException("Unexpected original dependency: " + Long.toHexString(pc));
            if (pc == 0x2c6c64 && emu.readRegister("r1").longValue() == 0)
                throw new IllegalStateException("Unexpected division by zero");
            if (entry == 0x1a0ea4 && pc >= 0x1a0ea4 && pc < 0x1a0f1c) pairPCs.add(pc);
            if (++steps > budget) throw new IllegalStateException("Instruction budget exceeded");
            monitor.checkCancelled();
            emu.step();
        }
        maxSteps = Math.max(maxSteps, steps);
        if (emu.readRegister("sp").longValue() != STACK)
            throw new IllegalStateException("Stack pointer not restored");
        for (int r = 4; r <= 11; ++r)
            if (emu.readRegister("r" + r).longValue() != 0x12340000L + r)
                throw new IllegalStateException("Callee-saved r" + r + " corrupted");
        return emu.readRegister("r0").longValue() & 0xffffffffL;
    }

    @Override public void run() throws Exception {
        Path out = Path.of(getScriptArgs()[0]);
        if (Files.exists(out.resolve("comparison.json")))
            throw new IllegalArgumentException("Refusing to overwrite comparison");
        mapped = new byte[0x377000];
        if (currentProgram.getMemory().getBytes(toAddr(0x100000), mapped) != mapped.length)
            throw new IllegalStateException("Incomplete reference map");
        String hash = HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(mapped));
        if (!hash.equals("834938d18d2b7c688311c46c27bed813d0d7a9f8e3cbb61da8a6a3f23d360ebd"))
            throw new IllegalStateException("Reference hash mismatch");
        byte[] binary = Files.readAllBytes(out.resolve("nkm-sort-index.bin"));
        recoveredHelpers = Files.exists(out.resolve("helper-entries.tsv"));
        codeSize = binary.length;
        if (binary.length == 0 || binary.length > 0x1000)
            throw new IllegalArgumentException("Unexpected rebuilt unit size");
        if (Files.exists(out.resolve("quotient-entry.txt"))) {
            rebuiltQuotient = Long.parseLong(Files.readString(out.resolve("quotient-entry.txt")));
            if (!recoveredHelpers || rebuiltQuotient < REBUILT || rebuiltQuotient >= REBUILT + codeSize)
                throw new IllegalArgumentException("Invalid rebuilt quotient entry");
        }
        try (PrintWriter listing = new PrintWriter(Files.newBufferedWriter(out.resolve("division-listing.txt")))) {
            for (long[] range : new long[][]{{0x2c6c64, 0x2c6c94}, {0x2c61e4, 0x2c62d4}}) {
                for (long pc = range[0]; pc < range[1]; pc += 4) {
                    var instruction = getInstructionAt(toAddr(pc));
                    if (instruction == null) throw new IllegalStateException("Missing division instruction");
                    listing.printf("%08x %s %s%n", pc,
                        HexFormat.of().formatHex(instruction.getBytes()), instruction);
                }
            }
        }
        var rows = Files.readAllLines(out.resolve("fixtures/cases.tsv"));
        int cases = 0;
        StrictEmulator original = null, rebuilt = null;
        String fixture = "";
        try (PrintWriter results = new PrintWriter(Files.newBufferedWriter(out.resolve("results.tsv")))) {
            results.println("fixture\tindex\texpected\toriginal\trebuilt");
            for (String row : rows.subList(1, rows.size())) {
                String[] cols = row.split("\t");
                if (!cols[0].matches("[a-z_]+")) throw new IllegalArgumentException("Fixture name");
                if (!fixture.equals(cols[0])) {
                    if (original != null) original.dispose();
                    if (rebuilt != null) rebuilt.dispose();
                    fixture = cols[0];
                    byte[] table = Files.readAllBytes(out.resolve("fixtures/" + fixture + ".bin"));
                    original = make(binary, table);
                    rebuilt = make(binary, table);
                }
                long index = Long.parseLong(cols[1]), expected = Long.parseLong(cols[2]);
                long a = call(original, ORIGINAL, index, 0), b = call(rebuilt, REBUILT, index, 0);
                results.printf("%s\t%d\t%d\t%d\t%d%n", fixture, index, expected, a, b);
                if (a != expected || b != expected)
                    throw new IllegalStateException("Mismatch: " + row + " original=" + a + " rebuilt=" + b);
                ++cases;
            }
        } finally {
            if (original != null) original.dispose();
            if (rebuilt != null) rebuilt.dispose();
        }
        // Independently check the quotient consumed by the count helper, without
        // claiming the complete division ABI (r1/remainder/zero divisor).
        int divisions = 0;
        StrictEmulator divider = make(binary, new byte[16]);
        StrictEmulator rebuiltDivider = rebuiltQuotient == 0 ? null : make(binary, new byte[16]);
        try (PrintWriter results = new PrintWriter(Files.newBufferedWriter(out.resolve("division.tsv")))) {
            results.println("dividend\tdivisor\texpected_quotient\toriginal_r0\trebuilt_r0");
            var divisionRows = Files.readAllLines(out.resolve("fixtures/divisions.tsv"));
            for (String row : divisionRows.subList(1, divisionRows.size())) {
                String[] cols = row.split("\t");
                long a = Long.parseLong(cols[0]), b = Long.parseLong(cols[1]);
                long expected = Long.parseLong(cols[2]);
                if (a < 0 || a > 0xffffffffL || b <= 0 || b > 0xffffffffL || expected != a / b)
                    throw new IllegalArgumentException("Invalid division case: " + row);
                long actual = call(divider, 0x2c6c64, a, b);
                Long rebuiltResult = rebuiltDivider == null ? null : call(rebuiltDivider, rebuiltQuotient, a, b);
                results.printf("%s\t%d\t%s%n", row, actual, rebuiltResult == null ? "" : rebuiltResult);
                if (actual != expected || (rebuiltResult != null && rebuiltResult != expected))
                    throw new IllegalStateException("Unsigned quotient mismatch: " + row +
                        " original=" + actual + " rebuilt=" + rebuiltResult);
                ++divisions;
            }
        } finally {
            divider.dispose();
            if (rebuiltDivider != null) rebuiltDivider.dispose();
        }
        // Every dispatch target, normalization stage and subtract block must run.
        // 0x2c6208 is entered via the carry-controlled normalization loop;
        // the zero-divisor escape at 0x2c63cc is deliberately outside scope.
        for (long pc = 0x2c61e4; pc < 0x2c62d4; pc += 4)
            if (!divisionPCs.contains(pc)) throw new IllegalStateException("Uncovered division PC: " + Long.toHexString(pc));
        for (long pc = 0x2c6c64; pc < 0x2c6c94; pc += 4)
            if (!divisionPCs.contains(pc)) throw new IllegalStateException("Uncovered division dispatch: " + Long.toHexString(pc));
        Files.writeString(out.resolve("division-coverage.txt"), divisionPCs.stream()
            .map(pc -> String.format("%08x%n", pc)).collect(java.util.stream.Collectors.joining()));
        int helpers = 0;
        if (recoveredHelpers) {
            Map<String, long[]> entries = new HashMap<>();
            var entryRows = Files.readAllLines(out.resolve("helper-entries.tsv"));
            for (String row : entryRows.subList(1, entryRows.size())) {
                String[] cols = row.split("\t");
                entries.put(cols[0], new long[]{Long.parseLong(cols[1]), Long.parseLong(cols[2])});
            }
            var helperRows = Files.readAllLines(out.resolve("fixtures/helpers.tsv"));
            fixture = "";
            original = null;
            rebuilt = null;
            try (PrintWriter results = new PrintWriter(Files.newBufferedWriter(out.resolve("helpers-results.tsv")))) {
                results.println("fixture\thelper\tr0\tr1\texpected\toriginal\trebuilt");
                for (String row : helperRows.subList(1, helperRows.size())) {
                    String[] cols = row.split("\t");
                    if (!cols[0].matches("[a-z_0-9]+")) throw new IllegalArgumentException("Fixture name");
                    if (!fixture.equals(cols[0])) {
                        if (original != null) original.dispose();
                        if (rebuilt != null) rebuilt.dispose();
                        fixture = cols[0];
                        byte[] table = Files.readAllBytes(out.resolve("fixtures/" + fixture + ".bin"));
                        original = make(binary, table);
                        rebuilt = make(binary, table);
                        Path registryFile = out.resolve("fixtures/" + fixture + ".registry.bin");
                        if (Files.exists(registryFile)) {
                            byte[] registry = Files.readAllBytes(registryFile);
                            if (registry.length != 67 * 16) throw new IllegalArgumentException("Registry size");
                            original.writeMemory(toAddr(0x49382c), registry);
                            rebuilt.writeMemory(toAddr(0x49382c), registry);
                        }
                    }
                    long r0 = Long.parseLong(cols[2]), r1 = Long.parseLong(cols[3]);
                    long expected = Long.parseLong(cols[4]);
                    long[] pair = entries.get(cols[1]);
                    if (pair == null) throw new IllegalArgumentException("Unknown helper");
                    long a = call(original, pair[0], r0, r1), b = call(rebuilt, pair[1], r0, r1);
                    results.printf("%s\t%d\t%d%n", row, a, b);
                    if (a != expected || b != expected)
                        throw new IllegalStateException("Helper mismatch: " + row + " original=" + a + " rebuilt=" + b);
                    ++helpers;
                }
            } finally {
                if (original != null) original.dispose();
                if (rebuilt != null) rebuilt.dispose();
            }
        }
        int pairCases = 0;
        if (Files.exists(out.resolve("pair-entry.txt"))) {
            long pairEntry = Long.parseLong(Files.readString(out.resolve("pair-entry.txt")));
            if (rebuiltQuotient == 0 || pairEntry < REBUILT || pairEntry >= REBUILT + codeSize)
                throw new IllegalArgumentException("Invalid rebuilt pair entry");
            try (PrintWriter listing = new PrintWriter(Files.newBufferedWriter(out.resolve("pair-listing.txt")))) {
                for (long pc = 0x1a0ea4; pc < 0x1a0f1c; pc += 4) {
                    var ins = getInstructionAt(toAddr(pc));
                    if (ins == null) throw new IllegalStateException("Missing pair instruction");
                    listing.printf("%08x %s %s%n", pc, HexFormat.of().formatHex(ins.getBytes()), ins);
                }
            }
            var pairRows = Files.readAllLines(out.resolve("fixtures/pairs.tsv"));
            fixture = "";
            original = null;
            rebuilt = null;
            try (PrintWriter results = new PrintWriter(Files.newBufferedWriter(out.resolve("pairs-results.tsv")))) {
                results.println("fixture\tkey\texpected\tcount\toriginal\trebuilt");
                for (String row : pairRows.subList(1, pairRows.size())) {
                    String[] cols = row.split("\t");
                    if (!cols[0].matches("pair_[a-z_]+")) throw new IllegalArgumentException("Pair fixture name");
                    if (!fixture.equals(cols[0])) {
                        if (original != null) original.dispose();
                        if (rebuilt != null) rebuilt.dispose();
                        fixture = cols[0];
                        byte[] table = Files.readAllBytes(out.resolve("fixtures/" + fixture + ".bin"));
                        original = make(binary, table);
                        rebuilt = make(binary, table);
                        println("SMT4_PAIR_FIXTURE " + fixture);
                    }
                    long key = Long.parseLong(cols[1]), expected = Long.parseLong(cols[2]);
                    int count = Integer.parseInt(cols[3]);
                    if (key < 0 || key > 0xffffffffL || expected < 0 || expected > 65535 || count < 0 || count > 1201)
                        throw new IllegalArgumentException("Invalid pair case");
                    // Each iteration executes count/division again. Existing short
                    // routines retain their original 512-instruction limit.
                    int budget = 128 + 512 * (count + 1);
                    long a = call(original, 0x1a0ea4, key, 0, budget);
                    long b = call(rebuilt, pairEntry, key, 0, budget);
                    results.printf("%s\t%d\t%d%n", row, a, b);
                    if (a != expected || b != expected)
                        throw new IllegalStateException("Pair mismatch: " + row + " original=" + a + " rebuilt=" + b);
                    ++pairCases;
                }
            } finally {
                if (original != null) original.dispose();
                if (rebuilt != null) rebuilt.dispose();
            }
            for (long pc = 0x1a0ea4; pc < 0x1a0f1c; pc += 4)
                if (!pairPCs.contains(pc)) throw new IllegalStateException("Uncovered pair PC: " + Long.toHexString(pc));
            Files.writeString(out.resolve("pair-coverage.txt"), pairPCs.stream()
                .map(pc -> String.format("%08x%n", pc)).collect(java.util.stream.Collectors.joining()));
        }
        Files.writeString(out.resolve("comparison.json"), String.format(Locale.ROOT,
            "{\n  \"lookup_cases\": %d,\n  \"division_cases\": %d,\n  \"max_instructions_per_call\": %d,\n" +
            "  \"helper_cases\": %d,\n  \"recovered_table_helpers\": %s,\n" +
            "  \"recovered_quotient\": %s,\n  \"original_division_instruction_addresses\": %d,\n" +
            "  \"pair_cases\": %d,\n  \"original_pair_instruction_addresses\": %d,\n" +
            "  \"callee_saved_registers\": true,\n  \"stack_restored\": true,\n" +
            "  \"writes_confined_to_stack\": true,\n  \"original_quotient_executed\": true\n}\n",
            cases, divisions, maxSteps, helpers, recoveredHelpers, rebuiltQuotient != 0,
            divisionPCs.size(), pairCases, pairPCs.size()), StandardOpenOption.CREATE_NEW);
        println("SMT4_NKM_COMPARE_OK cases=" + cases + " divisions=" + divisions + " helpers=" + helpers + " pairs=" + pairCases);
    }
}
