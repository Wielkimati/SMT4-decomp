// Targeted static evidence, never recovered source. Run -readOnly -noanalysis.
// @category SMT4
import ghidra.app.script.GhidraScript;
import ghidra.app.decompiler.DecompInterface;
import ghidra.program.model.listing.*;
import java.nio.file.*;
import java.io.*;
import java.security.MessageDigest;
import java.util.*;

public class InspectResourceRegistry extends GhidraScript {
    @Override public void run() throws Exception {
        Path out = Path.of(getScriptArgs()[0]);
        if (Files.exists(out)) throw new IllegalArgumentException("Output must be new");
        byte[] bytes = new byte[0x377000];
        if (currentProgram.getMemory().getBytes(toAddr(0x100000), bytes) != bytes.length)
            throw new IllegalStateException("Incomplete map");
        String hash = HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(bytes));
        if (!hash.equals("834938d18d2b7c688311c46c27bed813d0d7a9f8e3cbb61da8a6a3f23d360ebd"))
            throw new IllegalStateException("Reference hash mismatch");
        Files.createDirectories(out);
        long[] targets = {0x297714, 0x33c844, 0x33c8a0, 0x25c848,
                          0x2c3344, 0x2b6820, 0x19f990, 0x29706c};
        Set<Function> functions = new LinkedHashSet<>();
        try (PrintWriter refs = new PrintWriter(Files.newBufferedWriter(out.resolve("references.tsv")))) {
            refs.println("target\tfrom\ttype\tfunction");
            // Include interior registry references; absence is not proof against computed aliases.
            for (long target = 0x49382c; target < 0x49382c + 67 * 16; ++target) {
                for (var ref : getReferencesTo(toAddr(target))) {
                    Function f = getFunctionContaining(ref.getFromAddress());
                    refs.printf("%08x\t%s\t%s\t%s%n", target, ref.getFromAddress(),
                        ref.getReferenceType(), f == null ? "" : f.getEntryPoint());
                    if (f != null) functions.add(f);
                }
            }
            for (long target : targets) {
                Function f = getFunctionAt(toAddr(target));
                if (f == null && target == 0x19f990) {
                    // The saved automatic analysis decoded this callback incorrectly.
                    // Reinterpret only its three independently checked ARM words transiently.
                    clearListing(toAddr(target), toAddr(target + 11));
                    currentProgram.getProgramContext().setValue(currentProgram.getRegister("TMode"),
                        toAddr(target), toAddr(target), java.math.BigInteger.ZERO);
                    disassemble(toAddr(target));
                    f = createFunction(toAddr(target), null);
                }
                if (f == null) throw new IllegalStateException("Missing function " + Long.toHexString(target));
                functions.add(f);
                for (var ref : getReferencesTo(toAddr(target))) {
                    Function caller = getFunctionContaining(ref.getFromAddress());
                    refs.printf("%08x\t%s\t%s\t%s%n", target, ref.getFromAddress(),
                        ref.getReferenceType(), caller == null ? "" : caller.getEntryPoint());
                }
            }
        }
        // Raw aligned pointer candidates supplement Ghidra references (not a complete write census).
        try (PrintWriter w = new PrintWriter(Files.newBufferedWriter(out.resolve("pointer-candidates.tsv")))) {
            for (int off = 0; off < bytes.length; off += 4) {
                long value = Integer.toUnsignedLong(getInt(toAddr(0x100000 + off)));
                if (value >= 0x49382c && value < 0x49382c + 67 * 16)
                    w.printf("%08x\t%08x%n", 0x100000 + off, value);
            }
        }
        DecompInterface decomp = new DecompInterface();
        try (PrintWriter listing = new PrintWriter(Files.newBufferedWriter(out.resolve("listing.txt")));
             PrintWriter pseudo = new PrintWriter(Files.newBufferedWriter(out.resolve("pseudocode.c")))) {
            decomp.openProgram(currentProgram);
            for (Function f : functions) {
                listing.printf("\nFUNCTION %s %s%n", f.getEntryPoint(), f.getName());
                for (var cu : currentProgram.getListing().getCodeUnits(f.getBody(), true))
                    listing.printf("%s %s %s%n", cu.getAddress(), HexFormat.of().formatHex(cu.getBytes()), cu);
                var result = decomp.decompileFunction(f, 60, monitor);
                if (!result.decompileCompleted()) throw new IllegalStateException(result.getErrorMessage());
                pseudo.printf("\n/* %s: GENERATED ANALYSIS */\n%s%n", f.getEntryPoint(), result.getDecompiledFunction().getC());
            }
        } finally { decomp.dispose(); }
        Files.writeString(out.resolve("COMPLETE.txt"), "mapped_sha256=" + hash + "\nfunctions=" + functions.size());
        println("SMT4_REGISTRY_INSPECT_OK");
    }
}
