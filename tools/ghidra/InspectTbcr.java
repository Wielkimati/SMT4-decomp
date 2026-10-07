// Targeted read-only analysis. Generated output stays local and is not recovered source.
// @category SMT4
import ghidra.app.script.GhidraScript;
import ghidra.app.decompiler.DecompInterface;
import ghidra.program.model.listing.*;
import java.nio.file.*;
import java.io.*;
import java.security.MessageDigest;
import java.math.BigInteger;
import java.util.*;

public class InspectTbcr extends GhidraScript {
    @Override public void run() throws Exception {
        Path out = Path.of(getScriptArgs()[0]);
        if (Files.exists(out)) throw new IllegalArgumentException("Output must be new");
        byte[] bytes = new byte[0x377000];
        if (currentProgram.getMemory().getBytes(toAddr(0x100000), bytes) != bytes.length)
            throw new IllegalStateException("Incomplete memory map");
        String hash = HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(bytes));
        if (!hash.equals("834938d18d2b7c688311c46c27bed813d0d7a9f8e3cbb61da8a6a3f23d360ebd"))
            throw new IllegalStateException("Reference hash mismatch");
        Files.createDirectories(out);
        // The initializer is a self-relative startup callback that auto-analysis missed.
        // Verify its callback entry before creating transient analysis in a read-only run.
        if ((0x42a480L + Integer.toUnsignedLong(getInt(toAddr(0x42a480)))) % 0x100000000L != 0x3f05f0L)
            throw new IllegalStateException("Resource initializer callback mismatch");
        if (getFunctionAt(toAddr(0x3f05f0)) == null) {
            currentProgram.getProgramContext().setValue(currentProgram.getRegister("TMode"),
                toAddr(0x3f05f0), toAddr(0x3f05f0), BigInteger.ZERO);
            if (!disassemble(toAddr(0x3f05f0)) || createFunction(toAddr(0x3f05f0), null) == null)
                throw new IllegalStateException("Cannot analyze resource initializer");
        }
        Set<Function> functions = new LinkedHashSet<>();
        long[] targets = {0x2ac358, 0x2c0ea0, 0x2c0ef0, 0x2c0f18, 0x2883e8, 0x1a0ea4,
                          0x3f05f0, 0x3f0930, 0x49382c};
        try (PrintWriter w = new PrintWriter(Files.newBufferedWriter(out.resolve("references.tsv")))) {
            w.println("target\tfrom\ttype\tcontaining_function");
            for (long target : targets) {
                Function f = getFunctionContaining(toAddr(target));
                if (f != null) functions.add(f);
                var refs = currentProgram.getReferenceManager().getReferencesTo(toAddr(target));
                while (refs.hasNext()) {
                    var ref = refs.next();
                    Function caller = getFunctionContaining(ref.getFromAddress());
                    w.printf("%s\t%s\t%s\t%s%n", toAddr(target), ref.getFromAddress(),
                        ref.getReferenceType(), caller == null ? "" : caller.getEntryPoint());
                    // Follow the resource path and registry, not hundreds of generic table users.
                    if (target >= 0x3f0000 && caller != null) functions.add(caller);
                }
            }
        }
        DecompInterface decomp = new DecompInterface();
        try (PrintWriter listing = new PrintWriter(Files.newBufferedWriter(out.resolve("listing.txt")));
             PrintWriter pseudo = new PrintWriter(Files.newBufferedWriter(out.resolve("pseudocode.c")))) {
            decomp.openProgram(currentProgram);
            pseudo.println("/* GENERATED ANALYSIS ONLY: no runtime verification. */");
            for (Function f : functions) {
                listing.printf("\nFUNCTION %s %s TMode=%s%n", f.getEntryPoint(), f.getName(),
                    currentProgram.getProgramContext().getValue(currentProgram.getRegister("TMode"),
                        f.getEntryPoint(), false));
                for (var cu : currentProgram.getListing().getCodeUnits(f.getBody(), true))
                    listing.printf("%s %-24s %s%n", cu.getAddress(),
                        HexFormat.of().formatHex(cu.getBytes()), cu);
                pseudo.printf("\n/* %s %s */%n", f.getEntryPoint(), f.getName());
                var result = decomp.decompileFunction(f, 60, monitor);
                if (!result.decompileCompleted())
                    throw new IllegalStateException("Decompile failed: " + result.getErrorMessage());
                pseudo.println(result.getDecompiledFunction().getC());
            }
        } finally { decomp.dispose(); }
        Files.writeString(out.resolve("COMPLETE.txt"), "mapped_sha256=" + hash +
            "\nfunctions=" + functions.size() + "\nanalysis_only=true\n", StandardOpenOption.CREATE_NEW);
        println("SMT4_TBCR_INSPECT_OK");
    }
}
