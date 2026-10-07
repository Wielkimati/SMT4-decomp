// Field-offset discovery plus bounded worker/release evidence export (read-only).
// @category SMT4
import ghidra.app.script.GhidraScript;
import ghidra.app.decompiler.DecompInterface;
import java.nio.file.*;
import java.io.*;
import java.security.MessageDigest;
import java.util.*;

public class InspectResourceWorker extends GhidraScript {
    @Override public void run() throws Exception {
        Path out = Path.of(getScriptArgs()[0]);
        if (Files.exists(out)) throw new IllegalArgumentException("Choose new output");
        byte[] bytes = new byte[0x377000];
        if (currentProgram.getMemory().getBytes(toAddr(0x100000), bytes) != bytes.length)
            throw new IllegalStateException("Map");
        String hash = HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(bytes));
        if (!hash.equals("834938d18d2b7c688311c46c27bed813d0d7a9f8e3cbb61da8a6a3f23d360ebd"))
            throw new IllegalStateException("Hash");
        Files.createDirectories(out);
        Set<Long> targets = new TreeSet<>();
        for (long target : new long[]{0x113d58,0x2c43b4,0x1245f0,0x1244e8,0x2c3afc,0x2c3a78}) targets.add(target);
        var registration = getFunctionContaining(toAddr(0x10d114));
        if (registration == null) throw new IllegalStateException("Missing worker registration");
        targets.add(registration.getEntryPoint().getOffset());
        try (PrintWriter hits = new PrintWriter(Files.newBufferedWriter(out.resolve("field-hits.tsv")))) {
            for (var ins : currentProgram.getListing().getInstructions(true)) {
                String text = ins.toString();
                if (!text.contains("#0x130") && !text.contains("#0x134")) continue;
                var f = getFunctionContaining(ins.getAddress());
                hits.printf("%s\t%s\t%s%n",ins.getAddress(),f == null ? "unknown" : f.getEntryPoint(),text);
                // Offset hits are leads, not proof of a descriptor access.
            }
        }
        DecompInterface decomp = new DecompInterface();
        try (PrintWriter listing = new PrintWriter(Files.newBufferedWriter(out.resolve("listing.txt")));
             PrintWriter pseudo = new PrintWriter(Files.newBufferedWriter(out.resolve("pseudocode.c")));
             PrintWriter refs = new PrintWriter(Files.newBufferedWriter(out.resolve("references.tsv")))) {
            decomp.openProgram(currentProgram);
            for (long target : targets) {
                var f = getFunctionAt(toAddr(target));
                if (f == null) throw new IllegalStateException("Missing function " + Long.toHexString(target));
                listing.printf("\nFUNCTION %s %s%n", f.getEntryPoint(), f.getName());
                for (var cu : currentProgram.getListing().getCodeUnits(f.getBody(),true))
                    listing.printf("%s %s %s%n",cu.getAddress(),HexFormat.of().formatHex(cu.getBytes()),cu);
                var result = decomp.decompileFunction(f,60,monitor);
                if (!result.decompileCompleted()) throw new IllegalStateException(result.getErrorMessage());
                pseudo.printf("\n/* %s GENERATED ANALYSIS */\n%s%n", f.getEntryPoint(),result.getDecompiledFunction().getC());
                for (var ref : getReferencesTo(toAddr(target)))
                    refs.printf("%08x\t%s\t%s%n",target,ref.getFromAddress(),ref.getReferenceType());
            }
        } finally { decomp.dispose(); }
        Files.writeString(out.resolve("COMPLETE.txt"),"mapped_sha256="+hash+"\n");
        println("SMT4_WORKER_INSPECT_OK");
    }
}
