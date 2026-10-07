// Bounded read-only export of asynchronous request and immediate dependencies.
// @category SMT4
import ghidra.app.script.GhidraScript;
import ghidra.app.decompiler.DecompInterface;
import java.nio.file.*;
import java.io.*;
import java.security.MessageDigest;
import java.util.*;

public class InspectResourceRequest extends GhidraScript {
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
        long[] targets = {0x2b6820,0x2ae72c,0x155b30,0x155bbc,0x2c43b4};
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
        println("SMT4_REQUEST_INSPECT_OK");
    }
}
