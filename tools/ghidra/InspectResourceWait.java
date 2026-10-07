// Bounded read-only export of wait loop and synchronization/timing dependencies.
// @category SMT4
import ghidra.app.script.GhidraScript;
import ghidra.app.decompiler.DecompInterface;
import java.nio.file.*;
import java.io.*;
import java.security.MessageDigest;
import java.util.*;

public class InspectResourceWait extends GhidraScript {
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
        long[] targets = {0x1181b0,0x2c4298,0x2bb4f0,0x1382bc,0x1382e4,
                          0x1464f8,0x138fc0,0x2a88fc};
        DecompInterface decomp = new DecompInterface();
        try (PrintWriter listing = new PrintWriter(Files.newBufferedWriter(out.resolve("listing.txt")));
             PrintWriter pseudo = new PrintWriter(Files.newBufferedWriter(out.resolve("pseudocode.c")));
             PrintWriter refs = new PrintWriter(Files.newBufferedWriter(out.resolve("references.tsv")))) {
            decomp.openProgram(currentProgram);
            for (long target : targets) {
                var f = getFunctionAt(toAddr(target));
                if (f == null && (target == 0x1382bc || target == 0x1382e4 || target == 0x138fc0)) {
                    // These tail targets may belong to another automatically inferred body.
                    long stop = target == 0x1382bc ? 0x1382cc : target == 0x1382e4 ? 0x1382ec : 0x139010;
                    listing.printf("\nTAIL TARGET %08x (no separate function object)%n",target);
                    for (long pc=target;pc<stop;pc+=4) {
                        var instruction=getInstructionAt(toAddr(pc));
                        if (instruction==null) throw new IllegalStateException("Missing instruction");
                        listing.printf("%s %s %s%n",instruction.getAddress(),
                            HexFormat.of().formatHex(instruction.getBytes()),instruction);
                    }
                    for (var ref : getReferencesTo(toAddr(target)))
                        refs.printf("%08x\t%s\t%s%n",target,ref.getFromAddress(),ref.getReferenceType());
                    continue;
                }
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
        println("SMT4_WAIT_INSPECT_OK");
    }
}
