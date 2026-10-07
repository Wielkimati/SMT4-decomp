// Local analysis artifacts only: no export is recovered or runtime-verified source.
// @category SMT4
import ghidra.app.script.GhidraScript;
import ghidra.app.decompiler.DecompInterface;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.*;
import java.nio.file.*;
import java.io.*;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.HexFormat;

public class ExportSmt4 extends GhidraScript {
    private void checkMode(long address, int expected) {
        var value = currentProgram.getProgramContext().getValue(
            currentProgram.getRegister("TMode"), toAddr(address), false);
        if (value == null || value.intValue() != expected || getInstructionAt(toAddr(address)) == null)
            throw new IllegalStateException("Unexpected instruction/mode at " + toAddr(address));
    }

    @Override public void run() throws Exception {
        Path out = Path.of(getScriptArgs()[0]);
        if (Files.exists(out)) throw new IllegalArgumentException("Export directory must be new");
        Files.createDirectories(out);
        byte[] mapped = new byte[0x377000];
        if (currentProgram.getMemory().getBytes(toAddr(0x100000), mapped) != mapped.length)
            throw new IllegalStateException("Incomplete initialized map");
        String hash = HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(mapped));
        if (!hash.equals("834938d18d2b7c688311c46c27bed813d0d7a9f8e3cbb61da8a6a3f23d360ebd"))
            throw new IllegalStateException("Mapped bytes differ from expanded input");
        long[] targets = {0x100024, 0x10236c, 0x106d58, 0x104ef4, 0x100cb8,
            0x102338, 0x1023c0, 0x101308, 0x101300};
        for (int i = 0; i < targets.length; i++) {
            checkMode(0x100000 + i * 4, 0);
            var flows = getInstructionAt(toAddr(0x100000 + i * 4)).getFlows();
            if (flows.length != 1 || flows[0].getOffset() != targets[i])
                throw new IllegalStateException("Startup branch target mismatch");
            checkMode(targets[i], i == 4 ? 1 : 0);
        }
        if (getInt(toAddr(0x100040)) != 0x477000 || getInt(toAddr(0x100044)) != 0x4efe34)
            throw new IllegalStateException("BSS literal mismatch");
        try (PrintWriter w = new PrintWriter(Files.newBufferedWriter(out.resolve("symbols.tsv")))) {
            w.println("address\tname\tkind\tsource");
            for (Symbol s : currentProgram.getSymbolTable().getAllSymbols(true))
                if (s.getSource() == SourceType.USER_DEFINED)
                    w.printf("%s\t%s\t%s\t%s%n", s.getAddress(), s.getName(),
                        s.getSymbolType(), s.getSource());
        }
        try (PrintWriter w = new PrintWriter(Files.newBufferedWriter(out.resolve("memory-map.tsv")))) {
            w.println("name\tstart\tend_inclusive\tinitialized\tread\twrite\texecute");
            for (MemoryBlock b : currentProgram.getMemory().getBlocks())
                w.printf("%s\t%s\t%s\t%b\t%b\t%b\t%b%n", b.getName(), b.getStart(),
                    b.getEnd(), b.isInitialized(), b.isRead(), b.isWrite(), b.isExecute());
        }
        try (PrintWriter w = new PrintWriter(Files.newBufferedWriter(out.resolve("functions.tsv")))) {
            w.println("address\tname\tTMode\tbody_bytes");
            for (Function f : currentProgram.getFunctionManager().getFunctions(true))
                w.printf("%s\t%s\t%s\t%d%n", f.getEntryPoint(), f.getName(),
                    currentProgram.getProgramContext().getValue(currentProgram.getRegister("TMode"),
                        f.getEntryPoint(), false), f.getBody().getNumAddresses());
        }
        try (PrintWriter w = new PrintWriter(Files.newBufferedWriter(out.resolve("startup-listing.txt")))) {
            var it = currentProgram.getListing().getCodeUnits(toAddr(0x100000), true);
            while (it.hasNext()) {
                CodeUnit cu = it.next();
                if (cu.getAddress().getOffset() >= 0x103000) break;
                w.printf("%s  %-24s %s%n", cu.getAddress(),
                    HexFormat.of().formatHex(cu.getBytes()), cu.toString());
            }
        }
        DecompInterface decomp = new DecompInterface();
        try {
            decomp.openProgram(currentProgram);
            try (PrintWriter w = new PrintWriter(Files.newBufferedWriter(out.resolve("startup-pseudocode.c")))) {
                w.println("/* GENERATED ANALYSIS ONLY. Not recovered source; not runtime verified. */");
                long[] decompileTargets = {0x100000, 0x100024, 0x100cb8, 0x101300, 0x101308,
                    0x102338, 0x10236c, 0x1023c0, 0x104ef4, 0x106d58};
                for (long address : decompileTargets) {
                    Function f = currentProgram.getFunctionManager().getFunctionAt(toAddr(address));
                    if (f == null) continue;
                    var result = decomp.decompileFunction(f, 60, monitor);
                    w.printf("\n/* %s %s */%n", f.getEntryPoint(), f.getName());
                    if (result.decompileCompleted()) w.println(result.getDecompiledFunction().getC());
                    else w.println("/* Failed: " + result.getErrorMessage() + " */");
                }
            }
        } finally { decomp.dispose(); }
        Files.writeString(out.resolve("COMPLETE.txt"),
            "mapped_sha256=" + hash + "\nstartup_branches_and_modes=verified\nbss_literals=verified\nfunctions=" +
            currentProgram.getFunctionManager().getFunctionCount() + "\n", StandardCharsets.UTF_8,
            StandardOpenOption.CREATE_NEW);
        println("SMT4_EXPORT_OK " + hash);
    }
}
