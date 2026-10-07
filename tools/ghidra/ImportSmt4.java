// Map the pinned, already expanded EU executable before automatic analysis.
// @category SMT4
import ghidra.app.script.GhidraScript;
import ghidra.program.model.mem.MemoryBlock;
import java.io.ByteArrayInputStream;
import java.math.BigInteger;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.util.HexFormat;

public class ImportSmt4 extends GhidraScript {
    private void block(String name, long address, byte[] code, int offset, int size,
            boolean write, boolean execute) throws Exception {
        MemoryBlock b = currentProgram.getMemory().createInitializedBlock(name,
            toAddr(address), new ByteArrayInputStream(code, offset, size), size, monitor, false);
        b.setRead(true);
        b.setWrite(write);
        b.setExecute(execute);
        b.setComment("Expanded .code file offset " + String.format("0x%08x", offset));
    }

    @Override public void run() throws Exception {
        byte[] code = Files.readAllBytes(Path.of(getScriptArgs()[0]));
        String hash = HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(code));
        if (!hash.equals("834938d18d2b7c688311c46c27bed813d0d7a9f8e3cbb61da8a6a3f23d360ebd"))
            throw new IllegalArgumentException("Not the pinned expanded EU executable");
        if (!currentProgram.getLanguageID().toString().equals("ARM:LE:32:v6"))
            throw new IllegalArgumentException("Expected ARM:LE:32:v6");
        if (currentProgram.getMemory().getBlocks().length != 1 ||
                currentProgram.getListing().getNumInstructions() != 0)
            throw new IllegalStateException("Requires a fresh, unanalyzed binary import");
        currentProgram.getMemory().removeBlock(currentProgram.getMemory().getBlocks()[0], monitor);
        block(".text", 0x100000, code, 0, 0x2fe69c, false, true);
        block(".text_padding", 0x3fe69c, code, 0x2fe69c, 0x964, false, false);
        block(".rodata", 0x3ff000, code, 0x2ff000, 0x2bb78, false, false);
        block(".rodata_padding", 0x42ab78, code, 0x32ab78, 0x488, false, false);
        block(".data", 0x42b000, code, 0x32b000, 0x4b644, true, false);
        block(".data_padding", 0x476644, code, 0x376644, 0x9bc, true, false);
        MemoryBlock bss = currentProgram.getMemory().createUninitializedBlock(
            ".bss_startup_zeroed", toAddr(0x477000), 0x78e34, false);
        bss.setRead(true);
        bss.setWrite(true);
        bss.setExecute(false);
        bss.setComment("Startup 0x00100024 clears [0x00477000,0x004efe34). " +
            "ExHeader data end + BSS size also equals 0x004efe34. Runtime not yet checked.");
        currentProgram.getProgramContext().setValue(currentProgram.getRegister("TMode"),
            toAddr(0x100000), toAddr(0x10003f), BigInteger.ZERO);
        createLabel(toAddr(0x100000), "entry_startup", true);
        createLabel(toAddr(0x100024), "startup_zero_bss", true);
        createLabel(toAddr(0x477000), "startup_zero_begin", true);
        createLabel(toAddr(0x4efe34), "startup_zero_end_exclusive", true);
        currentProgram.getSymbolTable().addExternalEntryPoint(toAddr(0x100000));
        setPlateComment(toAddr(0x100024),
            "Confirmed static: zero words from 0x00477000 up to 0x004efe34 exclusive. " +
            "Descriptive project name, not an original symbol. Runtime verification pending.");
        setEOLComment(toAddr(0x476644),
            "ExHeader initialized data ends here; 0x9bc file-backed zero padding precedes startup clear range.");
        disassemble(toAddr(0x100000));
        createFunction(toAddr(0x100000), "entry_startup");
        createFunction(toAddr(0x100024), "startup_zero_bss");
        println("SMT4_MAP_OK " + hash);
    }
}
