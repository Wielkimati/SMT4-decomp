// @category SMT4
import ghidra.app.script.GhidraScript;
import java.nio.file.*;
public class InspectResourceRecursiveLock extends GhidraScript {
    public void run() throws Exception {
        StringBuilder s=new StringBuilder();
        for(long[] range:new long[][]{{0x2c3afc,0x2c3b34},{0x2c3a78,0x2c3a98}}) {
            var f=getFunctionAt(toAddr(range[0]));
            if(f==null || f.getBody().getMinAddress().getOffset()!=range[0] ||
                    f.getBody().getMaxAddress().getOffset()!=range[1]-1)
                throw new IllegalStateException("Saved function extent");
            s.append(String.format("%08x saved=%s%n",range[0],f.getBody()));
            for(long pc=range[0];pc<range[1];pc+=4)
                s.append(String.format("%08x %s%n",pc,getInstructionAt(toAddr(pc))));
        }
        Files.writeString(Path.of(getScriptArgs()[0]).resolve("static-ghidra.txt"),s);
        println("SMT4_RECURSIVE_LOCK_INSPECT_OK");
    }
}
