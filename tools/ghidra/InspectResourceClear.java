// @category SMT4
import ghidra.app.script.GhidraScript;
import java.nio.file.*;
public class InspectResourceClear extends GhidraScript {
    public void run() throws Exception {
        StringBuilder s=new StringBuilder();
        for(long[] range:new long[][]{{0x139f54,0x139f84},{0x2c3b9c,0x2c3bdc},{0x2c4b88,0x2c4bd8}}) {
            var f=getFunctionAt(toAddr(range[0]));
            s.append(String.format("%08x saved=%s%n",range[0],f==null?"none":f.getBody()));
            for(long pc=range[0];pc<range[1];pc+=4) {
                var i=getInstructionAt(toAddr(pc));
                s.append(String.format("%08x %s%n",pc,i));
            }
        }
        Files.writeString(Path.of(getScriptArgs()[0]).resolve("static-ghidra.txt"),s);
        println("SMT4_CLEAR_INSPECT_OK");
    }
}
