// Ghidra post-script used by agent.py when GHIDRA_HEADLESS is configured.

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolIterator;
import ghidra.program.model.symbol.SymbolTable;

public class ExtractFacts extends GhidraScript {
    @Override
    public void run() throws Exception {
        String query = getScriptArgs().length > 0 ? getScriptArgs()[0] : "summary";
        println("Ghidra ExtractFacts query=" + query);
        println("Program: " + currentProgram.getName());
        println("Image base: " + currentProgram.getImageBase());

        println("External/import-like symbols discovered by Ghidra:");
        SymbolTable symbols = currentProgram.getSymbolTable();
        SymbolIterator it = symbols.getAllSymbols(true);
        while (it.hasNext()) {
            Symbol symbol = it.next();
            String name = symbol.getName();
            if (name.contains("fgets") || name.contains("strcpy") || name.contains("strlen")
                    || name.contains("strcspn") || name.contains("malloc") || name.contains("free")) {
                println(symbol.getAddress() + " " + name);
            }
        }

        if (query.equals("strings")) {
            println("Defined strings:");
            Data data = getFirstData();
            while (data != null) {
                if (data.hasStringValue()) {
                    println(data.getAddress() + " " + data.getValue());
                }
                data = getDataAfter(data);
            }
        }

        println("Functions discovered by Ghidra:");
        FunctionIterator funcs = currentProgram.getFunctionManager().getFunctions(true);
        while (funcs.hasNext()) {
            Function f = funcs.next();
            println(f.getEntryPoint() + " " + f.getName());
        }

        if (query.equals("copy_flow")) {
            println("Relevant instructions in function 0x401264:");
            Address start = toAddr(0x401264);
            Function f = getFunctionContaining(start);
            if (f != null) {
                InstructionIterator insts = currentProgram.getListing().getInstructions(f.getBody(), true);
                while (insts.hasNext()) {
                    Instruction ins = insts.next();
                    long off = ins.getAddress().getOffset();
                    if (off >= 0x40130a && off <= 0x401382) {
                        println(ins.getAddress() + " " + ins.toString());
                    }
                }
            } else {
                println("No Ghidra function found at 0x401264");
            }
            println("Expected key evidence: call at 0x40131b reaches fgets; call at 0x401382 reaches __strcpy_chk.");
        }
    }
}
