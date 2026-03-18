/*
 * Ghidra headless postScript: ExportMalhausSummary.java
 * -postScript ExportMalhausSummary.java <output_json_path>
 */
import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.*;
import ghidra.program.model.address.*;
import ghidra.program.model.lang.*;
import ghidra.program.model.data.*;

import java.io.*;
import java.util.*;

public class ExportMalhausSummary extends GhidraScript {

    private static String esc(String s) {
        if (s == null) return "";
        return s.replace("\\", "\\\\")
                .replace("\"", "\\\"")
                .replace("\r", "\\r")
                .replace("\n", "\\n")
                .replace("\t", "\\t");
    }

    private static void kv(StringBuilder sb, String k, String v, boolean comma) {
        sb.append("\"").append(esc(k)).append("\":\"").append(esc(v)).append("\"");
        if (comma) sb.append(",");
    }

    @Override
    public void run() throws Exception {
        if (currentProgram == null) {
            println("No current program.");
            return;
        }
        String outPath = (getScriptArgs().length >= 1) ? getScriptArgs()[0] : null;
        if (outPath == null || outPath.trim().isEmpty()) {
            println("Missing output path argument.");
            return;
        }

        Listing listing = currentProgram.getListing();
        SymbolTable symtab = currentProgram.getSymbolTable();
        FunctionManager fm = currentProgram.getFunctionManager();
        Language lang = currentProgram.getLanguage();
        CompilerSpec cs = currentProgram.getCompilerSpec();

        String format = currentProgram.getExecutableFormat();
        String arch = (lang != null) ? lang.getProcessor().toString() : "";
        String endian = (lang != null) ? (lang.isBigEndian() ? "big" : "little") : "";
        String compiler = (cs != null) ? cs.getCompilerSpecDescription().getName() : "";
        Address entry = currentProgram.getEntryPoint();

        // Imports (external symbols)
        List<String> imports = new ArrayList<>();
        SymbolIterator it = symtab.getExternalSymbols();
        int importLimit = 300;
        while (it.hasNext() && imports.size() < importLimit) {
            Symbol s = it.next();
            String name = s.getName(true);
            if (name != null && !name.isEmpty()) imports.add(name);
        }

        // Functions
        List<Map<String,String>> funcs = new ArrayList<>();
        FunctionIterator fit = fm.getFunctions(true);
        int funcLimit = 400;
        while (fit.hasNext() && funcs.size() < funcLimit) {
            Function f = fit.next();
            Map<String,String> m = new HashMap<>();
            m.put("name", f.getName());
            m.put("entry", f.getEntryPoint().toString());
            funcs.add(m);
        }

        // Strings (defined string data)
        List<String> strings = new ArrayList<>();
        DataIterator dit = listing.getDefinedData(true);
        int stringLimit = 250;
        while (dit.hasNext() && strings.size() < stringLimit) {
            Data d = dit.next();
            DataType dt = d.getDataType();
            if (dt != null && dt.getName() != null) {
                String t = dt.getName().toLowerCase();
                if (t.contains("string")) {
                    try {
                        Object val = d.getValue();
                        if (val != null) {
                            String sv = val.toString();
                            if (sv.length() > 200) sv = sv.substring(0, 200);
                            strings.add(sv);
                        }
                    } catch (Exception e) {}
                }
            }
        }

        StringBuilder sb = new StringBuilder();
        sb.append("{");
        kv(sb, "executable_format", format, true);
        kv(sb, "arch", arch, true);
        kv(sb, "endian", endian, true);
        kv(sb, "compiler", compiler, true);
        kv(sb, "entrypoint", (entry != null ? entry.toString() : ""), true);

        sb.append("\"imports\":[");
        for (int i=0;i<imports.size();i++){
            sb.append("\"").append(esc(imports.get(i))).append("\"");
            if (i+1<imports.size()) sb.append(",");
        }
        sb.append("],");

        sb.append("\"functions\":[");
        for (int i=0;i<funcs.size();i++){
            Map<String,String> m = funcs.get(i);
            sb.append("{");
            kv(sb, "name", m.get("name"), true);
            kv(sb, "entry", m.get("entry"), false);
            sb.append("}");
            if (i+1<funcs.size()) sb.append(",");
        }
        sb.append("],");

        sb.append("\"strings\":[");
        for (int i=0;i<strings.size();i++){
            sb.append("\"").append(esc(strings.get(i))).append("\"");
            if (i+1<strings.size()) sb.append(",");
        }
        sb.append("]");

        sb.append("}");

        File f = new File(outPath);
        f.getParentFile().mkdirs();
        try (FileWriter w = new FileWriter(f)) {
            w.write(sb.toString());
        }
        println("Wrote summary to: " + outPath);
    }
}
