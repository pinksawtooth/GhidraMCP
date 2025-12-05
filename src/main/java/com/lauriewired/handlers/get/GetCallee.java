package com.lauriewired.handlers.get;

import com.lauriewired.handlers.Handler;
import com.sun.net.httpserver.HttpExchange;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.util.task.TaskMonitor;
import com.google.gson.Gson;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Comparator;
import java.util.List;
import java.util.Map;
import java.util.Set;

import static com.lauriewired.util.ParseUtils.parseQueryParams;
import static com.lauriewired.util.ParseUtils.sendResponse;
import static ghidra.program.util.GhidraProgramUtilities.getCurrentProgram;

/**
 * Handler for GET requests to retrieve the callees of a function at a specific address.
 * Returns JSON array of objects: [{"name": string, "address": string|null, "external": boolean}]
 */
public class GetCallee extends Handler {
    public GetCallee(PluginTool tool) {
        super(tool, "/get_callee");
    }

    @Override
    public void handle(HttpExchange exchange) throws IOException {
        Map<String, String> qparams = parseQueryParams(exchange);
        String addressStr = qparams.get("address");
        sendResponse(exchange, getCallee(addressStr));
    }

    /**
     * Retrieves the callees of a function at the specified address and encodes as JSON.
     */
    private String getCallee(String addressStr) {
        if (addressStr == null) {
            return "[]"; // Missing address parameter
        }

        try {
            Program currentProgram = getCurrentProgram(tool);
            if (currentProgram == null) {
                return "[]"; // No active program
            }

            Address address = currentProgram.getAddressFactory().getAddress(addressStr);
            Function fn = currentProgram.getFunctionManager().getFunctionContaining(address);
            if (fn == null) {
                return "[]"; // No function at the specified address
            }

            Set<Function> calleeSet = fn.getCalledFunctions(TaskMonitor.DUMMY);
            if (calleeSet.isEmpty() && fn.isThunk()) {
                Function thunkedFunction = fn.getThunkedFunction(false);
                if (thunkedFunction != null) {
                    calleeSet = thunkedFunction.getCalledFunctions(TaskMonitor.DUMMY);
                }
            }

            List<Function> callees = new ArrayList<>(calleeSet);
            // Sort for stable output
            Collections.sort(callees, Comparator.comparing(f -> f.getName(true), String.CASE_INSENSITIVE_ORDER));

            List<Map<String, Object>> out = new ArrayList<>();
            for (Function callee : callees) {
                String name = callee.getName(true);
                Address ep = callee.getEntryPoint();
                boolean external = false;
                String addrOut = null;
                if (ep != null) {
                    String epStr = ep.toString();
                    if (epStr != null && epStr.toUpperCase().startsWith("EXTERNAL:")) {
                        external = true;
                    } else if (epStr != null && !epStr.isEmpty()) {
                        String hex = epStr.startsWith("0x") ? epStr : ("0x" + epStr);
                        addrOut = hex.toLowerCase();
                    }
                }
                if (name != null && name.contains("FUN_")) {
                    external = false;
                }
                Map<String, Object> obj = new java.util.HashMap<>();
                obj.put("name", name);
                obj.put("address", (addrOut == null || external) ? null : addrOut);
                obj.put("external", external);
                out.add(obj);
            }
            Gson gson = new Gson();
            return gson.toJson(out);
        } catch (Exception e) {
            return "[]"; // On error, return empty list for robustness
        }
    }
}
