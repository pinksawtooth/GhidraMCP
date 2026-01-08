package com.lauriewired.handlers.get;

import com.lauriewired.handlers.Handler;
import com.sun.net.httpserver.HttpExchange;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.util.task.TaskMonitor;

import java.io.IOException;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

import static com.lauriewired.util.ParseUtils.parseQueryParams;
import static com.lauriewired.util.ParseUtils.parseIntOrDefault;
import static com.lauriewired.util.ParseUtils.sendResponse;
import static ghidra.program.util.GhidraProgramUtilities.getCurrentProgram;

/**
 * Handler for GET requests to retrieve a call graph starting from a function.
 * Returns a simple indented tree showing the call hierarchy.
 */
public class GetCallGraph extends Handler {
    public GetCallGraph(PluginTool tool) {
        super(tool, "/get_call_graph");
    }

    @Override
    public void handle(HttpExchange exchange) throws IOException {
        Map<String, String> qparams = parseQueryParams(exchange);
        String addressStr = qparams.get("address");
        int maxDepth = parseIntOrDefault(qparams.get("depth"), 20);
        boolean includeRuntime = "true".equalsIgnoreCase(qparams.get("include_runtime"));
        sendResponse(exchange, getCallGraph(addressStr, maxDepth, includeRuntime));
    }

    /**
     * Generates a call graph starting from the specified function.
     *
     * @param identifier Function name or address (required)
     * @param maxDepth Maximum depth to traverse (default: 20)
     * @param includeRuntime Whether to include runtime/compiler functions (default: false)
     * @return A string representation of the call graph
     */
    private String getCallGraph(String identifier, int maxDepth, boolean includeRuntime) {
        try {
            Program currentProgram = getCurrentProgram(tool);
            if (currentProgram == null) {
                return "No program loaded";
            }

            if (identifier == null || identifier.isEmpty()) {
                return "Function name or address is required";
            }

            Function startFunction = findFunction(currentProgram, identifier);
            if (startFunction == null) {
                return "No function found with identifier: " + identifier;
            }

            StringBuilder result = new StringBuilder();
            Set<String> visited = new HashSet<>();
            buildCallGraph(currentProgram, startFunction, 0, maxDepth, includeRuntime, visited, result);

            return result.toString();
        } catch (Exception e) {
            return "Error generating call graph: " + e.getMessage();
        }
    }

    /**
     * Finds a function by name or address.
     * Handles multiple address formats: "FUN_001015fc", "001015fc", "0x001015fc"
     *
     * @param program The current program
     * @param identifier Function name or address string
     * @return The function if found, null otherwise
     */
    private Function findFunction(Program program, String identifier) {
        // First, try to find by exact function name
        for (Function func : program.getFunctionManager().getFunctions(true)) {
            if (func.getName().equals(identifier) || func.getName(true).equals(identifier)) {
                return func;
            }
        }

        // Try to parse as address with different formats
        String normalizedAddr = identifier.trim();

        // If it doesn't start with 0x, try adding it
        if (!normalizedAddr.startsWith("0x") && !normalizedAddr.startsWith("0X")) {
            normalizedAddr = "0x" + normalizedAddr;
        }

        try {
            Address address = program.getAddressFactory().getAddress(normalizedAddr);
            if (address != null) {
                return program.getFunctionManager().getFunctionContaining(address);
            }
        } catch (Exception e) {
            // If address parsing fails, try without 0x prefix
            try {
                normalizedAddr = identifier.replace("0x", "").replace("0X", "");
                Address address = program.getAddressFactory().getAddress(normalizedAddr);
                if (address != null) {
                    return program.getFunctionManager().getFunctionContaining(address);
                }
            } catch (Exception ex) {
                // Ignore and return null
            }
        }

        return null;
    }

    /**
     * Recursively builds the call graph.
     *
     * @param program The current program
     * @param function The current function to process
     * @param currentDepth Current recursion depth
     * @param maxDepth Maximum allowed depth
     * @param includeRuntime Whether to include runtime/compiler functions
     * @param visited Set of already visited function addresses
     * @param result StringBuilder to accumulate the output
     */
    private void buildCallGraph(Program program, Function function, int currentDepth,
                                int maxDepth, boolean includeRuntime, Set<String> visited, StringBuilder result) {
        // Add indentation based on depth
        for (int i = 0; i < currentDepth; i++) {
            result.append("  ");
        }

        // Get function name and address
        String functionName = function.getName(true);
        Address entryPoint = function.getEntryPoint();
        String addressStr = entryPoint != null ? entryPoint.toString() : "unknown";

        // Format address to hex with 0x prefix
        if (!addressStr.equals("unknown") && !addressStr.startsWith("0x")) {
            addressStr = "0x" + addressStr;
        }

        // Add function to output
        result.append(functionName).append(" (").append(addressStr).append(")\n");

        // Mark as visited using address as key
        String functionKey = entryPoint != null ? entryPoint.toString() : functionName;
        visited.add(functionKey);

        // Check if we've reached max depth
        if (currentDepth >= maxDepth) {
            // Check if there are more callees
            Set<Function> callees = function.getCalledFunctions(TaskMonitor.DUMMY);
            if (callees != null && !callees.isEmpty()) {
                for (int i = 0; i <= currentDepth; i++) {
                    result.append("  ");
                }
                result.append("[MAX_DEPTH]\n");
            }
            return;
        }

        // Get all functions called by this function
        Set<Function> callees = function.getCalledFunctions(TaskMonitor.DUMMY);

        // Handle thunk functions
        if ((callees == null || callees.isEmpty()) && function.isThunk()) {
            Function thunkedFunction = function.getThunkedFunction(false);
            if (thunkedFunction != null) {
                callees = thunkedFunction.getCalledFunctions(TaskMonitor.DUMMY);
            }
        }

        if (callees != null) {
            for (Function callee : callees) {
                if (callee == null) {
                    continue;
                }

                // Skip external/imported functions and thunks
                // Linux: externals are thunks (isThunk=true, isExternal=false)
                // Windows: externals are either thunks OR true externals (isExternal=true)
                if (callee.isExternal() || callee.isThunk()) {
                    continue;
                }

                // Skip runtime/compiler functions if not included
                if (!includeRuntime) {
                    String simpleName = callee.getName();
                    if (simpleName != null && (simpleName.startsWith("_") || simpleName.startsWith("__"))) {
                        continue;
                    }
                }

                // Skip if already visited (show each function only once)
                Address calleeEntry = callee.getEntryPoint();
                String calleeName = callee.getName(true);
                String calleeKey = calleeEntry != null ? calleeEntry.toString() : calleeName;
                if (visited.contains(calleeKey)) {
                    continue;
                }

                // Recursively process callee
                buildCallGraph(program, callee, currentDepth + 1, maxDepth, includeRuntime, visited, result);
            }
        }
    }
}
