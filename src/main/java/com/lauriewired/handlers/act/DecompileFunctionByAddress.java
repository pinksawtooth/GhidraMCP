package com.lauriewired.handlers.act;

import com.lauriewired.handlers.Handler;
import com.sun.net.httpserver.HttpExchange;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.util.task.ConsoleTaskMonitor;

import java.io.IOException;
import java.util.Map;

import static com.lauriewired.util.ParseUtils.parseQueryParams;
import static com.lauriewired.util.ParseUtils.sendResponse;
import static ghidra.program.util.GhidraProgramUtilities.getCurrentProgram;

/**
 * Handler to decompile a function by its address in the current program.
 * This handler responds to HTTP requests with the decompiled C code of the function
 * at the specified address.
 */
public final class DecompileFunctionByAddress extends Handler {
	/**
	 * Constructor for the DecompileFunctionByAddress handler
	 *
	 * @param tool the PluginTool instance to interact with Ghidra
	 */
	public DecompileFunctionByAddress(PluginTool tool) {
		super(tool, "/decompile_function");
	}

	/**
	 * Handles HTTP requests to decompile a function by its address.
	 * Expects a query parameter "address" with the function's address.
	 *
	 * @param exchange the HttpExchange object representing the HTTP request
	 * @throws IOException if an I/O error occurs during handling
	 */
	@Override
	public void handle(HttpExchange exchange) throws IOException {
		Map<String, String> qparams = parseQueryParams(exchange);
		String address = qparams.get("address");
		sendResponse(exchange, decompileFunctionByAddress(address));
	}

	/**
	 * Decompiles the function at the specified address in the current program.
	 *
	 * @param addressStr the address of the function to decompile
	 * @return the decompiled C code or an error message
	 */
	private String decompileFunctionByAddress(String addressStr) {
		Program program = getCurrentProgram(tool);
		if (program == null)
			return "No program loaded";
		if (addressStr == null || addressStr.isEmpty())
			return "Address is required";

		try {
			Address addr = program.getAddressFactory().getAddress(addressStr);
			Function func = program.getListing().getFunctionContaining(addr);
			if (func == null)
				return "No function found at or containing address " + addressStr;

			DecompInterface decomp = new DecompInterface();
			decomp.openProgram(program);
			DecompileResults result = decomp.decompileFunction(func, 30, new ConsoleTaskMonitor());

			return (result != null && result.decompileCompleted())
					? result.getDecompiledFunction().getC()
					: "Decompilation failed";
		} catch (Exception e) {
			return "Error decompiling function: " + e.getMessage();
		}
	}
}
