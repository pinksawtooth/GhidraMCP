package com.lauriewired.handlers.get;

import com.lauriewired.handlers.Handler;
import com.sun.net.httpserver.HttpExchange;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;

import java.io.IOException;
import java.util.Map;

import static com.lauriewired.util.ParseUtils.parseQueryParams;
import static com.lauriewired.util.ParseUtils.sendResponse;
import static ghidra.program.util.GhidraProgramUtilities.getCurrentProgram;

/**
 * Handler to get function details by address
 */
public final class GetFunctionByAddress extends Handler {
	public GetFunctionByAddress(PluginTool tool) {
		super(tool, "/get_function_by_address");
	}

	/**
	 * Handle HTTP GET request to retrieve function details by address
	 *
	 * @param exchange the HTTP exchange
	 * @throws IOException if an I/O error occurs
	 */
	@Override
	public void handle(HttpExchange exchange) throws IOException {
		Map<String, String> qparams = parseQueryParams(exchange);
		String address = qparams.get("address");
		sendResponse(exchange, getFunctionByAddress(address));
	}

	/**
	 * Retrieves function details by address
	 *
	 * @param addressStr the address as a string
	 * @return a string containing function details or an error message
	 */
	private String getFunctionByAddress(String addressStr) {
		Program program = getCurrentProgram(tool);
		if (program == null)
			return "No program loaded";
		if (addressStr == null || addressStr.isEmpty())
			return "Address is required";

		try {
			Address addr = program.getAddressFactory().getAddress(addressStr);
			Function func = program.getFunctionManager().getFunctionAt(addr);

			if (func == null)
				return "No function found at address " + addressStr;

			return String.format("Function: %s at %s\nSignature: %s\nEntry: %s\nBody: %s - %s",
					func.getName(),
					func.getEntryPoint(),
					func.getSignature(),
					func.getEntryPoint(),
					func.getBody().getMinAddress(),
					func.getBody().getMaxAddress());
		} catch (Exception e) {
			return "Error getting function: " + e.getMessage();
		}
	}
}
