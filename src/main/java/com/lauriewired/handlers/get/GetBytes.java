package com.lauriewired.handlers.get;

import com.lauriewired.handlers.Handler;
import com.sun.net.httpserver.HttpExchange;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Program;

import java.io.IOException;
import java.util.*;

import static com.lauriewired.util.ParseUtils.*;
import static ghidra.program.util.GhidraProgramUtilities.getCurrentProgram;

/**
 * Handler to get bytes from a specified address in the current program.
 * Expects query parameters: address=<address> and size=<size>.
 */
public final class GetBytes extends Handler {
	/**
	 * Constructor for the GetBytes handler.
	 * 
	 * @param tool The PluginTool instance to use.
	 */
	public GetBytes(PluginTool tool) {
		super(tool, "/get_bytes");
	}

	/**
	 * Parses the query parameters from the HTTP exchange.
	 * 
	 * @param exchange The HTTP exchange containing the request.
	 * @return A map of query parameters.
	 */
	@Override
	public void handle(HttpExchange exchange) throws IOException {
		Map<String, String> qparams = parseQueryParams(exchange);
		String addrStr = qparams.get("address");
		int size = parseIntOrDefault(qparams.get("size"), 1);
		sendResponse(exchange, getBytes(addrStr, size));
	}

	/**
	 * Gets the bytes from the specified address in the current program.
	 * 
	 * @param addressStr The address to read from.
	 * @param size       The number of bytes to read.
	 * @return A string representation of the bytes in hex format.
	 */
	private String getBytes(String addressStr, int size) {
		Program program = getCurrentProgram(tool);
		if (program == null)
			return "No program loaded";
		if (addressStr == null || addressStr.isEmpty())
			return "Address is required";
		if (size <= 0)
			return "Size must be > 0";

		try {
			Address addr = program.getAddressFactory().getAddress(addressStr);
			byte[] buf = new byte[size];
			int read = program.getMemory().getBytes(addr, buf);
			return hexdump(addr, buf, read);
		} catch (Exception e) {
			return "Error reading memory: " + e.getMessage();
		}
	}
}