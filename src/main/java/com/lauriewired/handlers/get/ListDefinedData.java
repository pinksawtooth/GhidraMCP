package com.lauriewired.handlers.get;

import com.lauriewired.handlers.Handler;
import com.sun.net.httpserver.HttpExchange;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.DataIterator;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryBlock;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import static com.lauriewired.util.ParseUtils.*;
import static ghidra.program.util.GhidraProgramUtilities.getCurrentProgram;

/**
 * Handler for listing defined data in the current program.
 * 
 * Example usage: GET /data?offset=0&limit=100
 */
public final class ListDefinedData extends Handler {
	/**
	 * Constructs a new ListDefinedData handler.
	 * 
	 * @param tool The PluginTool instance to use for accessing the current program.
	 */
	public ListDefinedData(PluginTool tool) {
		super(tool, "/data");
	}

	/**
	 * Handles the HTTP request to list defined data.
	 * 
	 * @param exchange The HTTP exchange containing the request.
	 * @throws IOException If an I/O error occurs.
	 */
	@Override
	public void handle(HttpExchange exchange) throws IOException {
		Map<String, String> qparams = parseQueryParams(exchange);
		int offset = parseIntOrDefault(qparams.get("offset"), 0);
		int limit = parseIntOrDefault(qparams.get("limit"), 100);
		sendResponse(exchange, listDefinedData(offset, limit));
	}

	/**
	 * Lists defined data in the current program, paginated by offset and limit.
	 * 
	 * @param offset The starting index for pagination.
	 * @param limit  The maximum number of items to return.
	 * @return A string representation of the defined data, formatted for display.
	 */
	private String listDefinedData(int offset, int limit) {
		Program program = getCurrentProgram(tool);
		if (program == null)
			return "No program loaded";

		List<String> lines = new ArrayList<>();
		for (MemoryBlock block : program.getMemory().getBlocks()) {
			DataIterator it = program.getListing().getDefinedData(block.getStart(), true);
			while (it.hasNext()) {
				Data data = it.next();
				if (block.contains(data.getAddress())) {
					String label = data.getLabel() != null ? data.getLabel() : "(unnamed)";
					String valRepr = data.getDefaultValueRepresentation();
					lines.add(String.format("%s: %s = %s",
							data.getAddress(),
							escapeNonAscii(label),
							escapeNonAscii(valRepr)));
				}
			}
		}
		return paginateList(lines, offset, limit);
	}
}
