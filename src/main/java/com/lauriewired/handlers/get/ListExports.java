package com.lauriewired.handlers.get;

import com.lauriewired.handlers.Handler;
import com.sun.net.httpserver.HttpExchange;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolIterator;
import ghidra.program.model.symbol.SymbolTable;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import static com.lauriewired.util.ParseUtils.*;
import static ghidra.program.util.GhidraProgramUtilities.getCurrentProgram;

/**
 * Handler for listing all exports in the current program.
 * Exports are symbols that are external entry points, typically functions.
 * 
 * Example usage:
 * GET /exports?offset=0&limit=100
 */
public final class ListExports extends Handler {
	/**
	 * Constructor for ListExports handler.
	 * 
	 * @param tool the PluginTool instance to interact with Ghidra
	 */
	public ListExports(PluginTool tool) {
		super(tool, "/exports");
	}

	/**
	 * Handles the HTTP request to list exports.
	 * 
	 * @param exchange the HttpExchange instance containing the request
	 * @throws IOException if an I/O error occurs
	 */
	@Override
	public void handle(HttpExchange exchange) throws IOException {
		Map<String, String> qparams = parseQueryParams(exchange);
		int offset = parseIntOrDefault(qparams.get("offset"), 0);
		int limit = parseIntOrDefault(qparams.get("limit"), 100);
		sendResponse(exchange, listExports(offset, limit));
	}

	/**
	 * Lists all exports in the current program, paginated by offset and limit.
	 * 
	 * @param offset the starting index for pagination
	 * @param limit  the maximum number of exports to return
	 * @return a string representation of the exports, formatted for pagination
	 */
	private String listExports(int offset, int limit) {
		Program program = getCurrentProgram(tool);
		if (program == null)
			return "No program loaded";

		SymbolTable table = program.getSymbolTable();
		SymbolIterator it = table.getAllSymbols(true);

		List<String> lines = new ArrayList<>();
		while (it.hasNext()) {
			Symbol s = it.next();
			// On older Ghidra, "export" is recognized via isExternalEntryPoint()
			if (s.isExternalEntryPoint()) {
				lines.add(s.getName() + " -> " + s.getAddress());
			}
		}
		return paginateList(lines, offset, limit);
	}
}
