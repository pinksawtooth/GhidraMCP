package com.lauriewired.handlers.get;

import com.lauriewired.handlers.Handler;
import com.sun.net.httpserver.HttpExchange;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.Symbol;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import static com.lauriewired.util.ParseUtils.*;
import static ghidra.program.util.GhidraProgramUtilities.getCurrentProgram;

/**
 * Handler for listing all external symbols (imports) in the current program.
 * Responds with a paginated list of imports in the format:
 * "symbolName -> symbolAddress".
 */
public final class ListImports extends Handler {
	/**
	 * Constructor for ListImports handler.
	 *
	 * @param tool the PluginTool instance to use for accessing the current program.
	 */
	public ListImports(PluginTool tool) {
		super(tool, "/imports");
	}

	/**
	 * Handles the HTTP request to list imports.
	 * Expects query parameters 'offset' and 'limit' for pagination.
	 *
	 * @param exchange the HttpExchange instance containing the request and
	 *                 response.
	 * @throws IOException if an I/O error occurs during handling.
	 */
	@Override
	public void handle(HttpExchange exchange) throws IOException {
		Map<String, String> qparams = parseQueryParams(exchange);
		int offset = parseIntOrDefault(qparams.get("offset"), 0);
		int limit = parseIntOrDefault(qparams.get("limit"), 100);
		sendResponse(exchange, listImports(offset, limit));
	}

	/**
	 * Lists all external symbols (imports) in the current program, paginated.
	 *
	 * @param offset the starting index for pagination.
	 * @param limit  the maximum number of results to return.
	 * @return a string containing the paginated list of imports.
	 */
	private String listImports(int offset, int limit) {
		Program program = getCurrentProgram(tool);
		if (program == null)
			return "No program loaded";

		List<String> lines = new ArrayList<>();
		for (Symbol symbol : program.getSymbolTable().getExternalSymbols()) {
			lines.add(symbol.getName() + " -> " + symbol.getAddress());
		}
		return paginateList(lines, offset, limit);
	}
}
