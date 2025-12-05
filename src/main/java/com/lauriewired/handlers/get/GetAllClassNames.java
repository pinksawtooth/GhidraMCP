package com.lauriewired.handlers.get;

import com.lauriewired.handlers.Handler;
import com.sun.net.httpserver.HttpExchange;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.Namespace;
import ghidra.program.model.symbol.Symbol;

import java.io.IOException;
import java.util.*;

import static com.lauriewired.util.ParseUtils.*;
import static ghidra.program.util.GhidraProgramUtilities.getCurrentProgram;

/**
 * Handler to get all class names in the current program.
 * Supports pagination via 'offset' and 'limit' query parameters.
 */
public final class GetAllClassNames extends Handler {
	/**
	 * Constructor for the GetAllClassNames handler.
	 *
	 * @param tool The PluginTool instance to use for accessing the current program.
	 */
	public GetAllClassNames(PluginTool tool) {
		super(tool, "/classes");
	}

	/**
	 * Parses the query parameters from the HTTP request and returns a response
	 * containing
	 * all class names in the current program, with optional pagination.
	 *
	 * @param exchange The HttpExchange object representing the HTTP request.
	 * @throws IOException If an I/O error occurs while handling the request.
	 */
	@Override
	public void handle(HttpExchange exchange) throws IOException {
		Map<String, String> qparams = parseQueryParams(exchange);
		int offset = parseIntOrDefault(qparams.get("offset"), 0);
		int limit = parseIntOrDefault(qparams.get("limit"), 100);
		sendResponse(exchange, generateResponse(offset, limit));
	}

	/**
	 * Generates a response containing all class names in the current program,
	 * with optional pagination.
	 *
	 * @param offset The starting index for pagination.
	 * @param limit  The maximum number of class names to return.
	 * @return A string containing the paginated list of class names.
	 */
	private String generateResponse(int offset, int limit) {
		Program program = getCurrentProgram(tool);
		if (program == null)
			return "No program loaded";

		Set<String> classNames = new HashSet<>();
		for (Symbol symbol : program.getSymbolTable().getAllSymbols(true)) {
			Namespace ns = symbol.getParentNamespace();
			if (ns != null && !ns.isGlobal()) {
				classNames.add(ns.getName());
			}
		}
		// Convert set to list for pagination
		List<String> sorted = new ArrayList<>(classNames);
		Collections.sort(sorted);
		return paginateList(sorted, offset, limit);
	}
}
