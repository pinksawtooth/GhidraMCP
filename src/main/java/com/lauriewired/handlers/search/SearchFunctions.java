package com.lauriewired.handlers.search;

import com.lauriewired.handlers.Handler;
import com.sun.net.httpserver.HttpExchange;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Map;

import static com.lauriewired.util.ParseUtils.*;
import static ghidra.program.util.GhidraProgramUtilities.getCurrentProgram;

/**
 * Handler for searching functions by name in the current program.
 * Expects query parameters: query (search term), offset, limit.
 */
public final class SearchFunctions extends Handler {
	/**
	 * Constructor for SearchFunctions handler.
	 *
	 * @param tool the PluginTool instance to use for accessing the current program.
	 */
	public SearchFunctions(PluginTool tool) {
		super(tool, "/searchFunctions");
	}

	/**
	 * Handles HTTP GET requests to search for functions by name.
	 * Expects query parameters:
	 * - query: the search term (required)
	 * - offset: pagination offset (default 0)
	 * - limit: maximum number of results to return (default 100)
	 *
	 * @param exchange the HttpExchange object containing the request and response.
	 * @throws IOException if an I/O error occurs.
	 */
	@Override
	public void handle(HttpExchange exchange) throws IOException {
		Map<String, String> qparams = parseQueryParams(exchange);
		String searchTerm = qparams.get("query");
		int offset = parseIntOrDefault(qparams.get("offset"), 0);
		int limit = parseIntOrDefault(qparams.get("limit"), 100);
		sendResponse(exchange, searchFunctionsByName(searchTerm, offset, limit));
	}

	/**
	 * Searches for functions in the current program by name.
	 * Returns a paginated list of matching functions.
	 *
	 * @param searchTerm the term to search for in function names.
	 * @param offset     the pagination offset.
	 * @param limit      the maximum number of results to return.
	 * @return a string containing the results or an error message.
	 */
	private String searchFunctionsByName(String searchTerm, int offset, int limit) {
		Program program = getCurrentProgram(tool);
		if (program == null)
			return "No program loaded";
		if (searchTerm == null || searchTerm.isEmpty())
			return "Search term is required";

		List<String> matches = new ArrayList<>();
		for (Function func : program.getFunctionManager().getFunctions(true)) {
			String name = func.getName();
			// simple substring match
			if (name.toLowerCase().contains(searchTerm.toLowerCase())) {
				matches.add(String.format("%s @ %s", name, func.getEntryPoint()));
			}
		}

		Collections.sort(matches);

		if (matches.isEmpty()) {
			return "No functions matching '" + searchTerm + "'";
		}
		return paginateList(matches, offset, limit);
	}
}
