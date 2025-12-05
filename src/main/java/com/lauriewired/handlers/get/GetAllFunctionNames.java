package com.lauriewired.handlers.get;

import com.lauriewired.handlers.Handler;
import com.sun.net.httpserver.HttpExchange;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import static com.lauriewired.util.ParseUtils.*;
import static com.lauriewired.util.ParseUtils.parseIntOrDefault;
import static ghidra.program.util.GhidraProgramUtilities.getCurrentProgram;

/**
 * Handler to get all function names in the current program.
 * 
 * Example usage: GET /methods?offset=0&limit=100
 */
public final class GetAllFunctionNames extends Handler {
	/**
	 * Constructor for the GetAllFunctionNames handler.
	 *
	 * @param tool the PluginTool instance
	 */
	public GetAllFunctionNames(PluginTool tool) {
		super(tool, "/methods");
	}

	/**
	 * Handles the HTTP request to get all function names.
	 *
	 * @param exchange the HttpExchange instance containing the request
	 * @throws IOException if an I/O error occurs
	 */
	@Override
	public void handle(HttpExchange exchange) throws IOException {
		Map<String, String> qparams = parseQueryParams(exchange);
		int offset = parseIntOrDefault(qparams.get("offset"), 0);
		int limit = parseIntOrDefault(qparams.get("limit"), 100);
		sendResponse(exchange, generateResponse(offset, limit));
	}

	/**
	 * Generates a paginated response containing all function names in the current
	 * program.
	 *
	 * @param offset the starting index for pagination
	 * @param limit  the maximum number of function names to return
	 * @return a string containing the paginated list of function names
	 */
	private String generateResponse(int offset, int limit) {
		Program program = getCurrentProgram(tool);
		if (program == null)
			return "No program loaded";

		List<String> names = new ArrayList<>();
		for (Function f : program.getFunctionManager().getFunctions(true)) {
			names.add(f.getName());
		}
		return paginateList(names, offset, limit);
	}
}
