package com.lauriewired.handlers.get;

import com.lauriewired.handlers.Handler;
import com.sun.net.httpserver.HttpExchange;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryBlock;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import static com.lauriewired.util.ParseUtils.*;
import static ghidra.program.util.GhidraProgramUtilities.getCurrentProgram;

/**
 * Handler for listing memory segments in the current program.
 * Responds with a list of memory blocks, paginated by offset and limit.
 */
public final class ListSegments extends Handler {
	/**
	 * Constructor for ListSegments handler.
	 *
	 * @param tool the PluginTool instance to use for accessing the current program.
	 */
	public ListSegments(PluginTool tool) {
		super(tool, "/segments");
	}

	/**
	 * Handles the HTTP request to list memory segments.
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
		sendResponse(exchange, listSegments(offset, limit));
	}

	/**
	 * Lists memory segments in the current program, paginated by offset and limit.
	 *
	 * @param offset the starting index for pagination.
	 * @param limit  the maximum number of segments to return.
	 * @return a string representation of the memory segments, formatted for
	 *         pagination.
	 */
	private String listSegments(int offset, int limit) {
		Program program = getCurrentProgram(tool);
		if (program == null)
			return "No program loaded";

		List<String> lines = new ArrayList<>();
		for (MemoryBlock block : program.getMemory().getBlocks()) {
			lines.add(String.format("%s: %s - %s", block.getName(), block.getStart(), block.getEnd()));
		}
		return paginateList(lines, offset, limit);
	}
}
