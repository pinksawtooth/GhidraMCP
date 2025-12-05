package com.lauriewired.handlers.search;

import com.lauriewired.handlers.Handler;
import com.sun.net.httpserver.HttpExchange;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.Memory;
import ghidra.util.task.TaskMonitorAdapter;

import java.io.IOException;
import java.util.*;

import static com.lauriewired.util.ParseUtils.*;
import static ghidra.program.util.GhidraProgramUtilities.getCurrentProgram;

/**
 * Handler for searching for byte sequences in the current program's memory.
 * Expects a hex string of bytes to search for, with optional pagination
 * parameters.
 */
public final class SearchBytes extends Handler {
	/**
	 * Constructor for the SearchBytes handler.
	 * 
	 * @param tool The PluginTool instance to use.
	 */
	public SearchBytes(PluginTool tool) {
		super(tool, "/search_bytes");
	}

	/**
	 * Parses the query parameters from the HTTP request.
	 * 
	 * @param exchange The HttpExchange containing the request.
	 * @return A map of query parameters.
	 */
	@Override
	public void handle(HttpExchange exchange) throws IOException {
		Map<String, String> qparams = parseQueryParams(exchange);
		String bytesHex = qparams.get("bytes");
		int offset = parseIntOrDefault(qparams.get("offset"), 0);
		int limit = parseIntOrDefault(qparams.get("limit"), 100);
		sendResponse(exchange, searchBytes(bytesHex, offset, limit));
	}

	/**
	 * Searches for the specified byte sequence in the current program's memory.
	 * 
	 * @param bytesHex The hex string of bytes to search for.
	 * @param offset   The starting index for pagination.
	 * @param limit    The maximum number of results to return.
	 * @return A string containing the search results, formatted for pagination.
	 */
	private String searchBytes(String bytesHex, int offset, int limit) {
		Program program = getCurrentProgram(tool);
		if (program == null)
			return "No program loaded";
		if (bytesHex == null || bytesHex.isEmpty())
			return "Byte sequence required";

		byte[] needle;
		try {
			needle = decodeHex(bytesHex);
		} catch (IllegalArgumentException e) {
			return "Invalid hex string: " + bytesHex;
		}

		Memory mem = program.getMemory();
		List<String> hits = new ArrayList<>();

		Address cur = mem.getMinAddress();
		while (cur != null && hits.size() < offset + limit) {
			Address found = mem.findBytes(cur, needle, null, true, TaskMonitorAdapter.DUMMY_MONITOR);
			if (found == null)
				break;
			hits.add(found.toString());

			cur = found.add(1);
		}

		return paginateList(hits, offset, limit);
	}
}