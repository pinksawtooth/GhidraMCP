package com.lauriewired.handlers.get;

import com.lauriewired.handlers.Handler;
import com.sun.net.httpserver.HttpExchange;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.data.DataType;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.DataIterator;
import ghidra.program.model.listing.Program;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import static com.lauriewired.util.ParseUtils.*;
import static ghidra.program.util.GhidraProgramUtilities.getCurrentProgram;

/**
 * Handler to list all defined strings in the current program
 * Supports pagination and filtering by string content
 */
public final class ListDefinedStrings extends Handler {
	/**
	 * Constructor for ListDefinedStrings handler
	 * 
	 * @param tool the PluginTool instance to use for accessing the current program
	 */
	public ListDefinedStrings(PluginTool tool) {
		super(tool, "/strings");
	}

	/**
	 * Handle HTTP GET requests to list defined strings
	 * 
	 * @param exchange the HTTP exchange containing the request
	 * @throws Exception if an error occurs while processing the request
	 */
	@Override
	public void handle(HttpExchange exchange) throws Exception {
		Map<String, String> qparams = parseQueryParams(exchange);
		int offset = parseIntOrDefault(qparams.get("offset"), 0);
		int limit = parseIntOrDefault(qparams.get("limit"), 100);
		String filter = qparams.get("filter");
		sendResponse(exchange, listDefinedStrings(offset, limit, filter));
	}

	/**
	 * List all defined strings in the program with their addresses
	 * 
	 * @param offset the starting index for pagination
	 * @param limit  the maximum number of results to return
	 * @param filter optional filter to apply to string values
	 * @return a formatted string containing the list of defined strings
	 */
	private String listDefinedStrings(int offset, int limit, String filter) {
		Program program = getCurrentProgram(tool);
		if (program == null)
			return "No program loaded";

		List<String> lines = new ArrayList<>();
		DataIterator dataIt = program.getListing().getDefinedData(true);

		while (dataIt.hasNext()) {
			Data data = dataIt.next();

			if (data != null && isStringData(data)) {
				String value = data.getValue() != null ? data.getValue().toString() : "";

				if (filter == null || value.toLowerCase().contains(filter.toLowerCase())) {
					String escapedValue = escapeString(value);
					lines.add(String.format("%s: \"%s\"", data.getAddress(), escapedValue));
				}
			}
		}

		return paginateList(lines, offset, limit);
	}

	/**
	 * Check if the given data is a string type
	 * 
	 * @param data the Data object to check
	 * @return true if the data is a string type, false otherwise
	 */
	private boolean isStringData(Data data) {
		if (data == null)
			return false;

		DataType dt = data.getDataType();
		String typeName = dt.getName().toLowerCase();
		return typeName.contains("string") || typeName.contains("char") || typeName.equals("unicode");
	}
}
