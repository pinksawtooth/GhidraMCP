package com.lauriewired.handlers.get;

import com.lauriewired.handlers.Handler;
import com.sun.net.httpserver.HttpExchange;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.*;

import java.io.IOException;
import java.util.*;

import static com.lauriewired.util.ParseUtils.*;
import static ghidra.program.util.GhidraProgramUtilities.getCurrentProgram;

/**
 * Handler to retrieve data associated with a specific label in the current
 * program.
 * It responds with the address and value of the data defined at that label.
 */
public final class GetDataByLabel extends Handler {
	/**
	 * Constructor for the GetDataByLabel handler.
	 * 
	 * @param tool The PluginTool instance to use for accessing the current program.
	 */
	public GetDataByLabel(PluginTool tool) {
		super(tool, "/get_data_by_label");
	}

	/**
	 * Handles the HTTP request to retrieve data by label.
	 * 
	 * @param exchange The HttpExchange object containing the request and response.
	 * @throws IOException If an I/O error occurs during handling.
	 */
	@Override
	public void handle(HttpExchange exchange) throws IOException {
		Map<String, String> qparams = parseQueryParams(exchange);
		String label = qparams.get("label");
		sendResponse(exchange, getDataByLabel(label));
	}

	/**
	 * Retrieves data associated with the specified label in the current program.
	 * 
	 * @param label The label to search for in the current program.
	 * @return A string containing the address and value of the data defined at that
	 *         label,
	 *         or an error message if the label is not found or no program is
	 *         loaded.
	 */
	private String getDataByLabel(String label) {
		Program program = getCurrentProgram(tool);
		if (program == null)
			return "No program loaded";
		if (label == null || label.isEmpty())
			return "Label is required";

		SymbolTable st = program.getSymbolTable();
		SymbolIterator it = st.getSymbols(label);
		if (!it.hasNext())
			return "Label not found: " + label;

		StringBuilder sb = new StringBuilder();
		while (it.hasNext()) {
			Symbol s = it.next();
			Address a = s.getAddress();
			Data d = program.getListing().getDefinedDataAt(a);
			String v = (d != null) ? escapeString(String.valueOf(d.getDefaultValueRepresentation()))
					: "(no defined data)";
			sb.append(String.format("%s -> %s : %s%n", label, a, v));
		}
		return sb.toString();
	}
}