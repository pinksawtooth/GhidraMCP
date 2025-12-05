package com.lauriewired.handlers.get;

import com.lauriewired.handlers.Handler;
import com.sun.net.httpserver.HttpExchange;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;

import java.io.IOException;

import static com.lauriewired.util.ParseUtils.sendResponse;
import static ghidra.program.util.GhidraProgramUtilities.getCurrentProgram;

/**
 * Handler to list all functions in the current program.
 * Responds with a list of function names and their entry points.
 */
public final class ListFunctions extends Handler {
	/**
	 * Constructor for ListFunctions handler.
	 *
	 * @param tool the PluginTool instance
	 */
	public ListFunctions(PluginTool tool) {
		super(tool, "/list_functions");
	}

	/**
	 * Handles the HTTP request to list functions.
	 *
	 * @param exchange the HttpExchange instance
	 * @throws IOException if an I/O error occurs
	 */
	@Override
	public void handle(HttpExchange exchange) throws IOException {
		sendResponse(exchange, listFunctions());
	}

	/**
	 * Lists all functions in the current program.
	 *
	 * @return a string containing the names and entry points of all functions
	 */
	private String listFunctions() {
		Program program = getCurrentProgram(tool);
		if (program == null)
			return "No program loaded";

		StringBuilder result = new StringBuilder();
		for (Function func : program.getFunctionManager().getFunctions(true)) {
			result.append(String.format("%s at %s\n",
					func.getName(),
					func.getEntryPoint()));
		}

		return result.toString();
	}
}
