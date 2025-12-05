package com.lauriewired.handlers.get;

import com.lauriewired.handlers.Handler;
import com.sun.net.httpserver.HttpExchange;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.address.GlobalNamespace;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.Namespace;
import ghidra.program.model.symbol.Symbol;

import java.io.IOException;
import java.util.*;

import static com.lauriewired.util.ParseUtils.*;
import static ghidra.program.util.GhidraProgramUtilities.getCurrentProgram;

/**
 * Handler for listing namespaces in the current program.
 * 
 * Example usage:
 * GET /namespaces?offset=0&limit=100
 */
public final class ListNamespaces extends Handler {
	/**
	 * Constructor for the ListNamespaces handler.
	 *
	 * @param tool the PluginTool instance
	 */
	public ListNamespaces(PluginTool tool) {
		super(tool, "/namespaces");
	}

	/**
	 * Handles the HTTP request to list namespaces.
	 *
	 * @param exchange the HttpExchange instance containing the request
	 * @throws IOException if an I/O error occurs
	 */
	@Override
	public void handle(HttpExchange exchange) throws IOException {
		Map<String, String> qparams = parseQueryParams(exchange);
		int offset = parseIntOrDefault(qparams.get("offset"), 0);
		int limit = parseIntOrDefault(qparams.get("limit"), 100);
		sendResponse(exchange, listNamespaces(offset, limit));
	}

	/**
	 * Lists namespaces in the current program, paginated by offset and limit.
	 *
	 * @param offset the starting index for pagination
	 * @param limit  the maximum number of namespaces to return
	 * @return a string representation of the paginated list of namespaces
	 */
	private String listNamespaces(int offset, int limit) {
		Program program = getCurrentProgram(tool);
		if (program == null)
			return "No program loaded";

		Set<String> namespaces = new HashSet<>();
		for (Symbol symbol : program.getSymbolTable().getAllSymbols(true)) {
			Namespace ns = symbol.getParentNamespace();
			if (ns != null && !(ns instanceof GlobalNamespace)) {
				namespaces.add(ns.getName());
			}
		}
		List<String> sorted = new ArrayList<>(namespaces);
		Collections.sort(sorted);
		return paginateList(sorted, offset, limit);
	}
}
