package com.lauriewired.handlers.get;

import com.lauriewired.handlers.Handler;
import com.sun.net.httpserver.HttpExchange;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.RefType;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceManager;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import static com.lauriewired.util.ParseUtils.*;
import static ghidra.program.util.GhidraProgramUtilities.getCurrentProgram;

/** Handler for getting cross-references from a specific address */
public final class GetXrefsFrom extends Handler {
	/**
	 * Constructor for the GetXrefsFrom handler.
	 * 
	 * @param tool The PluginTool instance to use for accessing the current program.
	 */
	public GetXrefsFrom(PluginTool tool) {
		super(tool, "/xrefs_from");
	}

	/**
	 * Handles the HTTP request to get cross-references from a specific address.
	 * 
	 * @param exchange The HttpExchange object containing the request and response.
	 * @throws Exception If an error occurs while processing the request.
	 */
	@Override
	public void handle(HttpExchange exchange) throws Exception {
		Map<String, String> qparams = parseQueryParams(exchange);
		String address = qparams.get("address");
		int offset = parseIntOrDefault(qparams.get("offset"), 0);
		int limit = parseIntOrDefault(qparams.get("limit"), 100);
		sendResponse(exchange, getXrefsFrom(address, offset, limit));
	}

	/**
	 * Get references from a specific address in the current program.
	 * 
	 * @param addressStr The address to get references from.
	 * @param offset     The offset for pagination.
	 * @param limit      The maximum number of references to return.
	 * @return A string containing the references or an error message.
	 */
	private String getXrefsFrom(String addressStr, int offset, int limit) {
		Program program = getCurrentProgram(tool);
		if (program == null)
			return "No program loaded";
		if (addressStr == null || addressStr.isEmpty())
			return "Address is required";

		try {
			Address addr = program.getAddressFactory().getAddress(addressStr);
			ReferenceManager refManager = program.getReferenceManager();

			Reference[] references = refManager.getReferencesFrom(addr);

			List<String> refs = new ArrayList<>();
			for (Reference ref : references) {
				Address toAddr = ref.getToAddress();
				RefType refType = ref.getReferenceType();

				String targetInfo = "";
				Function toFunc = program.getFunctionManager().getFunctionAt(toAddr);
				if (toFunc != null) {
					targetInfo = " to function " + toFunc.getName();
				} else {
					Data data = program.getListing().getDataAt(toAddr);
					if (data != null) {
						targetInfo = " to data " + (data.getLabel() != null ? data.getLabel() : data.getPathName());
					}
				}

				refs.add(String.format("To %s%s [%s]", toAddr, targetInfo, refType.getName()));
			}

			return paginateList(refs, offset, limit);
		} catch (Exception e) {
			return "Error getting references from address: " + e.getMessage();
		}
	}
}
