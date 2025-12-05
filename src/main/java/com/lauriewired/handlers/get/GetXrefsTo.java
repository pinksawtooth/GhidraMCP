package com.lauriewired.handlers.get;

import com.lauriewired.handlers.Handler;
import com.sun.net.httpserver.HttpExchange;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.RefType;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceIterator;
import ghidra.program.model.symbol.ReferenceManager;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import static com.lauriewired.util.ParseUtils.*;
import static ghidra.program.util.GhidraProgramUtilities.getCurrentProgram;

/**
 * Handler to get all references to a specific address in the current program.
 * Example usage: /xrefs_to?address=0x00401000&offset=0&limit=100
 */
public final class GetXrefsTo extends Handler {
	/**
	 * Constructor for the GetXrefsTo handler.
	 *
	 * @param tool the Ghidra plugin tool
	 */
	public GetXrefsTo(PluginTool tool) {
		super(tool, "/xrefs_to");
	}

	/**
	 * Handles the HTTP request to get cross-references to a specific address.
	 *
	 * @param exchange the HTTP exchange containing the request
	 * @throws Exception if an error occurs while processing the request
	 */
	@Override
	public void handle(HttpExchange exchange) throws Exception {
		Map<String, String> qparams = parseQueryParams(exchange);
		String address = qparams.get("address");
		int offset = parseIntOrDefault(qparams.get("offset"), 0);
		int limit = parseIntOrDefault(qparams.get("limit"), 100);
		sendResponse(exchange, getXrefsTo(address, offset, limit));
	}

	/**
	 * Retrieves cross-references to a specific address in the current program.
	 *
	 * @param addressStr the address to get references to
	 * @param offset     the offset for pagination
	 * @param limit      the maximum number of results to return
	 * @return a string representation of the references found
	 */
	private String getXrefsTo(String addressStr, int offset, int limit) {
		Program program = getCurrentProgram(tool);
		if (program == null)
			return "No program loaded";
		if (addressStr == null || addressStr.isEmpty())
			return "Address is required";

		try {
			Address addr = program.getAddressFactory().getAddress(addressStr);
			ReferenceManager refManager = program.getReferenceManager();

			ReferenceIterator refIter = refManager.getReferencesTo(addr);

			List<String> refs = new ArrayList<>();
			while (refIter.hasNext()) {
				Reference ref = refIter.next();
				Address fromAddr = ref.getFromAddress();
				RefType refType = ref.getReferenceType();

				Function fromFunc = program.getFunctionManager().getFunctionContaining(fromAddr);
				String funcInfo = (fromFunc != null) ? " in " + fromFunc.getName() : "";

				refs.add(String.format("From %s%s [%s]", fromAddr, funcInfo, refType.getName()));
			}

			return paginateList(refs, offset, limit);
		} catch (Exception e) {
			return "Error getting references to address: " + e.getMessage();
		}
	}
}
