package com.lauriewired.handlers.get;

import com.lauriewired.handlers.Handler;
import com.sun.net.httpserver.HttpExchange;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeComponent;
import ghidra.program.model.data.DataTypeManager;
import ghidra.program.model.data.Structure;
import ghidra.program.model.listing.Program;

import com.google.gson.Gson;

import java.io.IOException;
import java.util.*;

import static com.lauriewired.util.ParseUtils.*;
import ghidra.program.model.data.CategoryPath;
import static ghidra.program.util.GhidraProgramUtilities.getCurrentProgram;

/**
 * Handler for retrieving details of a structure by its name and category.
 * Expects query parameters: name (required), category (optional).
 */
public final class GetStruct extends Handler {
	/**
	 * Constructor for the GetStruct handler.
	 *
	 * @param tool the PluginTool instance to use for accessing the current program.
	 */
	public GetStruct(PluginTool tool) {
		super(tool, "/get_struct");
	}

	/**
	 * Handles the HTTP request to retrieve structure details.
	 *
	 * @param exchange the HttpExchange object containing the request and response.
	 * @throws IOException if an I/O error occurs during handling.
	 */
	@Override
	public void handle(HttpExchange exchange) throws IOException {
		Map<String, String> qparams = parseQueryParams(exchange);
		String structName = qparams.get("name");
		String category = qparams.get("category");
		if (structName == null) {
			sendResponse(exchange, "name is required");
			return;
		}
		sendResponse(exchange, getStruct(structName, category));
	}

	/**
	 * Retrieves the structure details as a JSON string.
	 *
	 * @param structName the name of the structure to retrieve.
	 * @param category   the category path where the structure is located
	 *                   (optional).
	 * @return a JSON representation of the structure or an error message if not
	 *         found.
	 */
	private String getStruct(String structName, String category) {
		Program program = getCurrentProgram(tool);
		if (program == null)
			return "No program loaded";

		DataTypeManager dtm = program.getDataTypeManager();
		CategoryPath path = new CategoryPath(category == null ? "/" : category);
		DataType dt = dtm.getDataType(path, structName);

		if (dt == null || !(dt instanceof Structure)) {
			return "Error: Struct " + structName + " not found in category " + path;
		}

		Structure struct = (Structure) dt;

		Map<String, Object> structRepr = new HashMap<>();
		structRepr.put("name", struct.getName());
		structRepr.put("category", struct.getCategoryPath().getPath());
		structRepr.put("size", struct.getLength());
		structRepr.put("isNotYetDefined", struct.isNotYetDefined());

		List<Map<String, Object>> membersList = new ArrayList<>();
		for (DataTypeComponent component : struct.getDefinedComponents()) {
			Map<String, Object> memberMap = new HashMap<>();
			memberMap.put("name", component.getFieldName());
			memberMap.put("type", component.getDataType().getName());
			memberMap.put("offset", component.getOffset());
			memberMap.put("size", component.getLength());
			memberMap.put("comment", component.getComment());
			membersList.add(memberMap);
		}
		structRepr.put("members", membersList);

		Gson gson = new Gson();
		return gson.toJson(structRepr);
	}
}
