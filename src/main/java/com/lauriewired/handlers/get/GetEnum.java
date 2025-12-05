package com.lauriewired.handlers.get;

import com.lauriewired.handlers.Handler;
import com.sun.net.httpserver.HttpExchange;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeManager;
import ghidra.program.model.data.Enum;
import ghidra.program.model.listing.Program;

import com.google.gson.Gson;

import java.io.IOException;
import java.util.*;

import static com.lauriewired.util.ParseUtils.*;
import ghidra.program.model.data.CategoryPath;
import static ghidra.program.util.GhidraProgramUtilities.getCurrentProgram;

/**
 * Handler for retrieving details of an enum by its name and category.
 * Expects query parameters: name (required), category (optional).
 */
public final class GetEnum extends Handler {
	/**
	 * Constructor for the GetEnum handler.
	 *
	 * @param tool the PluginTool instance to use for accessing the current program.
	 */
	public GetEnum(PluginTool tool) {
		super(tool, "/get_enum");
	}

	/**
	 * Handles the HTTP request to retrieve enum details.
	 *
	 * @param exchange the HttpExchange object containing the request and response.
	 * @throws IOException if an I/O error occurs during handling.
	 */
	@Override
	public void handle(HttpExchange exchange) throws IOException {
		Map<String, String> qparams = parseQueryParams(exchange);
		String enumName = qparams.get("name");
		String category = qparams.get("category");
		if (enumName == null) {
			sendResponse(exchange, "name is required");
			return;
		}
		sendResponse(exchange, getEnum(enumName, category));
	}

	/**
	 * Retrieves the enum details as a JSON string.
	 *
	 * @param enumName the name of the enum to retrieve.
	 * @param category   the category path where the enum is located
	 *                   (optional).
	 * @return a JSON representation of the enum or an error message if not
	 *         found.
	 */
	private String getEnum(String enumName, String category) {
		Program program = getCurrentProgram(tool);
		if (program == null)
			return "No program loaded";

		DataTypeManager dtm = program.getDataTypeManager();
		CategoryPath path = new CategoryPath(category == null ? "/" : category);
		DataType dt = dtm.getDataType(path, enumName);

		if (dt == null || !(dt instanceof Enum)) {
			return "Error: Enum " + enumName + " not found in category " + path;
		}

		Enum enumDt = (Enum) dt;

		Map<String, Object> enumRepr = new HashMap<>();
		enumRepr.put("name", enumDt.getName());
		enumRepr.put("category", enumDt.getCategoryPath().getPath());
		enumRepr.put("size", enumDt.getLength());
		enumRepr.put("count", enumDt.getCount());
		enumRepr.put("isSigned", enumDt.isSigned());
		enumRepr.put("description", enumDt.getDescription());

		List<Map<String, Object>> valuesList = new ArrayList<>();
		String[] names = enumDt.getNames();
		long[] values = enumDt.getValues();
		
		// Create a map for quick lookup of values by name
		Map<String, Long> nameToValue = new HashMap<>();
		for (int i = 0; i < names.length; i++) {
			nameToValue.put(names[i], values[i]);
		}

		// Build the values list
		for (String name : names) {
			Long value = nameToValue.get(name);
			if (value != null) {
				Map<String, Object> valueMap = new HashMap<>();
				valueMap.put("name", name);
				valueMap.put("value", value);
				String comment = enumDt.getComment(name);
				valueMap.put("comment", comment != null ? comment : "");
				valuesList.add(valueMap);
			}
		}
		enumRepr.put("values", valuesList);

		Gson gson = new Gson();
		return gson.toJson(enumRepr);
	}
}