package com.lauriewired.handlers.act;

import com.lauriewired.handlers.Handler;
import com.sun.net.httpserver.HttpExchange;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeManager;
import ghidra.program.model.data.Enum;
import ghidra.program.model.listing.Program;

import com.google.gson.Gson;

import javax.swing.SwingUtilities;
import java.io.IOException;
import java.lang.reflect.InvocationTargetException;
import java.util.*;
import java.util.concurrent.atomic.AtomicReference;

import static com.lauriewired.util.ParseUtils.*;
import static com.lauriewired.util.EnumUtils.EnumValue;
import ghidra.program.model.data.CategoryPath;
import static ghidra.program.util.GhidraProgramUtilities.getCurrentProgram;

/**
 * Handler for adding values to an enum in Ghidra.
 * Expects a POST request with parameters:
 * - enum_name: Name of the enum to modify
 * - category: Category path where the enum is located (optional)
 * - values: JSON array of values to add, each with fields:
 *   - name: Name of the enum value
 *   - value: Numeric value of the enum entry
 *   - comment: Comment for the enum value (optional)
 */
public final class AddEnumValues extends Handler {
	/**
	 * Constructor for the AddEnumValues handler.
	 *
	 * @param tool The Ghidra plugin tool instance.
	 */
	public AddEnumValues(PluginTool tool) {
		super(tool, "/add_enum_values");
	}

	/**
	 * Handles the HTTP request to add values to an enum.
	 *
	 * @param exchange The HTTP exchange containing the request and response.
	 * @throws IOException If an I/O error occurs during handling.
	 */
	@Override
	public void handle(HttpExchange exchange) throws IOException {
		Map<String, String> params = parsePostParams(exchange);
		String enumName = params.get("enum_name");
		String category = params.get("category");
		String valuesJson = params.get("values");

		if (enumName == null || valuesJson == null) {
			sendResponse(exchange, "enum_name and values are required");
			return;
		}
		sendResponse(exchange, addEnumValues(enumName, category, valuesJson));
	}

	/**
	 * Adds values to an enum in the current Ghidra program.
	 *
	 * @param enumName The name of the enum to modify.
	 * @param category   The category path where the enum is located (optional).
	 * @param valuesJson JSON array of values to add.
	 * @return A message indicating success or failure.
	 */
	private String addEnumValues(String enumName, String category, String valuesJson) {
		Program program = getCurrentProgram(tool);
		if (program == null)
			return "No program loaded";

		final AtomicReference<String> result = new AtomicReference<>();
		try {
			SwingUtilities.invokeAndWait(() -> {
				int txId = program.startTransaction("Add Enum Values");
				boolean success = false;
				try {
					DataTypeManager dtm = program.getDataTypeManager();
					CategoryPath path = new CategoryPath(category == null ? "/" : category);
					DataType dt = dtm.getDataType(path, enumName);

					if (dt == null || !(dt instanceof Enum)) {
						result.set("Error: Enum " + enumName + " not found in category " + path);
						return;
					}
					Enum enumDt = (Enum) dt;

					StringBuilder responseBuilder = new StringBuilder();

					if (valuesJson != null && !valuesJson.isEmpty()) {
						Gson gson = new Gson();
						EnumValue[] values = gson.fromJson(valuesJson, EnumValue[].class);

						int valuesAdded = 0;
						for (EnumValue enumValue : values) {
							if (enumValue.name == null || enumValue.name.isEmpty()) {
								responseBuilder.append("\nError: Enum value name cannot be empty. Skipping value.");
								continue;
							}

							// Check if value name already exists
							if (enumDt.contains(enumValue.name)) {
								responseBuilder.append("\nWarning: Enum value '").append(enumValue.name)
										.append("' already exists. Skipping.");
								continue;
							}

							// Add the enum value with or without comment
							if (enumValue.comment != null && !enumValue.comment.isEmpty()) {
								enumDt.add(enumValue.name, (long) enumValue.value, enumValue.comment);
							} else {
								enumDt.add(enumValue.name, (long) enumValue.value);
							}
							valuesAdded++;
						}
						responseBuilder.append("\nAdded ").append(valuesAdded).append(" values to enum ").append(enumName).append(".");
						result.set(responseBuilder.toString());
						success = valuesAdded > 0;
					}

				} catch (Exception e) {
					result.set("Error: Failed to add values to enum: " + e.getMessage());
				} finally {
					program.endTransaction(txId, success);
				}
			});
		} catch (InterruptedException | InvocationTargetException e) {
			return "Error: Failed to execute add enum values on Swing thread: " + e.getMessage();
		}
		return result.get();
	}
}