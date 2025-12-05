package com.lauriewired.handlers.act;

import com.lauriewired.handlers.Handler;
import com.sun.net.httpserver.HttpExchange;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeManager;
import ghidra.program.model.data.EnumDataType;
import ghidra.program.model.listing.Program;

import com.google.gson.Gson;

import javax.swing.SwingUtilities;
import java.io.IOException;
import java.lang.reflect.InvocationTargetException;
import java.util.*;
import java.util.concurrent.atomic.AtomicReference;

import static com.lauriewired.util.ParseUtils.*;
import ghidra.program.model.data.CategoryPath;
import static ghidra.program.util.GhidraProgramUtilities.getCurrentProgram;

/**
 * Handler for removing values from an enum in Ghidra.
 * Expects a POST request with parameters:
 * - enum_name: Name of the enum to modify
 * - category: Category path where the enum is located (optional)
 * - values: JSON array of value names to remove, or single value name as string
 */
public final class RemoveEnumValues extends Handler {
	/**
	 * Constructor for the RemoveEnumValues handler.
	 *
	 * @param tool The Ghidra plugin tool instance.
	 */
	public RemoveEnumValues(PluginTool tool) {
		super(tool, "/remove_enum_values");
	}

	/**
	 * Handles the HTTP request to remove values from an enum.
	 *
	 * @param exchange The HTTP exchange containing the request and response.
	 * @throws IOException If an I/O error occurs during handling.
	 */
	@Override
	public void handle(HttpExchange exchange) throws IOException {
		Map<String, String> params = parsePostParams(exchange);
		String enumName = params.get("enum_name");
		String category = params.get("category");
		String valuesParam = params.get("values");

		if (enumName == null || valuesParam == null) {
			sendResponse(exchange, "enum_name and values are required");
			return;
		}
		sendResponse(exchange, removeEnumValues(enumName, category, valuesParam));
	}

	/**
	 * Removes values from an enum in the current Ghidra program.
	 *
	 * @param enumName The name of the enum to modify.
	 * @param category The category path where the enum is located (optional).
	 * @param valuesParam JSON array of value names to remove, or single value name.
	 * @return A message indicating success or failure.
	 */
	private String removeEnumValues(String enumName, String category, String valuesParam) {
		Program program = getCurrentProgram(tool);
		if (program == null)
			return "No program loaded";

		final AtomicReference<String> result = new AtomicReference<>();
		try {
			SwingUtilities.invokeAndWait(() -> {
				int txId = program.startTransaction("Remove Enum Values");
				boolean success = false;
				try {
					DataTypeManager dtm = program.getDataTypeManager();
					CategoryPath path = new CategoryPath(category == null ? "/" : category);
					DataType dt = dtm.getDataType(path, enumName);

					if (dt == null || !(dt instanceof EnumDataType)) {
						result.set("Error: Enum " + enumName + " not found in category " + path);
						return;
					}
					EnumDataType enumDt = (EnumDataType) dt;

					StringBuilder responseBuilder = new StringBuilder(
							"Removing values from enum " + enumName);

					// Parse value names to remove
					List<String> valueNames = new ArrayList<>();
					try {
						// Try to parse as JSON array first
						Gson gson = new Gson();
						String[] names = gson.fromJson(valuesParam, String[].class);
						valueNames.addAll(Arrays.asList(names));
					} catch (Exception e) {
						// If not JSON array, treat as single value name
						valueNames.add(valuesParam.trim());
					}

					int valuesRemoved = 0;
					for (String valueName : valueNames) {
						try {
							// Check if value exists
							boolean valueExists = false;
							String[] enumValueNames = enumDt.getNames();
							for (String existingName : enumValueNames) {
								if (existingName.equals(valueName)) {
									valueExists = true;
									break;
								}
							}

							if (!valueExists) {
								responseBuilder.append("\nWarning: Value '").append(valueName)
										.append("' not found in enum. Skipping.");
								continue;
							}

							// Remove the value
							enumDt.remove(valueName);
							responseBuilder.append("\nRemoved value '").append(valueName).append("'");
							valuesRemoved++;
						} catch (Exception e) {
							responseBuilder.append("\nError removing value '").append(valueName)
									.append("': ").append(e.getMessage());
						}
					}

					if (valuesRemoved > 0) {
						responseBuilder.append("\nSuccessfully removed ").append(valuesRemoved)
								.append(" values from enum ").append(enumName);
						success = true;
					} else {
						responseBuilder.append("\nNo values were removed from enum ").append(enumName);
					}

					result.set(responseBuilder.toString());

				} catch (Exception e) {
					result.set("Error: Failed to remove values from enum: " + e.getMessage());
				} finally {
					program.endTransaction(txId, success);
				}
			});
		} catch (InterruptedException | InvocationTargetException e) {
			return "Error: Failed to execute remove enum values on Swing thread: " + e.getMessage();
		}
		return result.get();
	}
}