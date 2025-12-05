package com.lauriewired.handlers.act;

import com.lauriewired.handlers.Handler;
import com.sun.net.httpserver.HttpExchange;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.data.DataTypeConflictHandler;
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
import static com.lauriewired.util.EnumUtils.EnumValue;
import ghidra.program.model.data.CategoryPath;
import static ghidra.program.util.GhidraProgramUtilities.getCurrentProgram;

/**
 * Handler for creating a new enum in Ghidra.
 * Expects parameters: name, category (optional), size (optional), values (optional JSON array).
 * Values should be in the format: [{"name": "VALUE1", "value": 0, "comment": "First value"}, ...]
 */
public final class CreateEnum extends Handler {
	/**
	 * Constructs a new CreateEnum handler.
	 *
	 * @param tool The PluginTool instance to interact with Ghidra.
	 */
	public CreateEnum(PluginTool tool) {
		super(tool, "/create_enum");
	}

	/**
	 * Handles the HTTP request to create a new enum.
	 * Parses parameters from the POST request and creates the enum in Ghidra.
	 *
	 * @param exchange The HTTP exchange containing the request and response.
	 * @throws IOException If an I/O error occurs during handling.
	 */
	public void handle(HttpExchange exchange) throws IOException {
		Map<String, String> params = parsePostParams(exchange);
		String name = params.get("name");
		String category = params.get("category");
		long size = parseIntOrDefault(params.get("size"), 4); // Default to 4 bytes (int size)
		String valuesJson = params.get("values"); // Optional

		if (name == null || name.isEmpty()) {
			sendResponse(exchange, "Enum name is required");
			return;
		}
		sendResponse(exchange, createEnum(name, category, (int) size, valuesJson));
	}

	/**
	 * Creates a new enum in Ghidra with the specified parameters.
	 * This method runs on the Swing thread to ensure thread safety when interacting with Ghidra's data types.
	 *
	 * @param name        The name of the enum to create.
	 * @param category    The category path where the enum will be created (optional).
	 * @param size        The size of the enum in bytes (optional, defaults to 4).
	 * @param valuesJson  JSON array of enum values (optional).
	 * @return A message indicating success or failure of the operation.
	 */
	private String createEnum(String name, String category, int size, String valuesJson) {
		Program program = getCurrentProgram(tool);
		if (program == null)
			return "No program loaded";

		final AtomicReference<String> result = new AtomicReference<>();
		try {
			SwingUtilities.invokeAndWait(() -> {
				int txId = program.startTransaction("Create Enum");
				boolean success = false;
				try {
					DataTypeManager dtm = program.getDataTypeManager();
					CategoryPath path = new CategoryPath(category == null ? "/" : category);

					if (dtm.getDataType(path, name) != null) {
						result.set("Error: Enum " + name + " already exists in category " + path);
						return;
					}
					
					// Create the enum with specified size
					EnumDataType newEnum = new EnumDataType(path, name, size, dtm);

					StringBuilder responseBuilder = new StringBuilder(
							"Enum " + name + " created successfully in category " + path + " with size " + size + " bytes");

					if (valuesJson != null && !valuesJson.isEmpty()) {
						Gson gson = new Gson();
						EnumValue[] values = gson.fromJson(valuesJson, EnumValue[].class);

						int valuesAdded = 0;
						for (EnumValue enumValue : values) {
							if (enumValue.name == null || enumValue.name.isEmpty()) {
								responseBuilder.append("\nError: Enum value name cannot be empty. Skipping value.");
								continue;
							}

							// Add the enum value with or without comment
							if (enumValue.comment != null && !enumValue.comment.isEmpty()) {
								newEnum.add(enumValue.name, (long) enumValue.value, enumValue.comment);
							} else {
								newEnum.add(enumValue.name, (long) enumValue.value);
							}
							valuesAdded++;
						}
						responseBuilder.append("\nAdded ").append(valuesAdded).append(" values.");
					}
					
					dtm.addDataType(newEnum, DataTypeConflictHandler.DEFAULT_HANDLER);
					result.set(responseBuilder.toString());
					success = true;
				} catch (Exception e) {
					result.set("Error: Failed to create enum: " + e.getMessage());
				} finally {
					program.endTransaction(txId, success);
				}
			});
		} catch (InterruptedException | InvocationTargetException e) {
			return "Error: Failed to execute create enum on Swing thread: " + e.getMessage();
		}
		return result.get();
	}
}