package com.lauriewired.handlers.act;

import com.lauriewired.handlers.Handler;
import com.sun.net.httpserver.HttpExchange;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeConflictHandler;
import ghidra.program.model.data.DataTypeManager;
import ghidra.program.model.data.StructureDataType;
import ghidra.program.model.listing.Program;

import com.google.gson.Gson;

import javax.swing.SwingUtilities;
import java.io.IOException;
import java.lang.reflect.InvocationTargetException;
import java.util.*;
import java.util.concurrent.atomic.AtomicReference;

import static com.lauriewired.util.GhidraUtils.*;
import static com.lauriewired.util.ParseUtils.*;
import static com.lauriewired.util.StructUtils.StructMember;
import ghidra.program.model.data.CategoryPath;
import static ghidra.program.util.GhidraProgramUtilities.getCurrentProgram;

/**
 * Handler for creating a new struct in Ghidra.
 * Expects parameters: name, category (optional), size (optional), members (optional JSON array).
 * Members should be in the format: [{"name": "member1", "type": "int", "offset": 0, "comment": "Member 1"}, ...]
 */
public final class CreateStruct extends Handler {
	/**
	 * Constructs a new CreateStruct handler.
	 *
	 * @param tool The PluginTool instance to interact with Ghidra.
	 */
	public CreateStruct(PluginTool tool) {
		super(tool, "/create_struct");
	}

	/**
	 * Handles the HTTP request to create a new struct.
	 * Parses parameters from the POST request and creates the struct in Ghidra.
	 *
	 * @param exchange The HTTP exchange containing the request and response.
	 * @throws IOException If an I/O error occurs during handling.
	 */
	public void handle(HttpExchange exchange) throws IOException {
		Map<String, String> params = parsePostParams(exchange);
		String name = params.get("name");
		String category = params.get("category");
		long size = parseIntOrDefault(params.get("size"), 0);
		String membersJson = params.get("members"); // Optional

		if (name == null || name.isEmpty()) {
			sendResponse(exchange, "Struct name is required");
			return;
		}
		sendResponse(exchange, createStruct(name, category, (int) size, membersJson));
	}

	/**
	 * Creates a new struct in Ghidra with the specified parameters.
	 * This method runs on the Swing thread to ensure thread safety when interacting with Ghidra's data types.
	 *
	 * @param name        The name of the struct to create.
	 * @param category    The category path where the struct will be created (optional).
	 * @param size        The size of the struct (optional, defaults to 0).
	 * @param membersJson JSON array of struct members (optional).
	 * @return A message indicating success or failure of the operation.
	 */
	private String createStruct(String name, String category, int size, String membersJson) {
		Program program = getCurrentProgram(tool);
		if (program == null)
			return "No program loaded";

		final AtomicReference<String> result = new AtomicReference<>();
		try {
			SwingUtilities.invokeAndWait(() -> {
				int txId = program.startTransaction("Create Struct");
				boolean success = false;
				try {
					DataTypeManager dtm = program.getDataTypeManager();
					CategoryPath path = new CategoryPath(category == null ? "/" : category);

					if (dtm.getDataType(path, name) != null) {
						result.set("Error: Struct " + name + " already exists in category " + path);
						return;
					}
					StructureDataType newStruct = new StructureDataType(path, name, size, dtm);

					StringBuilder responseBuilder = new StringBuilder(
							"Struct " + name + " created successfully in category " + path);

					if (membersJson != null && !membersJson.isEmpty()) {
						Gson gson = new Gson();
						StructMember[] members = gson.fromJson(membersJson, StructMember[].class);

						int membersAdded = 0;
						for (StructMember member : members) {
							DataType memberDt = resolveDataType(tool, dtm, member.type);
							if (memberDt == null) {
								responseBuilder.append("\nError: Could not resolve data type '").append(member.type)
										.append("' for member '").append(member.name)
										.append("'. Aborting further member creation.");
								break;
							}

							if (member.offset != -1) {
								newStruct.insertAtOffset((int) member.offset, memberDt, -1, member.name,
										member.comment);
							} else {
								newStruct.add(memberDt, member.name, member.comment);
							}
							membersAdded++;
						}
						responseBuilder.append("\nAdded ").append(membersAdded).append(" members.");
					}
					dtm.addDataType(newStruct, DataTypeConflictHandler.DEFAULT_HANDLER);
					result.set(responseBuilder.toString());
					success = true;
				} catch (Exception e) {
					result.set("Error: Failed to create struct: " + e.getMessage());
				} finally {
					program.endTransaction(txId, success);
				}
			});
		} catch (InterruptedException | InvocationTargetException e) {
			return "Error: Failed to execute create struct on Swing thread: " + e.getMessage();
		}
		return result.get();
	}
}
