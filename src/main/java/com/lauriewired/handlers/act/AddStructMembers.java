package com.lauriewired.handlers.act;

import com.lauriewired.handlers.Handler;
import com.sun.net.httpserver.HttpExchange;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeManager;
import ghidra.program.model.data.Structure;
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
 * Handler for adding members to a structure in Ghidra.
 * Expects a POST request with parameters:
 * - struct_name: Name of the structure to modify
 * - category: Category path where the structure is located (optional)
 * - members: JSON array of members to add, each with fields:
 *   - type: Data type of the member
 *   - name: Name of the member
 *   - comment: Comment for the member (optional)
 *   - offset: Offset in bytes (optional, -1 for next available position)
 */
public final class AddStructMembers extends Handler {
	/**
	 * Constructor for the AddStructMembers handler.
	 *
	 * @param tool The Ghidra plugin tool instance.
	 */
	public AddStructMembers(PluginTool tool) {
		super(tool, "/add_struct_members");
	}

	/**
	 * Handles the HTTP request to add members to a structure.
	 *
	 * @param exchange The HTTP exchange containing the request and response.
	 * @throws IOException If an I/O error occurs during handling.
	 */
	@Override
	public void handle(HttpExchange exchange) throws IOException {
		Map<String, String> params = parsePostParams(exchange);
		String structName = params.get("struct_name");
		String category = params.get("category");
		String membersJson = params.get("members");

		if (structName == null || membersJson == null) {
			sendResponse(exchange, "struct_name and members are required");
			return;
		}
		sendResponse(exchange, addStructMembers(structName, category, membersJson));
	}

	/**
	 * Adds members to a structure in the current Ghidra program.
	 *
	 * @param structName The name of the structure to modify.
	 * @param category   The category path where the structure is located (optional).
	 * @param membersJson JSON array of members to add.
	 * @return A message indicating success or failure.
	 */
	private String addStructMembers(String structName, String category, String membersJson) {
		Program program = getCurrentProgram(tool);
		if (program == null)
			return "No program loaded";

		final AtomicReference<String> result = new AtomicReference<>();
		try {
			SwingUtilities.invokeAndWait(() -> {
				int txId = program.startTransaction("Add Struct Member");
				boolean success = false;
				try {
					DataTypeManager dtm = program.getDataTypeManager();
					CategoryPath path = new CategoryPath(category == null ? "/" : category);
					DataType dt = dtm.getDataType(path, structName);

					if (dt == null || !(dt instanceof Structure)) {
						result.set("Error: Struct " + structName + " not found in category " + path);
						return;
					}
					Structure struct = (Structure) dt;

					StringBuilder responseBuilder = new StringBuilder();

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
								struct.insertAtOffset((int) member.offset, memberDt, -1, member.name, member.comment);
							} else {
								struct.add(memberDt, member.name, member.comment);
							}
							membersAdded++;
						}
						responseBuilder.append("\nAdded ").append(membersAdded).append(" members.");
						result.set(responseBuilder.toString());
						success = membersAdded > 0;
					}

				} catch (Exception e) {
					result.set("Error: Failed to add member to struct: " + e.getMessage());
				} finally {
					program.endTransaction(txId, success);
				}
			});
		} catch (InterruptedException | InvocationTargetException e) {
			return "Error: Failed to execute add struct member on Swing thread: " + e.getMessage();
		}
		return result.get();
	}
}
