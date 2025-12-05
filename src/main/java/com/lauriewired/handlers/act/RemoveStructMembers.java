package com.lauriewired.handlers.act;

import com.lauriewired.handlers.Handler;
import com.sun.net.httpserver.HttpExchange;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeManager;
import ghidra.program.model.data.Structure;
import ghidra.program.model.data.DataTypeComponent;
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
 * Handler for removing members from a structure in Ghidra.
 * Expects a POST request with parameters:
 * - struct_name: Name of the structure to modify
 * - category: Category path where the structure is located (optional)
 * - members: JSON array of member names to remove, or single member name as string
 */
public final class RemoveStructMembers extends Handler {
	/**
	 * Constructor for the RemoveStructMembers handler.
	 *
	 * @param tool The Ghidra plugin tool instance.
	 */
	public RemoveStructMembers(PluginTool tool) {
		super(tool, "/remove_struct_members");
	}

	/**
	 * Handles the HTTP request to remove members from a structure.
	 *
	 * @param exchange The HTTP exchange containing the request and response.
	 * @throws IOException If an I/O error occurs during handling.
	 */
	@Override
	public void handle(HttpExchange exchange) throws IOException {
		Map<String, String> params = parsePostParams(exchange);
		String structName = params.get("struct_name");
		String category = params.get("category");
		String membersParam = params.get("members");

		if (structName == null || membersParam == null) {
			sendResponse(exchange, "struct_name and members are required");
			return;
		}
		sendResponse(exchange, removeStructMembers(structName, category, membersParam));
	}

	/**
	 * Removes members from a structure in the current Ghidra program.
	 *
	 * @param structName The name of the structure to modify.
	 * @param category The category path where the structure is located (optional).
	 * @param membersParam JSON array of member names to remove, or single member name.
	 * @return A message indicating success or failure.
	 */
	private String removeStructMembers(String structName, String category, String membersParam) {
		Program program = getCurrentProgram(tool);
		if (program == null)
			return "No program loaded";

		final AtomicReference<String> result = new AtomicReference<>();
		try {
			SwingUtilities.invokeAndWait(() -> {
				int txId = program.startTransaction("Remove Struct Members");
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

					StringBuilder responseBuilder = new StringBuilder(
							"Removing members from struct " + structName);

					// Parse member names to remove
					List<String> memberNames = new ArrayList<>();
					try {
						// Try to parse as JSON array first
						Gson gson = new Gson();
						String[] names = gson.fromJson(membersParam, String[].class);
						memberNames.addAll(Arrays.asList(names));
					} catch (Exception e) {
						// If not JSON array, treat as single member name
						memberNames.add(membersParam.trim());
					}

					int membersRemoved = 0;
					for (String memberName : memberNames) {
						DataTypeComponent component = null;
						for (DataTypeComponent comp : struct.getComponents()) {
							if (comp.getFieldName() != null && comp.getFieldName().equals(memberName)) {
								component = comp;
								break;
							}
						}
						
						if (component == null) {
							responseBuilder.append("\nWarning: Member '").append(memberName)
									.append("' not found in struct. Skipping.");
							continue;
						}

						int ordinal = component.getOrdinal();
						struct.delete(ordinal);
						responseBuilder.append("\nRemoved member '").append(memberName)
								.append("' (ordinal ").append(ordinal).append(")");
						membersRemoved++;
					}

					if (membersRemoved > 0) {
						responseBuilder.append("\nSuccessfully removed ").append(membersRemoved)
								.append(" members from struct ").append(structName);
						success = true;
					} else {
						responseBuilder.append("\nNo members were removed from struct ").append(structName);
					}

					result.set(responseBuilder.toString());

				} catch (Exception e) {
					result.set("Error: Failed to remove members from struct: " + e.getMessage());
				} finally {
					program.endTransaction(txId, success);
				}
			});
		} catch (InterruptedException | InvocationTargetException e) {
			return "Error: Failed to execute remove struct members on Swing thread: " + e.getMessage();
		}
		return result.get();
	}
}