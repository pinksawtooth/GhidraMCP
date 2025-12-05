package com.lauriewired.handlers.act;

import com.lauriewired.handlers.Handler;
import com.sun.net.httpserver.HttpExchange;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.data.DataTypeManager;
import ghidra.program.model.data.Structure;
import ghidra.program.model.data.DataTypeComponent;
import ghidra.program.model.listing.GhidraClass;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.Namespace;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolTable;
import ghidra.program.model.symbol.SymbolType;
import ghidra.program.database.data.DataTypeUtilities;

import com.google.gson.Gson;

import javax.swing.SwingUtilities;
import java.io.IOException;
import java.lang.reflect.InvocationTargetException;
import java.util.*;
import java.util.concurrent.atomic.AtomicReference;

import static com.lauriewired.util.ParseUtils.*;
import static ghidra.program.util.GhidraProgramUtilities.getCurrentProgram;

/**
 * Handler for removing members from a C++ class in Ghidra.
 * This modifies the class's associated structure data type.
 * Expects a POST request with parameters:
 * - class_name: Name of the class to modify
 * - parent_namespace: Parent namespace where the class is located (optional)
 * - members: JSON array of member names to remove, or single member name as string
 */
public final class RemoveClassMembers extends Handler {
	/**
	 * Constructor for the RemoveClassMembers handler.
	 *
	 * @param tool The Ghidra plugin tool instance.
	 */
	public RemoveClassMembers(PluginTool tool) {
		super(tool, "/remove_class_members");
	}

	/**
	 * Handles the HTTP request to remove members from a class.
	 *
	 * @param exchange The HTTP exchange containing the request and response.
	 * @throws IOException If an I/O error occurs during handling.
	 */
	@Override
	public void handle(HttpExchange exchange) throws IOException {
		Map<String, String> params = parsePostParams(exchange);
		String className = params.get("class_name");
		String parentNamespace = params.get("parent_namespace");
		String membersParam = params.get("members");

		if (className == null || membersParam == null) {
			sendResponse(exchange, "class_name and members are required");
			return;
		}
		sendResponse(exchange, removeClassMembers(className, parentNamespace, membersParam));
	}

	/**
	 * Removes members from a class in the current Ghidra program.
	 *
	 * @param className The name of the class to modify.
	 * @param parentNamespace The parent namespace where the class is located (optional).
	 * @param membersParam JSON array of member names to remove, or single member name.
	 * @return A message indicating success or failure.
	 */
	private String removeClassMembers(String className, String parentNamespace, String membersParam) {
		Program program = getCurrentProgram(tool);
		if (program == null)
			return "No program loaded";

		final AtomicReference<String> result = new AtomicReference<>();
		try {
			SwingUtilities.invokeAndWait(() -> {
				int txId = program.startTransaction("Remove Class Members");
				boolean success = false;
				try {
					SymbolTable symbolTable = program.getSymbolTable();
					DataTypeManager dtm = program.getDataTypeManager();

					// Find the class namespace
					Namespace parent = program.getGlobalNamespace();
					if (parentNamespace != null && !parentNamespace.isEmpty()) {
						parent = symbolTable.getNamespace(parentNamespace, program.getGlobalNamespace());
						if (parent == null) {
							result.set("Error: Parent namespace '" + parentNamespace + "' not found");
							return;
						}
					}

					// Find the class by iterating through symbols
					GhidraClass classNamespace = null;
					for (Symbol symbol : symbolTable.getSymbols(className, parent)) {
						if (symbol.getSymbolType() == SymbolType.CLASS) {
							classNamespace = (GhidraClass) symbol.getObject();
							break;
						}
					}

					if (classNamespace == null) {
						result.set("Error: Class '" + className + "' not found" + 
								(parent != null ? " in namespace " + parent.getName() : ""));
						return;
					}

					// Find the associated structure
					Structure classStruct = DataTypeUtilities.findExistingClassStruct(dtm, classNamespace);
					if (classStruct == null) {
						result.set("Error: No structure found for class '" + className + "'");
						return;
					}

					StringBuilder responseBuilder = new StringBuilder(
							"Removing members from class " + className);

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
						for (DataTypeComponent comp : classStruct.getComponents()) {
							if (comp.getFieldName() != null && comp.getFieldName().equals(memberName)) {
								component = comp;
								break;
							}
						}
						
						if (component == null) {
							responseBuilder.append("\nWarning: Member '").append(memberName)
									.append("' not found in class. Skipping.");
							continue;
						}

						int ordinal = component.getOrdinal();
						classStruct.delete(ordinal);
						responseBuilder.append("\nRemoved member '").append(memberName)
								.append("' (ordinal ").append(ordinal).append(")");
						membersRemoved++;
					}

					if (membersRemoved > 0) {
						responseBuilder.append("\nSuccessfully removed ").append(membersRemoved)
								.append(" members from class ").append(className);
						success = true;
					} else {
						responseBuilder.append("\nNo members were removed from class ").append(className);
					}

					result.set(responseBuilder.toString());

				} catch (Exception e) {
					result.set("Error: Failed to remove members from class: " + e.getMessage());
				} finally {
					program.endTransaction(txId, success);
				}
			});
		} catch (InterruptedException | InvocationTargetException e) {
			return "Error: Failed to execute remove class members on Swing thread: " + e.getMessage();
		}
		return result.get();
	}
}