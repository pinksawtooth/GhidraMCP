package com.lauriewired.handlers.set;

import com.lauriewired.handlers.Handler;
import com.sun.net.httpserver.HttpExchange;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeManager;
import ghidra.program.model.data.Structure;
import ghidra.program.model.listing.Program;

import javax.swing.SwingUtilities;
import java.io.IOException;
import java.lang.reflect.InvocationTargetException;
import java.util.*;
import java.util.concurrent.atomic.AtomicReference;

import static com.lauriewired.util.ParseUtils.*;
import ghidra.program.model.data.CategoryPath;
import static ghidra.program.util.GhidraProgramUtilities.getCurrentProgram;

/**
 * Handler for clearing the contents of a structure in Ghidra.
 * This handler processes requests to clear a specified structure by name and
 * category.
 */
public final class ClearStruct extends Handler {
	/**
	 * Constructs a new ClearStruct handler.
	 *
	 * @param tool the PluginTool instance to use for program operations
	 */
	public ClearStruct(PluginTool tool) {
		super(tool, "/clear_struct");
	}

	/**
	 * Handles HTTP requests to clear a structure.
	 * Expects POST parameters: struct_name (required), category (optional).
	 *
	 * @param exchange the HttpExchange object containing the request
	 * @throws IOException if an I/O error occurs
	 */
	@Override
	public void handle(HttpExchange exchange) throws IOException {
		Map<String, String> params = parsePostParams(exchange);
		String structName = params.get("struct_name");
		String category = params.get("category");
		if (structName == null) {
			sendResponse(exchange, "struct_name is required");
			return;
		}
		sendResponse(exchange, clearStruct(structName, category));
	}

	/**
	 * Clears the contents of a structure.
	 *
	 * @param structName the name of the structure to clear
	 * @param category   the category of the structure
	 * @return a message indicating the result of the operation
	 */
	private String clearStruct(String structName, String category) {
		Program program = getCurrentProgram(tool);
		if (program == null)
			return "No program loaded";

		final AtomicReference<String> result = new AtomicReference<>();
		try {
			SwingUtilities.invokeAndWait(() -> {
				int txId = program.startTransaction("Clear Struct");
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
					if (struct.isNotYetDefined()) {
						result.set("Struct " + structName + " is empty, nothing to clear.");
						success = true; // Not an error state
						return;
					}
					struct.deleteAll();
					result.set("Struct " + structName + " cleared.");
					success = true;
				} catch (Exception e) {
					result.set("Error: Failed to clear struct: " + e.getMessage());
				} finally {
					program.endTransaction(txId, success);
				}
			});
		} catch (InterruptedException | InvocationTargetException e) {
			return "Error: Failed to execute clear struct on Swing thread: " + e.getMessage();
		}
		return result.get();
	}
}
