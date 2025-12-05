package com.lauriewired.handlers.set;

import com.lauriewired.handlers.Handler;
import com.sun.net.httpserver.HttpExchange;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.SourceType;
import ghidra.util.Msg;

import javax.swing.*;
import java.io.IOException;
import java.lang.reflect.InvocationTargetException;
import java.util.Map;
import java.util.concurrent.atomic.AtomicBoolean;

import static com.lauriewired.util.ParseUtils.parsePostParams;
import static com.lauriewired.util.ParseUtils.sendResponse;
import static ghidra.program.util.GhidraProgramUtilities.getCurrentProgram;

/**
 * Handler for renaming a function in the current program.
 * Expects POST parameters: oldName and newName.
 */
public final class RenameFunction extends Handler {
	/**
	 * Constructor for RenameFunction handler.
	 *
	 * @param tool the PluginTool instance to interact with Ghidra
	 */
	public RenameFunction(PluginTool tool) {
		super(tool, "/renameFunction");
	}

	/**
	 * Handles the HTTP request to rename a function.
	 * Expects parameters "oldName" and "newName" in the POST request.
	 *
	 * @param exchange the HttpExchange object containing the request
	 * @throws IOException if an I/O error occurs
	 */
	@Override
	public void handle(HttpExchange exchange) throws IOException {
		Map<String, String> params = parsePostParams(exchange);
		String response = rename(params.get("oldName"), params.get("newName"))
				? "Renamed successfully"
				: "Rename failed";
		sendResponse(exchange, response);
	}

	/**
	 * Renames a function in the current program.
	 *
	 * @param oldName the current name of the function
	 * @param newName the new name to set for the function
	 * @return true if the rename was successful, false otherwise
	 */
	private boolean rename(String oldName, String newName) {
		Program program = getCurrentProgram(tool);
		if (program == null)
			return false;

		AtomicBoolean successFlag = new AtomicBoolean(false);
		try {
			SwingUtilities.invokeAndWait(() -> {
				int tx = program.startTransaction("Rename function via HTTP");
				try {
					for (Function func : program.getFunctionManager().getFunctions(true)) {
						if (func.getName().equals(oldName)) {
							func.setName(newName, SourceType.USER_DEFINED);
							successFlag.set(true);
							break;
						}
					}
				} catch (Exception e) {
					Msg.error(this, "Error renaming function", e);
				} finally {
					program.endTransaction(tx, successFlag.get());
				}
			});
		} catch (InterruptedException | InvocationTargetException e) {
			Msg.error(this, "Failed to execute rename on Swing thread", e);
		}
		return successFlag.get();
	}
}
