package com.lauriewired.handlers.set;

import com.lauriewired.handlers.Handler;
import com.sun.net.httpserver.HttpExchange;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.SourceType;
import ghidra.util.Msg;

import javax.swing.*;
import java.lang.reflect.InvocationTargetException;
import java.util.Map;
import java.util.concurrent.atomic.AtomicBoolean;

import static com.lauriewired.util.ParseUtils.parsePostParams;
import static com.lauriewired.util.ParseUtils.sendResponse;
import static ghidra.program.util.GhidraProgramUtilities.getCurrentProgram;

/**
 * Handler to rename a function by its address
 */
public final class RenameFunctionByAddress extends Handler {
	/**
	 * Constructor for the RenameFunctionByAddress handler
	 *
	 * @param tool the PluginTool instance
	 */
	public RenameFunctionByAddress(PluginTool tool) {
		super(tool, "/rename_function_by_address");
	}

	/**
	 * Handle the HTTP request to rename a function by its address
	 *
	 * @param exchange the HttpExchange instance containing the request
	 * @throws Exception if an error occurs during processing
	 */
	@Override
	public void handle(HttpExchange exchange) throws Exception {
		Map<String, String> params = parsePostParams(exchange);
		String functionAddress = params.get("function_address");
		String newName = params.get("new_name");
		boolean success = renameFunctionByAddress(functionAddress, newName);
		sendResponse(exchange, success ? "Function renamed successfully" : "Failed to rename function");
	}

	/**
	 * Renames a function by its address
	 *
	 * @param functionAddrStr the address of the function as a string
	 * @param newName         the new name for the function
	 * @return true if the rename was successful, false otherwise
	 */
	private boolean renameFunctionByAddress(String functionAddrStr, String newName) {
		Program program = getCurrentProgram(tool);
		if (program == null)
			return false;
		if (functionAddrStr == null || functionAddrStr.isEmpty() ||
				newName == null || newName.isEmpty()) {
			return false;
		}

		AtomicBoolean success = new AtomicBoolean(false);

		try {
			SwingUtilities.invokeAndWait(() -> {
				performFunctionRename(program, functionAddrStr, newName, success);
			});
		} catch (InterruptedException | InvocationTargetException e) {
			Msg.error(this, "Failed to execute rename function on Swing thread", e);
		}

		return success.get();
	}

	/**
	 * Performs the function renaming operation on the Swing thread
	 *
	 * @param program         the current program
	 * @param functionAddrStr the address of the function as a string
	 * @param newName         the new name for the function
	 * @param success         an AtomicBoolean to indicate success or failure
	 */
	private void performFunctionRename(Program program, String functionAddrStr, String newName, AtomicBoolean success) {
		int tx = program.startTransaction("Rename function by address");
		try {
			Address addr = program.getAddressFactory().getAddress(functionAddrStr);
			Function func = program.getListing().getFunctionContaining(addr);

			if (func == null) {
				Msg.error(this, "Could not find function at address: " + functionAddrStr);
				return;
			}

			func.setName(newName, SourceType.USER_DEFINED);
			success.set(true);
		} catch (Exception e) {
			Msg.error(this, "Error renaming function by address", e);
		} finally {
			program.endTransaction(tx, success.get());
		}
	}
}
