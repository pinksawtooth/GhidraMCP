package com.lauriewired.handlers.set;

import com.lauriewired.handlers.Handler;
import com.sun.net.httpserver.HttpExchange;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeManager;
import ghidra.program.model.data.PointerDataType;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.program.model.pcode.HighFunctionDBUtil;
import ghidra.program.model.pcode.HighSymbol;
import ghidra.program.model.pcode.HighVariable;
import ghidra.program.model.symbol.SourceType;
import ghidra.util.Msg;
import ghidra.util.task.ConsoleTaskMonitor;

import javax.swing.*;
import java.lang.reflect.InvocationTargetException;
import java.util.Iterator;
import java.util.Map;
import java.util.concurrent.atomic.AtomicBoolean;

import static com.lauriewired.util.GhidraUtils.resolveDataType;
import static com.lauriewired.util.ParseUtils.*;
import static ghidra.program.util.GhidraProgramUtilities.getCurrentProgram;

/**
 * Handler for setting the type of a local variable in a function.
 * This handler allows users to specify a function address, variable name,
 * and the new type they want to set for that variable.
 */
public final class SetLocalVariableType extends Handler {
	/**
	 * Constructor for the SetLocalVariableType handler.
	 * 
	 * @param tool The PluginTool instance to use for accessing the current program.
	 */
	public SetLocalVariableType(PluginTool tool) {
		super(tool, "/set_local_variable_type");
	}

	/**
	 * Handles the HTTP request to set a local variable's type.
	 * 
	 * @param exchange The HttpExchange object containing the request and response.
	 * @throws Exception If an error occurs while processing the request.
	 */
	@Override
	public void handle(HttpExchange exchange) throws Exception {
		Map<String, String> params = parsePostParams(exchange);
		String functionAddress = params.get("function_address");
		String variableName = params.get("variable_name");
		String newType = params.get("new_type");

		// Capture detailed information about setting the type
		StringBuilder responseMsg = new StringBuilder();
		responseMsg.append("Setting variable type: ").append(variableName)
				.append(" to ").append(newType)
				.append(" in function at ").append(functionAddress).append("\n\n");

		// Attempt to find the data type in various categories
		Program program = getCurrentProgram(tool);
		if (program != null) {
			DataTypeManager dtm = program.getDataTypeManager();
			DataType directType = findDataTypeByNameInAllCategories(dtm, newType);
			if (directType != null) {
				responseMsg.append("Found type: ").append(directType.getPathName()).append("\n");
			} else if (newType.startsWith("P") && newType.length() > 1) {
				String baseTypeName = newType.substring(1);
				DataType baseType = findDataTypeByNameInAllCategories(dtm, baseTypeName);
				if (baseType != null) {
					responseMsg.append("Found base type for pointer: ").append(baseType.getPathName()).append("\n");
				} else {
					responseMsg.append("Base type not found for pointer: ").append(baseTypeName).append("\n");
				}
			} else {
				responseMsg.append("Type not found directly: ").append(newType).append("\n");
			}
		}

		// Try to set the type
		boolean success = setLocalVariableType(functionAddress, variableName, newType);

		String successMsg = success ? "Variable type set successfully" : "Failed to set variable type";
		responseMsg.append("\nResult: ").append(successMsg);

		sendResponse(exchange, responseMsg.toString());
	}

	/**
	 * Sets the type of a local variable in a function.
	 * 
	 * @param functionAddrStr The address of the function as a string.
	 * @param variableName    The name of the variable to change.
	 * @param newType         The new type to set for the variable.
	 * @return true if the type was set successfully, false otherwise.
	 */
	private boolean setLocalVariableType(String functionAddrStr, String variableName, String newType) {
		// Input validation
		Program program = getCurrentProgram(tool);
		if (program == null)
			return false;
		if (functionAddrStr == null || functionAddrStr.isEmpty() ||
				variableName == null || variableName.isEmpty() ||
				newType == null || newType.isEmpty()) {
			return false;
		}

		AtomicBoolean success = new AtomicBoolean(false);

		try {
			SwingUtilities
					.invokeAndWait(() -> applyVariableType(program, functionAddrStr, variableName, newType, success));
		} catch (InterruptedException | InvocationTargetException e) {
			Msg.error(this, "Failed to execute set variable type on Swing thread", e);
		}

		return success.get();
	}

	/**
	 * Applies the new type to the specified variable in the given function.
	 * This method is run on the Swing thread to ensure UI updates are safe.
	 * 
	 * @param program         The current program.
	 * @param functionAddrStr The address of the function as a string.
	 * @param variableName    The name of the variable to change.
	 * @param newType         The new type to set for the variable.
	 * @param success         AtomicBoolean to indicate if the operation was
	 *                        successful.
	 */
	private void applyVariableType(Program program, String functionAddrStr,
			String variableName, String newType, AtomicBoolean success) {
		try {
			// Find the function
			Address addr = program.getAddressFactory().getAddress(functionAddrStr);
			Function func = program.getListing().getFunctionContaining(addr);

			if (func == null) {
				Msg.error(this, "Could not find function at address: " + functionAddrStr);
				return;
			}

			DecompileResults results = decompileFunction(func, program);
			if (results == null || !results.decompileCompleted()) {
				return;
			}

			ghidra.program.model.pcode.HighFunction highFunction = results.getHighFunction();
			if (highFunction == null) {
				Msg.error(this, "No high function available");
				return;
			}

			// Find the symbol by name
			HighSymbol symbol = findSymbolByName(highFunction, variableName);
			if (symbol == null) {
				Msg.error(this, "Could not find variable '" + variableName + "' in decompiled function");
				return;
			}

			// Get high variable
			HighVariable highVar = symbol.getHighVariable();
			if (highVar == null) {
				Msg.error(this, "No HighVariable found for symbol: " + variableName);
				return;
			}

			Msg.info(this, "Found high variable for: " + variableName +
					" with current type " + highVar.getDataType().getName());

			// Find the data type
			DataTypeManager dtm = program.getDataTypeManager();
			DataType dataType = resolveDataType(tool, dtm, newType);

			if (dataType == null) {
				Msg.error(this, "Could not resolve data type: " + newType);
				return;
			}

			Msg.info(this, "Using data type: " + dataType.getName() + " for variable " + variableName);

			// Apply the type change in a transaction
			updateVariableType(program, symbol, dataType, success);

		} catch (Exception e) {
			Msg.error(this, "Error setting variable type: " + e.getMessage());
		}
	}

	/**
	 * Helper method to find a data type by name in all categories, handling case
	 * sensitivity.
	 * 
	 * @param dtm      The data type manager to search in.
	 * @param typeName The name of the type to find.
	 * @return The DataType if found, or null if not found.
	 */
	private DataType findDataTypeByNameInAllCategories(DataTypeManager dtm, String typeName) {
		// Try exact match first
		DataType result = searchByNameInAllCategories(dtm, typeName);
		if (result != null) {
			return result;
		}

		// Try lowercase
		return searchByNameInAllCategories(dtm, typeName.toLowerCase());
	}

	/**
	 * Searches for a data type by name in all categories of the DataTypeManager.
	 * This method checks both exact and case-insensitive matches.
	 * 
	 * @param dtm  The DataTypeManager to search in.
	 * @param name The name of the data type to search for.
	 * @return The DataType if found, or null if not found.
	 */
	private DataType searchByNameInAllCategories(DataTypeManager dtm, String name) {
		// Get all data types from the manager
		Iterator<DataType> allTypes = dtm.getAllDataTypes();
		while (allTypes.hasNext()) {
			DataType dt = allTypes.next();
			// Check if the name matches exactly (case-sensitive)
			if (dt.getName().equals(name)) {
				return dt;
			}
			// For case-insensitive, we want an exact match except for case
			if (dt.getName().equalsIgnoreCase(name)) {
				return dt;
			}
		}
		return null;
	}

	/**
	 * Find a symbol by name in the local symbol map of the high function.
	 * 
	 * @param highFunction The high function to search in.
	 * @param variableName The name of the variable to find.
	 * @return The HighSymbol if found, or null if not found.
	 */
	private HighSymbol findSymbolByName(ghidra.program.model.pcode.HighFunction highFunction, String variableName) {
		Iterator<HighSymbol> symbols = highFunction.getLocalSymbolMap().getSymbols();
		while (symbols.hasNext()) {
			HighSymbol s = symbols.next();
			if (s.getName().equals(variableName)) {
				return s;
			}
		}
		return null;
	}

	/**
	 * Decompile the function to access its high-level representation.
	 * 
	 * @param func    The function to decompile.
	 * @param program The current program.
	 * @return The DecompileResults containing the decompiled function.
	 */
	private DecompileResults decompileFunction(Function func, Program program) {
		// Set up decompiler for accessing the decompiled function
		DecompInterface decomp = new DecompInterface();
		decomp.openProgram(program);
		decomp.setSimplificationStyle("decompile"); // Full decompilation

		// Decompile the function
		DecompileResults results = decomp.decompileFunction(func, 60, new ConsoleTaskMonitor());

		if (!results.decompileCompleted()) {
			Msg.error(this, "Could not decompile function: " + results.getErrorMessage());
			return null;
		}

		return results;
	}

	/**
	 * Update the variable type in the database using HighFunctionDBUtil.
	 * 
	 * @param program  The current program.
	 * @param symbol   The high symbol representing the variable.
	 * @param dataType The new data type to set for the variable.
	 * @param success  AtomicBoolean to indicate if the operation was successful.
	 */
	private void updateVariableType(Program program, HighSymbol symbol, DataType dataType, AtomicBoolean success) {
		int tx = program.startTransaction("Set variable type");
		try {
			// Use HighFunctionDBUtil to update the variable with the new type
			HighFunctionDBUtil.updateDBVariable(
					symbol, // The high symbol to modify
					symbol.getName(), // Keep original name
					dataType, // The new data type
					SourceType.USER_DEFINED // Mark as user-defined
			);

			success.set(true);
			Msg.info(this, "Successfully set variable type using HighFunctionDBUtil");
		} catch (Exception e) {
			Msg.error(this, "Error setting variable type: " + e.getMessage());
		} finally {
			program.endTransaction(tx, success.get());
		}
	}
}
