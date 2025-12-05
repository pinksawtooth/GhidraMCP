package com.lauriewired.handlers.set;

import com.lauriewired.handlers.Handler;
import com.sun.net.httpserver.HttpExchange;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeManager;
import ghidra.program.model.data.DataUtilities;
import ghidra.program.model.data.DataUtilities.ClearDataMode;
import ghidra.program.model.util.CodeUnitInsertionException;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Program;
import ghidra.util.Msg;

import javax.swing.SwingUtilities;
import java.io.IOException;
import java.lang.reflect.InvocationTargetException;
import java.util.Map;
import java.util.concurrent.atomic.AtomicReference;

import static com.lauriewired.util.GhidraUtils.resolveDataType;
import static com.lauriewired.util.ParseUtils.*;
import static ghidra.program.util.GhidraProgramUtilities.getCurrentProgram;

/**
 * Handler for setting the data type of a global variable or data at a specific address.
 * This handler allows users to specify an address and the new data type they want to apply,
 * effectively creating typed data at memory locations.
 * 
 * Expects POST parameters:
 * - address: The memory address where to set the data type
 * - data_type: The name of the data type to apply
 * - length: Optional length for dynamic data types (default: -1, let type determine)
 * - clear_mode: Optional clearing mode (default: "CHECK_FOR_SPACE")
 */
public final class SetGlobalDataType extends Handler {
	/**
	 * Constructor for the SetGlobalDataType handler.
	 * 
	 * @param tool The PluginTool instance to use for accessing the current program.
	 */
	public SetGlobalDataType(PluginTool tool) {
		super(tool, "/set_global_data_type");
	}

	/**
	 * Handles the HTTP request to set a global data type at a specific address.
	 * 
	 * @param exchange The HttpExchange object containing the request and response.
	 * @throws IOException If an I/O error occurs during handling.
	 */
	@Override
	public void handle(HttpExchange exchange) throws IOException {
		Map<String, String> params = parsePostParams(exchange);
		String addressStr = params.get("address");
		String dataTypeName = params.get("data_type");
		String lengthStr = params.get("length");
		String clearModeStr = params.get("clear_mode");

		if (addressStr == null || addressStr.isEmpty()) {
			sendResponse(exchange, "Error: address parameter is required");
			return;
		}

		if (dataTypeName == null || dataTypeName.isEmpty()) {
			sendResponse(exchange, "Error: data_type parameter is required");
			return;
		}

		int length = parseIntOrDefault(lengthStr, -1);
		ClearDataMode clearMode = parseClearDataMode(clearModeStr);

		// Capture detailed information about setting the data type
		StringBuilder responseMsg = new StringBuilder();
		responseMsg.append("Setting data type at address ").append(addressStr)
				.append(" to type ").append(dataTypeName);
		if (length > 0) {
			responseMsg.append(" with length ").append(length);
		}
		responseMsg.append(" using clear mode ").append(clearMode).append("\n\n");

		// Attempt to find the data type
		Program program = getCurrentProgram(tool);
		if (program != null) {
			DataTypeManager dtm = program.getDataTypeManager();
			DataType dataType = resolveDataType(tool, dtm, dataTypeName);
			if (dataType != null) {
				responseMsg.append("Found data type: ").append(dataType.getPathName()).append("\n");
			} else {
				responseMsg.append("Warning: Data type not found: ").append(dataTypeName).append("\n");
			}
		}

		// Try to set the data type
		String result = setGlobalDataType(addressStr, dataTypeName, length, clearMode);
		responseMsg.append("\nResult: ").append(result);

		sendResponse(exchange, responseMsg.toString());
	}

	/**
	 * Sets the data type at the specified address.
	 * 
	 * @param addressStr The address where to set the data type as a string.
	 * @param dataTypeName The name of the data type to apply.
	 * @param length The length for dynamic data types, or -1 to let the type determine.
	 * @param clearMode The clearing mode to use when conflicting data exists.
	 * @return A message indicating success or failure of the operation.
	 */
	private String setGlobalDataType(String addressStr, String dataTypeName, int length, ClearDataMode clearMode) {
		Program program = getCurrentProgram(tool);
		if (program == null) {
			return "No program loaded";
		}

		final AtomicReference<String> result = new AtomicReference<>();
		try {
			SwingUtilities.invokeAndWait(() -> {
				int txId = program.startTransaction("Set Global Data Type");
				boolean success = false;
				try {
					// Parse the address
					Address address = program.getAddressFactory().getAddress(addressStr);
					if (address == null) {
						result.set("Error: Invalid address format: " + addressStr);
						return;
					}

					// Resolve the data type
					DataTypeManager dtm = program.getDataTypeManager();
					DataType dataType = resolveDataType(tool, dtm, dataTypeName);
					if (dataType == null) {
						result.set("Error: Could not resolve data type: " + dataTypeName);
						return;
					}

					Msg.info(this, "Setting data type " + dataType.getName() + " at address " + address);

					// Create the data using DataUtilities
					Data newData = DataUtilities.createData(program, address, dataType, length, clearMode);
					
					if (newData != null) {
						result.set("Successfully set data type '" + dataType.getName() + 
								"' at address " + address + ". Data length: " + newData.getLength() + " bytes.");
						success = true;
					} else {
						result.set("Error: Failed to create data at address " + address);
					}

				} catch (CodeUnitInsertionException e) {
					result.set("Error: Could not insert data at address " + addressStr + 
							" - " + e.getMessage() + ". Try using a different clear_mode.");
				} catch (Exception e) {
					result.set("Error: Failed to set data type: " + e.getMessage());
					Msg.error(this, "Error setting global data type", e);
				} finally {
					program.endTransaction(txId, success);
				}
			});
		} catch (InterruptedException | InvocationTargetException e) {
			return "Error: Failed to execute set data type on Swing thread: " + e.getMessage();
		}
		return result.get();
	}

	/**
	 * Parses the clear mode string into a ClearDataMode enum value.
	 * 
	 * @param clearModeStr The clear mode string.
	 * @return The corresponding ClearDataMode enum value, or CHECK_FOR_SPACE as default.
	 */
	private ClearDataMode parseClearDataMode(String clearModeStr) {
		if (clearModeStr == null || clearModeStr.isEmpty()) {
			return ClearDataMode.CHECK_FOR_SPACE;
		}

		try {
			switch (clearModeStr.toUpperCase()) {
				case "CHECK_FOR_SPACE":
					return ClearDataMode.CHECK_FOR_SPACE;
				case "CLEAR_SINGLE_DATA":
					return ClearDataMode.CLEAR_SINGLE_DATA;
				case "CLEAR_ALL_UNDEFINED_CONFLICT_DATA":
					return ClearDataMode.CLEAR_ALL_UNDEFINED_CONFLICT_DATA;
				case "CLEAR_ALL_DEFAULT_CONFLICT_DATA":
					return ClearDataMode.CLEAR_ALL_DEFAULT_CONFLICT_DATA;
				case "CLEAR_ALL_CONFLICT_DATA":
					return ClearDataMode.CLEAR_ALL_CONFLICT_DATA;
				default:
					Msg.warn(this, "Unknown clear mode: " + clearModeStr + ", using CHECK_FOR_SPACE");
					return ClearDataMode.CHECK_FOR_SPACE;
			}
		} catch (Exception e) {
			Msg.warn(this, "Error parsing clear mode: " + clearModeStr + ", using CHECK_FOR_SPACE");
			return ClearDataMode.CHECK_FOR_SPACE;
		}
	}
}