package com.lauriewired.handlers.get;

import com.lauriewired.handlers.Handler;
import com.sun.net.httpserver.HttpExchange;
import ghidra.app.services.CodeViewerService;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.program.util.ProgramLocation;

import java.io.IOException;

import static com.lauriewired.util.ParseUtils.sendResponse;
import static ghidra.program.util.GhidraProgramUtilities.getCurrentProgram;

/**
 * Handler to get the current function in Ghidra GUI.
 * Responds with the function name, entry point, and signature.
 */
public final class GetCurrentFunction extends Handler {
	/**
	 * Constructor for the GetCurrentFunction handler.
	 *
	 * @param tool The Ghidra PluginTool instance.
	 */
	public GetCurrentFunction(PluginTool tool) {
		super(tool, "/get_current_function");
	}

	/**
	 * Handles the HTTP request to get the current function.
	 *
	 * @param exchange The HTTP exchange containing the request and response.
	 * @throws IOException If an I/O error occurs during handling.
	 */
	@Override
	public void handle(HttpExchange exchange) throws IOException {
		sendResponse(exchange, getCurrentFunction());
	}

	/**
	 * Retrieves the current function at the current location in the Ghidra GUI.
	 *
	 * @return A string containing the function name, entry point, and signature,
	 *         or an error message if no function is found or if there are issues.
	 */
	private String getCurrentFunction() {
		CodeViewerService service = tool.getService(CodeViewerService.class);
		if (service == null)
			return "Code viewer service not available";

		ProgramLocation location = service.getCurrentLocation();
		if (location == null)
			return "No current location";

		Program program = getCurrentProgram(tool);
		if (program == null)
			return "No program loaded";

		Function func = program.getFunctionManager().getFunctionContaining(location.getAddress());
		if (func == null)
			return "No function at current location: " + location.getAddress();

		return String.format("Function: %s at %s\nSignature: %s",
				func.getName(),
				func.getEntryPoint(),
				func.getSignature());
	}
}
