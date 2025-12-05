package com.lauriewired.handlers.get;

import com.lauriewired.handlers.Handler;
import com.sun.net.httpserver.HttpExchange;
import ghidra.app.services.CodeViewerService;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.util.ProgramLocation;

import java.io.IOException;

import static com.lauriewired.util.ParseUtils.sendResponse;

/**
 * Handler to get the current address from the CodeViewerService
 */
public final class GetCurrentAddress extends Handler {
	/**
	 * Constructor for GetCurrentAddress handler
	 *
	 * @param tool PluginTool instance to access Ghidra services
	 */
	public GetCurrentAddress(PluginTool tool) {
		super(tool, "/get_current_address");
	}

	/**
	 * Handle HTTP request to get current address
	 *
	 * @param exchange HttpExchange instance containing request and response
	 * @throws IOException if an I/O error occurs
	 */
	@Override
	public void handle(HttpExchange exchange) throws IOException {
		sendResponse(exchange, getCurrentAddress());
	}

	/**
	 * Retrieves the current address from the CodeViewerService
	 *
	 * @return String representation of the current address or an error message
	 */
	private String getCurrentAddress() {
		CodeViewerService service = tool.getService(CodeViewerService.class);
		if (service == null)
			return "Code viewer service not available";

		ProgramLocation location = service.getCurrentLocation();
		return (location != null) ? location.getAddress().toString() : "No current location";
	}
}
