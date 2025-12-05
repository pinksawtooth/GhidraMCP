package com.lauriewired.handlers.act;

import com.lauriewired.handlers.Handler;
import com.sun.net.httpserver.HttpExchange;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.BookmarkManager;
import ghidra.program.model.listing.BookmarkType;
import ghidra.program.model.listing.Program;

import javax.swing.*;
import java.io.IOException;
import java.util.Map;
import java.util.concurrent.atomic.AtomicReference;

import static com.lauriewired.util.ParseUtils.parsePostParams;
import static com.lauriewired.util.ParseUtils.sendResponse;
import static ghidra.program.util.GhidraProgramUtilities.getCurrentProgram;

/**
 * Handler for POST requests to add a bookmark at a specific address.
 */
public class AddBookmark extends Handler {
	/**
	 * Constructor for AddBookmark.
	 *
	 * @param tool the plugin tool
	 */
	public AddBookmark(PluginTool tool) {
		super(tool, "/add_bookmark");
	}

	/**
	 * Handles the HTTP exchange to add a bookmark.
	 *
	 * @param exchange the HTTP exchange
	 * @throws IOException
	 */
	@Override
	public void handle(HttpExchange exchange) throws IOException {
		if (!"POST".equals(exchange.getRequestMethod())) {
			sendResponse(exchange, "Unsupported method");
			return;
		}

		Map<String, String> params = parsePostParams(exchange);
		String addressStr = params.get("address");
		String category = params.get("category");
		String comment = params.get("comment");
		String type = params.get("type");

		if (addressStr == null || category == null || comment == null || type == null) {
			sendResponse(exchange, "Missing required parameters: address, category, comment, type");
			return;
		}

		sendResponse(exchange, addBookmark(addressStr, category, comment, type));
	}

	private String addBookmark(String addressStr, String category, String comment, String type) {
		Program currentProgram = getCurrentProgram(tool);
		if (currentProgram == null) {
			return "No active program";
		}

		final AtomicReference<String> result = new AtomicReference<>();
		try {
			SwingUtilities.invokeAndWait(() -> {
				int transactionID = currentProgram.startTransaction("Add Bookmark");
				boolean success = false;
				try {
					Address address = currentProgram.getAddressFactory().getAddress(addressStr);
					BookmarkManager bookmarkManager = currentProgram.getBookmarkManager();
					bookmarkManager.setBookmark(address, type, category, comment);
					result.set("Bookmark created successfully at " + addressStr);
					success = true;
				} catch (Exception e) {
					result.set("Error processing request: " + e.getMessage());
				} finally {
					currentProgram.endTransaction(transactionID, success);
				}
			});
		} catch (Exception e) {
			return "Error processing request: " + e.getMessage();
		}
		return result.get();
	}
}
