package com.lauriewired.handlers.comment;

import com.lauriewired.handlers.Handler;
import com.sun.net.httpserver.HttpExchange;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.listing.CommentType;

import java.util.Map;

import static com.lauriewired.util.GhidraUtils.setCommentAtAddress;
import static com.lauriewired.util.ParseUtils.parsePostParams;
import static com.lauriewired.util.ParseUtils.sendResponse;

/**
 * Handler for setting a comment in the disassembly at a specific address.
 * Expects POST request with parameters: address and comment.
 */
public final class SetDisassemblyComment extends Handler {
	/**
	 * Constructor for the SetDisassemblyComment handler.
	 *
	 * @param tool the Ghidra PluginTool instance
	 */
	public SetDisassemblyComment(PluginTool tool) {
		super(tool, "/set_disassembly_comment");
	}

	/**
	 * Handles the HTTP request to set a disassembly comment.
	 * Expects a POST request with parameters: address and comment.
	 *
	 * @param exchange the HTTP exchange containing the request
	 * @throws Exception if an error occurs while handling the request
	 */
	@Override
	public void handle(HttpExchange exchange) throws Exception {
		Map<String, String> params = parsePostParams(exchange);
		String address = params.get("address");
		String comment = params.get("comment");
		boolean success = setDisassemblyComment(address, comment);
		sendResponse(exchange, success ? "Comment set successfully" : "Failed to set comment");
	}

	/**
	 * Sets a disassembly comment at the specified address.
	 *
	 * @param addressStr the address as a string
	 * @param comment    the comment to set
	 * @return true if the comment was set successfully, false otherwise
	 */
	private boolean setDisassemblyComment(String addressStr, String comment) {
		return setCommentAtAddress(tool, addressStr, comment, CommentType.EOL, "Set disassembly comment");
	}
}
