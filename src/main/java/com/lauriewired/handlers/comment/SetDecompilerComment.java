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
 * Handler for setting a decompiler comment in Ghidra
 * This handler processes HTTP requests to set comments on decompiled code
 */
public final class SetDecompilerComment extends Handler {
	/**
	 * Constructor for the SetDecompilerComment handler
	 * 
	 * @param tool The Ghidra PluginTool instance
	 */
	public SetDecompilerComment(PluginTool tool) {
		super(tool, "/set_decompiler_comment");
	}

	/**
	 * Handles HTTP POST requests to set a decompiler comment
	 * 
	 * @param exchange The HTTP exchange containing the request and response
	 * @throws Exception If an error occurs while processing the request
	 */
	@Override
	public void handle(HttpExchange exchange) throws Exception {
		Map<String, String> params = parsePostParams(exchange);
		String address = params.get("address");
		String comment = params.get("comment");
		boolean success = setDecompilerComment(address, comment);
		sendResponse(exchange, success ? "Comment set successfully" : "Failed to set comment");
	}

	/**
	 * Sets a decompiler comment at the specified address
	 * 
	 * @param addressStr The address as a string where the comment should be set
	 * @param comment    The comment to set
	 * @return true if the comment was set successfully, false otherwise
	 */
	private boolean setDecompilerComment(String addressStr, String comment) {
		return setCommentAtAddress(tool, addressStr, comment, CommentType.PRE, "Set decompiler comment");
	}
}
