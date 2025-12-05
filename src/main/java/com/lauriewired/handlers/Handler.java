package com.lauriewired.handlers;

import com.sun.net.httpserver.HttpExchange;
import ghidra.framework.plugintool.PluginTool;

/**
 * Abstract class representing a handler for HTTP requests in a Ghidra
 * PluginTool.
 * Subclasses must implement the handle method to define how requests are
 * processed.
 */
public abstract class Handler {
	/** The PluginTool instance this handler is associated with. */
	protected final PluginTool tool;

	/** The path this handler will respond to. */
	protected final String path;

	/**
	 * Constructs a new Handler with the specified PluginTool and path.
	 *
	 * @param tool the PluginTool instance this handler is associated with
	 * @param path the path this handler will respond to
	 */
	protected Handler(PluginTool tool, String path) {
		this.tool = tool;
		this.path = path;
	}

	/**
	 * Gets the path this handler will respond to.
	 *
	 * @return the path
	 */
	public String getPath() {
		return path;
	}

	/**
	 * Handles an HTTP request.
	 * Subclasses must implement this method to define how requests are
	 * processed.
	 *
	 * @param exchange the HttpExchange object representing the HTTP request
	 * @throws Exception if an error occurs while handling the request
	 */
	public abstract void handle(HttpExchange exchange) throws Exception;
}
