package com.lauriewired;

import com.lauriewired.handlers.Handler;
import ghidra.framework.plugintool.Plugin;
import ghidra.framework.plugintool.PluginTool;
import ghidra.app.plugin.PluginCategoryNames;
import ghidra.framework.plugintool.PluginInfo;
import ghidra.framework.plugintool.util.PluginStatus;
import ghidra.util.Msg;
import ghidra.framework.options.Options;

import com.sun.net.httpserver.HttpServer;
import org.reflections.Reflections;

import java.io.IOException;
import java.lang.reflect.Constructor;
import java.net.InetSocketAddress;
import java.util.*;

/**
 * GhidraMCP Plugin - Model Context Protocol Server for Ghidra
 * 
 * This plugin creates an HTTP server that exposes Ghidra's analysis
 * capabilities
 * through a RESTful API, enabling AI language models to autonomously perform
 * reverse engineering tasks. The plugin integrates with the CodeBrowser tool
 * and provides comprehensive access to:
 * 
 * <ul>
 * <li>Function decompilation and analysis</li>
 * <li>Symbol and variable management</li>
 * <li>Memory and data structure examination</li>
 * <li>Cross-reference analysis</li>
 * <li>Binary annotation and commenting</li>
 * </ul>
 * 
 * <h3>Server Lifecycle</h3>
 * The HTTP server automatically starts when the plugin is enabled in
 * CodeBrowser
 * with an active program loaded. The server runs on a configurable port
 * (default: 8080)
 * and remains active while the CodeBrowser session continues.
 * 
 * <h3>API Endpoints</h3>
 * The plugin exposes over 20 REST endpoints for comprehensive binary analysis:
 * <ul>
 * <li><code>/methods</code> - List all functions with pagination</li>
 * <li><code>/decompile</code> - Decompile functions by name or address</li>
 * <li><code>/renameFunction</code> - Rename functions and variables</li>
 * <li><code>/xrefs_to</code> - Analyze cross-references</li>
 * <li><code>/strings</code> - Extract and filter string data</li>
 * </ul>
 * 
 * <h3>Thread Safety</h3>
 * All Ghidra API interactions are properly synchronized using
 * SwingUtilities.invokeAndWait()
 * to ensure thread safety with Ghidra's event dispatch thread.
 * 
 * @author LaurieWired
 * @version 2.0
 * @since Ghidra 11.3.2
 * @see ghidra.framework.plugintool.Plugin
 * @see com.sun.net.httpserver.HttpServer
 */
@PluginInfo(status = PluginStatus.RELEASED, packageName = ghidra.app.DeveloperPluginPackage.NAME, category = PluginCategoryNames.ANALYSIS, shortDescription = "HTTP server plugin", description = "Starts an embedded HTTP server to expose program data. Port configurable via Tool Options.")
public class GhidraMCPPlugin extends Plugin {

	/** The embedded HTTP server instance that handles all API requests */
	private HttpServer server;

	/** Configuration category name for tool options */
	private static final String OPTION_CATEGORY_NAME = "GhidraMCP HTTP Server";

	/** Configuration option name for the server address setting */
	private static final String ADDRESS_OPTION_NAME = "Server Address";

	/** Default address for the HTTP server */
	private static final String DEFAULT_ADDRESS = "127.0.0.1";

	/** Configuration option name for the server port setting */
	private static final String PORT_OPTION_NAME = "Server Port";

	/** Configuration option name for the decompile timeout setting */
	private static final String DECOMPILE_TIMEOUT_OPTION_NAME = "Decompile Timeout";

	/** Default port number for the HTTP server (8080) */
	private static final int DEFAULT_PORT = 8080;

	/** Default decompile timeout in seconds */
	private static final int DEFAULT_DECOMPILE_TIMEOUT = 30;

	/** HashMap to store all registered API routes */
	private static final HashMap<String, Handler> routes = new HashMap<>();

	/** The timeout for decompilation requests in seconds */
	private int decompileTimeout;

	/**
	 * Constructs a new GhidraMCP plugin instance and initializes the HTTP server.
	 * 
	 * This constructor:
	 * <ol>
	 * <li>Registers the port configuration option in Ghidra's tool options</li>
	 * <li>Starts the embedded HTTP server on the configured port</li>
	 * <li>Creates all REST API endpoint handlers</li>
	 * </ol>
	 * 
	 * The server will only function properly when:
	 * <ul>
	 * <li>A program is loaded in the current CodeBrowser session</li>
	 * <li>The plugin is enabled in the Developer tools configuration</li>
	 * </ul>
	 * 
	 * @param tool The Ghidra PluginTool instance that hosts this plugin
	 * @throws IllegalStateException if the HTTP server fails to start
	 * @see #startServer()
	 */
	public GhidraMCPPlugin(PluginTool tool) {
		super(tool);
		Msg.info(this, "GhidraMCPPlugin loading...");

		// Register the configuration option
		Options options = tool.getOptions(OPTION_CATEGORY_NAME);
		options.registerOption(ADDRESS_OPTION_NAME, DEFAULT_ADDRESS,
				null, // No help location for now
				"The network address the embedded HTTP server will listen on. " +
						"Requires Ghidra restart or plugin reload to take effect after changing.");
		options.registerOption(PORT_OPTION_NAME, DEFAULT_PORT,
				null, // No help location for now
				"The network port number the embedded HTTP server will listen on. " +
						"Requires Ghidra restart or plugin reload to take effect after changing.");
		options.registerOption(DECOMPILE_TIMEOUT_OPTION_NAME, DEFAULT_DECOMPILE_TIMEOUT,
				null,
				"Decompilation timeout. " +
						"Requires Ghidra restart or plugin reload to take effect after changing.");

		try {
			startServer();
		} catch (IOException e) {
			Msg.error(this, "Failed to start HTTP server", e);
		}
		Msg.info(this, "GhidraMCPPlugin loaded!");
	}

	/**
	 * Initializes and starts the embedded HTTP server with all API endpoints.
	 * 
	 * This method creates an HTTP server instance and registers handlers for all
	 * supported REST API endpoints. The server supports:
	 * 
	 * <h4>Function Analysis Endpoints:</h4>
	 * <ul>
	 * <li><code>GET /methods</code> - List functions with pagination</li>
	 * <li><code>POST /decompile</code> - Decompile function by name</li>
	 * <li><code>GET /decompile_function?address=0x...</code> - Decompile by
	 * address</li>
	 * <li><code>GET /disassemble_function?address=0x...</code> - Get assembly
	 * listing</li>
	 * </ul>
	 * 
	 * <h4>Symbol Management Endpoints:</h4>
	 * <ul>
	 * <li><code>POST /renameFunction</code> - Rename functions</li>
	 * <li><code>POST /renameVariable</code> - Rename local variables</li>
	 * <li><code>POST /set_function_prototype</code> - Set function signatures</li>
	 * </ul>
	 * 
	 * <h4>Analysis and Reference Endpoints:</h4>
	 * <ul>
	 * <li><code>GET /xrefs_to?address=0x...</code> - Find references to
	 * address</li>
	 * <li><code>GET /xrefs_from?address=0x...</code> - Find references from
	 * address</li>
	 * <li><code>GET /strings</code> - List string data with filtering</li>
	 * </ul>
	 * 
	 * <h4>Commenting and Annotation:</h4>
	 * <ul>
	 * <li><code>POST /set_decompiler_comment</code> - Add pseudocode comments</li>
	 * <li><code>POST /set_disassembly_comment</code> - Add assembly comments</li>
	 * </ul>
	 * 
	 * The server runs on a separate thread to avoid blocking Ghidra's UI thread.
	 * All endpoints return plain text responses with UTF-8 encoding.
	 * 
	 * @throws IOException if the server cannot bind to the configured port
	 * @see #sendResponse(HttpExchange, String)
	 * @see #parseQueryParams(HttpExchange)
	 */
	private void startServer() throws IOException {
		// Read the configured port
		Options options = tool.getOptions(OPTION_CATEGORY_NAME);
		String listenAddress = options.getString(ADDRESS_OPTION_NAME, DEFAULT_ADDRESS);
		int port = options.getInt(PORT_OPTION_NAME, DEFAULT_PORT);

		// Stop existing server if running (e.g., if plugin is reloaded)
		if (server != null) {
			Msg.info(this, "Stopping existing HTTP server before starting new one.");
			server.stop(0);
			server = null;
		}

		InetSocketAddress inetAddress = new InetSocketAddress(listenAddress, port);

		if (inetAddress.isUnresolved()) {
			Msg.error(this, "Failed to resolve listen address.");
			return;
		}

		server = HttpServer.create(inetAddress, 0);

		Reflections reflections = new Reflections("com.lauriewired.handlers");
		Set<Class<? extends Handler>> subclasses = reflections.getSubTypesOf(Handler.class);
		for (Class<?> clazz : subclasses) {
			System.out.println(clazz.getName());
			try {
				Constructor<?> constructor = clazz.getConstructor(PluginTool.class);
				Handler handler = (Handler) constructor.newInstance(tool);
				if (routes.containsKey(handler.getPath())) {
					Msg.error(this, "Handler class " + clazz.getName() + " already registered, skipped.");
					continue;
				}
				routes.put(handler.getPath(), handler);
				server.createContext(handler.getPath(), exchange -> {
					try {
						handler.handle(exchange);
					} catch (Exception e) {
						throw new RuntimeException(e);
					}
				});
			} catch (NoSuchMethodException e) {
				Msg.error(this, "Handler class " + clazz.getName() +
						" doesn't have constructor xxx(PluginTool tool), skipped.");
			} catch (Exception e) {
				e.printStackTrace();
			}
		}

		server.setExecutor(null);
		new Thread(() -> {
			try {
				server.start();
				Msg.info(this, "GhidraMCP HTTP server started on port " + port);
			} catch (Exception e) {
				Msg.error(this, "Failed to start HTTP server on port " + port + ". Port might be in use.", e);
				server = null; // Ensure server isn't considered running
			}
		}, "GhidraMCP-HTTP-Server").start();
	}

	/**
	 * Cleanly shuts down the HTTP server and releases plugin resources.
	 * 
	 * This method is automatically called by Ghidra when:
	 * <ul>
	 * <li>The plugin is disabled in the CodeBrowser configuration</li>
	 * <li>The CodeBrowser tool is closed</li>
	 * <li>Ghidra is shutting down</li>
	 * <li>The plugin is being reloaded</li>
	 * </ul>
	 * 
	 * <b>Shutdown Process:</b>
	 * <ol>
	 * <li>Stops the HTTP server with a 1-second grace period for active
	 * connections</li>
	 * <li>Nullifies the server reference to prevent further use</li>
	 * <li>Calls the parent dispose method to clean up plugin infrastructure</li>
	 * </ol>
	 * 
	 * <b>Thread Safety:</b> This method can be called from any thread and safely
	 * handles concurrent access to the server instance.
	 * 
	 * @see HttpServer#stop(int)
	 * @see Plugin#dispose()
	 */
	@Override
	public void dispose() {
		if (server != null) {
			Msg.info(this, "Stopping GhidraMCP HTTP server...");
			server.stop(1); // Stop with a small delay (e.g., 1 second) for connections to finish
			server = null; // Nullify the reference
			Msg.info(this, "GhidraMCP HTTP server stopped.");
		}
		super.dispose();
	}
}
