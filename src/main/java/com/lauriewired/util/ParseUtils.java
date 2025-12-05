package com.lauriewired.util;

import com.sun.net.httpserver.HttpExchange;
import ghidra.program.model.address.Address;
import ghidra.util.Msg;

import java.io.IOException;
import java.io.OutputStream;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * Utility methods for parsing HTTP requests and responses.
 * 
 * This class provides methods to parse query parameters, post body parameters,
 * paginate lists, parse integers with defaults, escape non-ASCII characters,
 * and send HTTP responses.
 */
public final class ParseUtils {
	/**
	 * Parse query parameters from the request URI.
	 * 
	 * @param exchange The HttpExchange object containing the request.
	 * @return A map of query parameters where the key is the parameter name
	 *         and the value is the parameter value.
	 *         For example, for a query string "offset=10&limit=100",
	 *         the map will contain {"offset": "10", "limit": "100"}
	 */
	public static Map<String, String> parseQueryParams(HttpExchange exchange) {
		Map<String, String> result = new HashMap<>();
		String query = exchange.getRequestURI().getQuery(); // e.g. offset=10&limit=100
		if (query != null) {
			String[] pairs = query.split("&");
			for (String p : pairs) {
				String[] kv = p.split("=");
				if (kv.length == 2) {
					// URL decode parameter values
					try {
						String key = URLDecoder.decode(kv[0], StandardCharsets.UTF_8);
						String value = URLDecoder.decode(kv[1], StandardCharsets.UTF_8);
						result.put(key, value);
					} catch (Exception e) {
						Msg.error(ParseUtils.class, "Error decoding URL parameter", e);
					}
				}
			}
		}
		return result;
	}

	/**
	 * Parse POST parameters from the request body.
	 * 
	 * @param exchange The HttpExchange object containing the request.
	 * @return A map of POST parameters where the key is the parameter name
	 *         and the value is the parameter value.
	 *         For example, for a body "offset=10&limit=100",
	 *         the map will contain {"offset": "10", "limit": "100"}
	 */
	public static Map<String, String> parsePostParams(HttpExchange exchange) throws IOException {
		byte[] body = exchange.getRequestBody().readAllBytes();
		String bodyStr = new String(body, StandardCharsets.UTF_8);
		Map<String, String> params = new HashMap<>();
		for (String pair : bodyStr.split("&")) {
			String[] kv = pair.split("=");
			if (kv.length == 2) {
				// URL decode parameter values
				try {
					String key = URLDecoder.decode(kv[0], StandardCharsets.UTF_8);
					String value = URLDecoder.decode(kv[1], StandardCharsets.UTF_8);
					params.put(key, value);
				} catch (Exception e) {
					Msg.error(ParseUtils.class, "Error decoding URL parameter", e);
				}
			}
		}
		return params;
	}

	/**
	 * Paginate a list of items based on offset and limit.
	 * 
	 * @param items  The list of items to paginate.
	 * @param offset The starting index for pagination.
	 * @param limit  The maximum number of items to return.
	 * @return A string containing the paginated items, each on a new line.
	 *         If the offset is beyond the list size, returns an empty string.
	 */
	public static String paginateList(List<String> items, int offset, int limit) {
		int start = Math.max(0, offset);
		int end = Math.min(items.size(), offset + limit);

		if (start >= items.size()) {
			return ""; // no items in range
		}
		List<String> sub = items.subList(start, end);
		return String.join("\n", sub);
	}

	/**
	 * Parse an integer from a string, returning a default value if parsing fails.
	 * 
	 * @param val          The string to parse.
	 * @param defaultValue The default value to return if parsing fails.
	 * @return The parsed integer or the default value if parsing fails.
	 */
	public static int parseIntOrDefault(String val, int defaultValue) {
		if (val == null)
			return defaultValue;
		try {
			return Integer.parseInt(val);
		} catch (NumberFormatException e) {
			return defaultValue;
		}
	}

	/**
	 * Escape non-ASCII characters in a string.
	 * 
	 * @param input The input string to escape.
	 * @return A string where non-ASCII characters are replaced with their
	 *         hexadecimal representation, e.g. "\xFF" for 255.
	 */
	public static String escapeNonAscii(String input) {
		if (input == null)
			return "";
		StringBuilder sb = new StringBuilder();
		for (char c : input.toCharArray()) {
			if (c >= 32 && c < 127) {
				sb.append(c);
			} else {
				sb.append("\\x");
				sb.append(Integer.toHexString(c & 0xFF));
			}
		}
		return sb.toString();
	}

	/**
	 * Escape special characters in a string for safe display
	 * 
	 * @param input the string to escape
	 * @return the escaped string
	 */
	public static String escapeString(String input) {
		if (input == null)
			return "";

		StringBuilder sb = new StringBuilder();
		for (int i = 0; i < input.length(); i++) {
			char c = input.charAt(i);
			if (c >= 32 && c < 127) {
				sb.append(c);
			} else if (c == '\n') {
				sb.append("\\n");
			} else if (c == '\r') {
				sb.append("\\r");
			} else if (c == '\t') {
				sb.append("\\t");
			} else {
				sb.append(String.format("\\x%02x", (int) c & 0xFF));
			}
		}
		return sb.toString();
	}

	/**
	 * Send a plain text response to the HTTP exchange.
	 * 
	 * @param exchange The HttpExchange object to send the response to.
	 * @param response The response string to send.
	 * @throws IOException If an I/O error occurs while sending the response.
	 */
	public static void sendResponse(HttpExchange exchange, String response) throws IOException {
		byte[] bytes = response.getBytes(StandardCharsets.UTF_8);
		exchange.getResponseHeaders().set("Content-Type", "text/plain; charset=utf-8");
		exchange.sendResponseHeaders(200, bytes.length);
		try (OutputStream os = exchange.getResponseBody()) {
			os.write(bytes);
		}
	}

	/**
	 * Generate a hexdump of a byte array starting from a given base address.
	 * 
	 * @param base The base address to start the hexdump from.
	 * @param buf  The byte array to generate the hexdump for.
	 * @param len  The number of bytes to include in the hexdump.
	 * @return A string representation of the hexdump.
	 */
	public static String hexdump(Address base, byte[] buf, int len) {
		StringBuilder sb = new StringBuilder();
		for (int i = 0; i < len; i += 16) {
			sb.append(String.format("%s  ", base.add(i)));
			for (int j = 0; j < 16 && (i + j) < len; j++) {
				sb.append(String.format("%02X ", buf[i + j]));
			}
			sb.append('\n');
		}
		return sb.toString();
	}

	/**
	 * Decode a hexadecimal string into a byte array.
	 * 
	 * @param hex The hexadecimal string to decode.
	 * @return A byte array representing the decoded hexadecimal string.
	 * @throws IllegalArgumentException If the input string is not a valid hex
	 *                                  string.
	 */
	public static byte[] decodeHex(String hex) {
		hex = hex.replaceAll("\\s+", "");
		if (hex.length() % 2 != 0)
			throw new IllegalArgumentException();
		byte[] out = new byte[hex.length() / 2];
		for (int i = 0; i < out.length; i++) {
			out[i] = (byte) Integer.parseInt(hex.substring(i * 2, i * 2 + 2), 16);
		}
		return out;
	}
}
