# /// script
# requires-python = ">=3.10"
# dependencies = [
#     "requests>=2,<3",
#     "mcp>=1.2.0,<2",
# ]
# ///

import sys
import json
import requests
import argparse
import logging
from urllib.parse import urljoin

from mcp.server.fastmcp import FastMCP

DEFAULT_GHIDRA_SERVER = "http://127.0.0.1:8080/"
DEFAULT_REQUEST_TIMEOUT = 30

logger = logging.getLogger(__name__)

mcp = FastMCP("ghidra-mcp")

# Initialize ghidra_server_url with default value
ghidra_server_url = DEFAULT_GHIDRA_SERVER
# Initialize ghidra_request_timeout with default value
ghidra_request_timeout = DEFAULT_REQUEST_TIMEOUT


def safe_get(endpoint: str, params: dict = None) -> list:
    """
    Perform a GET request with optional query parameters.
    """
    if params is None:
        params = {}

    url = urljoin(ghidra_server_url, endpoint)

    try:
        response = requests.get(url, params=params, timeout=ghidra_request_timeout)
        response.encoding = "utf-8"
        if response.ok:
            return response.text.splitlines()
        else:
            return [f"Error {response.status_code}: {response.text.strip()}"]
    except Exception as e:
        return [f"Request failed: {str(e)}"]


def safe_post(endpoint: str, data: dict | str) -> str:
    try:
        url = urljoin(ghidra_server_url, endpoint)
        if isinstance(data, dict):
            response = requests.post(url, data=data, timeout=ghidra_request_timeout)
        else:
            response = requests.post(
                url, data=data.encode("utf-8"), timeout=ghidra_request_timeout
            )
        response.encoding = "utf-8"
        if response.ok:
            return response.text.strip()
        else:
            return f"Error {response.status_code}: {response.text.strip()}"
    except Exception as e:
        return f"Request failed: {str(e)}"


@mcp.tool()
def list_methods(offset: int = 0, limit: int = 100) -> list:
    """
    List all function names in the program with pagination.
    """
    return safe_get("methods", {"offset": offset, "limit": limit})


@mcp.tool()
def list_classes(offset: int = 0, limit: int = 100) -> list:
    """
    List all namespace/class names in the program with pagination.
    """
    return safe_get("classes", {"offset": offset, "limit": limit})


@mcp.tool()
def decompile_function(name: str) -> str:
    """
    Decompile a specific function by name and return the decompiled C code.
    """
    return safe_post("decompile", name)


@mcp.tool()
def rename_function(old_name: str, new_name: str) -> str:
    """
    Rename a function by its current name to a new user-defined name.
    """
    return safe_post("renameFunction", {"oldName": old_name, "newName": new_name})


@mcp.tool()
def rename_data(address: str, new_name: str) -> str:
    """
    Rename a data label at the specified address.
    """
    return safe_post("renameData", {"address": address, "newName": new_name})


@mcp.tool()
def list_segments(offset: int = 0, limit: int = 100) -> list:
    """
    List all memory segments in the program with pagination.
    """
    return safe_get("segments", {"offset": offset, "limit": limit})


@mcp.tool()
def list_imports(offset: int = 0, limit: int = 100) -> list:
    """
    List imported symbols in the program with pagination.
    """
    return safe_get("imports", {"offset": offset, "limit": limit})


@mcp.tool()
def list_exports(offset: int = 0, limit: int = 100) -> list:
    """
    List exported functions/symbols with pagination.
    """
    return safe_get("exports", {"offset": offset, "limit": limit})


@mcp.tool()
def list_namespaces(offset: int = 0, limit: int = 100) -> list:
    """
    List all non-global namespaces in the program with pagination.
    """
    return safe_get("namespaces", {"offset": offset, "limit": limit})


@mcp.tool()
def list_data_items(offset: int = 0, limit: int = 100) -> list:
    """
    List defined data labels and their values with pagination.
    """
    return safe_get("data", {"offset": offset, "limit": limit})


@mcp.tool()
def search_functions_by_name(query: str, offset: int = 0, limit: int = 100) -> list:
    """
    Search for functions whose name contains the given substring.
    """
    if not query:
        return ["Error: query string is required"]
    return safe_get(
        "searchFunctions", {"query": query, "offset": offset, "limit": limit}
    )


@mcp.tool()
def rename_variable(function_name: str, old_name: str, new_name: str) -> str:
    """
    Rename a local variable within a function.
    """
    return safe_post(
        "renameVariable",
        {"functionName": function_name, "oldName": old_name, "newName": new_name},
    )


@mcp.tool()
def get_function_by_address(address: str) -> str:
    """
    Get a function by its address.
    """
    return "\n".join(safe_get("get_function_by_address", {"address": address}))


@mcp.tool()
def get_current_address() -> str:
    """
    Get the address currently selected by the user.
    """
    return "\n".join(safe_get("get_current_address"))


@mcp.tool()
def get_current_function() -> str:
    """
    Get the function currently selected by the user.
    """
    return "\n".join(safe_get("get_current_function"))


@mcp.tool()
def list_functions() -> list:
    """
    List all functions in the database.
    """
    return safe_get("list_functions")


@mcp.tool()
def decompile_function_by_address(address: str) -> str:
    """
    Decompile a function at the given address.
    """
    return "\n".join(safe_get("decompile_function", {"address": address}))


@mcp.tool()
def disassemble_function(address: str) -> list:
    """
    Get assembly code (address: instruction; comment) for a function.
    """
    return safe_get("disassemble_function", {"address": address})


@mcp.tool()
def set_decompiler_comment(address: str, comment: str) -> str:
    """
    Set a comment for a given address in the function pseudocode.
    """
    return safe_post("set_decompiler_comment", {"address": address, "comment": comment})


@mcp.tool()
def set_disassembly_comment(address: str, comment: str) -> str:
    """
    Set a comment for a given address in the function disassembly.
    """
    return safe_post(
        "set_disassembly_comment", {"address": address, "comment": comment}
    )


@mcp.tool()
def rename_function_by_address(function_address: str, new_name: str) -> str:
    """
    Rename a function by its address.
    """
    return safe_post(
        "rename_function_by_address",
        {"function_address": function_address, "new_name": new_name},
    )


@mcp.tool()
def set_function_prototype(function_address: str, prototype: str) -> str:
    """
    Set a function's prototype.
    """
    return safe_post(
        "set_function_prototype",
        {"function_address": function_address, "prototype": prototype},
    )


@mcp.tool()
def set_local_variable_type(
    function_address: str, variable_name: str, new_type: str
) -> str:
    """
    Set a local variable's type.
    """
    return safe_post(
        "set_local_variable_type",
        {
            "function_address": function_address,
            "variable_name": variable_name,
            "new_type": new_type,
        },
    )


@mcp.tool()
def get_xrefs_to(address: str, offset: int = 0, limit: int = 100) -> list:
    """
    Get all references to the specified address (xref to).

    Args:
        address: Target address in hex format (e.g. "0x1400010a0")
        offset: Pagination offset (default: 0)
        limit: Maximum number of references to return (default: 100)

    Returns:
        List of references to the specified address
    """
    return safe_get("xrefs_to", {"address": address, "offset": offset, "limit": limit})


@mcp.tool()
def get_xrefs_from(address: str, offset: int = 0, limit: int = 100) -> list:
    """
    Get all references from the specified address (xref from).

    Args:
        address: Source address in hex format (e.g. "0x1400010a0")
        offset: Pagination offset (default: 0)
        limit: Maximum number of references to return (default: 100)

    Returns:
        List of references from the specified address
    """
    return safe_get(
        "xrefs_from", {"address": address, "offset": offset, "limit": limit}
    )


@mcp.tool()
def get_function_xrefs(name: str, offset: int = 0, limit: int = 100) -> list:
    """
    Get all references to the specified function by name.

    Args:
        name: Function name to search for
        offset: Pagination offset (default: 0)
        limit: Maximum number of references to return (default: 100)

    Returns:
        List of references to the specified function
    """
    return safe_get("function_xrefs", {"name": name, "offset": offset, "limit": limit})


@mcp.tool()
def list_strings(offset: int = 0, limit: int = 2000, filter: str = None) -> list:
    """
    List all defined strings in the program with their addresses.

    Args:
        offset: Pagination offset (default: 0)
        limit: Maximum number of strings to return (default: 2000)
        filter: Optional filter to match within string content

    Returns:
        List of strings with their addresses
    """
    params = {"offset": offset, "limit": limit}
    if filter:
        params["filter"] = filter
    return safe_get("strings", params)


@mcp.tool()
def create_struct(
    name: str, category: str = None, size: int = 0, members: list = None
) -> str:
    """
    Create a new structure.

    Args:
        name: The name of the new structure.
        category: The category path for the structure (e.g., /my_structs). Defaults to root.
        size: The initial size of the structure.
        members: A list of member dictionaries to add to the new struct.
                 Each dict should have 'name', 'type', and optionally 'offset' and 'comment'.
                 The 'type' should be a builtin C datatype or a structure name defined in Ghidra data type manager.
                 Pointers are specified with asterisk, e.g. void*, int* or PCSTR, PVOID for Windows types
                 Example: [{"name": "field1", "type": "int", "offset": 0, "comment": "my field"}]

    Returns:
        A status message indicating success or failure.
    """
    data = {"name": name, "size": str(size)}
    if category:
        data["category"] = category
    if members:
        data["members"] = json.dumps(members)
    return safe_post("create_struct", data)


@mcp.tool()
def add_struct_members(struct_name: str, members: list, category: str = None) -> str:
    """
    Add a member to an existing structure.

    Args:
        struct_name: The name of the structure to modify.
        members: A list of member dictionaries to add to the new struct.
                 Each dict should have 'name', 'type', and optionally 'offset' and 'comment'.
                 The 'type' should be a builtin C datatype or a structure name defined in Ghidra data type manager.
                 Pointers are specified with asterisk, e.g. void*, int* or PCSTR, PVOID for Windows types
                 Example: [{"name": "field1", "type": "int", "offset": 0, "comment": "my field"}]
        category: The category path for the structure. Defaults to root.

    Returns:
        A status message indicating success or failure.
    """

    data = {"struct_name": struct_name, "members": json.dumps(members)}
    if category:
        data["category"] = category
    return safe_post("add_struct_members", data)


@mcp.tool()
def clear_struct(struct_name: str, category: str = None) -> str:
    """
    Remove all members from a structure.

    Args:
        struct_name: The name of the structure to clear.
        category: The category path for the structure. Defaults to root.

    Returns:
        A status message indicating success or failure.
    """
    data = {"struct_name": struct_name}
    if category:
        data["category"] = category
    return safe_post("clear_struct", data)


@mcp.tool()
def get_struct(name: str, category: str = None) -> dict:
    """
    Get a struct's definition.

    Args:
        name: The name of the structure.
        category: The category path for the structure. Defaults to root.

    Returns:
        A dictionary representing the struct, or an error message.
    """
    params = {"name": name}
    if category:
        params["category"] = category

    response_lines = safe_get("get_struct", params)
    response_str = "\n".join(response_lines)

    try:
        # Attempt to parse the JSON response
        return json.loads(response_str)
    except json.JSONDecodeError:
        # If it's not JSON, it's likely an error message
        return {"error": response_str}


@mcp.tool()
def get_data_by_label(label: str) -> str:
    """
    Get information about a data label.

    Args:
        label: Exact symbol / label name to look up in the program.

    Returns:
        A newline-separated string.
        Each line has:  "<label> -> <address> : <value-representation>"
        If the label is not found, an explanatory message is returned.
    """
    return "\n".join(safe_get("get_data_by_label", {"label": label}))


@mcp.tool()
def get_bytes(address: str, size: int = 1) -> str:
    """
    Read raw bytes from memory and dump them in hex.

    Args:
        address: Start address in hex notation (e.g. "0x1401003A0").
        size:    Number of bytes to read (default: 1).

    Returns:
        A hexdump-style multiline string.
        Format: "<address>  <16-byte hex sequence…>".
        On error (invalid address / size ≤ 0) an error message is returned.
    """
    return "\n".join(safe_get("get_bytes", {"address": address, "size": size}))


@mcp.tool()
def search_bytes(bytes_hex: str, offset: int = 0, limit: int = 100) -> list:
    """
    Search the whole program for a specific byte sequence.

    Args:
        bytes_hex: Byte sequence encoded as a hex string
                   (e.g. "DEADBEEF" or "DE AD BE EF").
        offset:    Pagination offset for results (default: 0).
        limit:     Maximum number of hit addresses to return (default: 100).

    Returns:
        A list of addresses (as hex strings) where the sequence was found,
        subject to pagination.  If no hits, an explanatory message list
        such as ["No matches found"] is returned.
    """
    return safe_get(
        "search_bytes",
        {"bytes": bytes_hex, "offset": offset, "limit": limit},
    )


@mcp.tool()
def create_enum(
    name: str, category: str = None, size: int = 4, values: list = None
) -> str:
    """
    Create a new enum.

    Args:
        name: The name of the new enum.
        category: The category path for the enum (e.g., /my_enums). Defaults to root.
        size: The size of the enum in bytes (default: 4).
        values: A list of value dictionaries to add to the new enum.
                Each dict should have 'name', 'value', and optionally 'comment'.
                Example: [{"name": "VALUE1", "value": 0, "comment": "First value"}]

    Returns:
        A status message indicating success or failure.
    """
    data = {"name": name, "size": str(size)}
    if category:
        data["category"] = category
    if values:
        data["values"] = json.dumps(values)
    return safe_post("create_enum", data)


@mcp.tool()
def add_enum_values(enum_name: str, values: list, category: str = None) -> str:
    """
    Add values to an existing enum.

    Args:
        enum_name: The name of the enum to modify.
        values: A list of value dictionaries to add to the enum.
                Each dict should have 'name', 'value', and optionally 'comment'.
                Example: [{"name": "VALUE1", "value": 0, "comment": "First value"}]
        category: The category path for the enum. Defaults to root.

    Returns:
        A status message indicating success or failure.
    """
    data = {"enum_name": enum_name, "values": json.dumps(values)}
    if category:
        data["category"] = category
    return safe_post("add_enum_values", data)


@mcp.tool()
def get_enum(name: str, category: str = None) -> dict:
    """
    Get an enum's definition.

    Args:
        name: The name of the enum.
        category: The category path for the enum. Defaults to root.

    Returns:
        A dictionary representing the enum, or an error message.
    """
    params = {"name": name}
    if category:
        params["category"] = category

    response_lines = safe_get("get_enum", params)
    response_str = "\n".join(response_lines)

    try:
        # Attempt to parse the JSON response
        return json.loads(response_str)
    except json.JSONDecodeError:
        # If it's not JSON, it's likely an error message
        return {"error": response_str}


@mcp.tool()
def set_global_data_type(
    address: str, data_type: str, length: int = -1, clear_mode: str = "CHECK_FOR_SPACE"
) -> str:
    """
    Set the data type of a global variable or data at a specific memory address.

    Args:
        address: The memory address in hex format (e.g., "0x401000")
        data_type: The name of the data type to apply (e.g., "int", "char*", "MyStruct")
        length: Optional length for dynamic data types (default: -1, let type determine)
        clear_mode: How to handle conflicting data. Options:
                   - "CHECK_FOR_SPACE": Ensure data fits before clearing (default)
                   - "CLEAR_SINGLE_DATA": Always clear single code unit at address
                   - "CLEAR_ALL_UNDEFINED_CONFLICT_DATA": Clear conflicting undefined data
                   - "CLEAR_ALL_DEFAULT_CONFLICT_DATA": Clear conflicting default data
                   - "CLEAR_ALL_CONFLICT_DATA": Clear all conflicting data

    Returns:
        A status message indicating success or failure.
    """
    data = {"address": address, "data_type": data_type, "clear_mode": clear_mode}
    if length > 0:
        data["length"] = str(length)

    return safe_post("set_global_data_type", data)


@mcp.tool()
def add_class_members(
    class_name: str, members: list, parent_namespace: str = None
) -> str:
    """
    Add members to an existing C++ class.

    Args:
        class_name: The name of the class to modify.
        members: A list of member dictionaries to add to the class.
                Each dict should have 'name', 'type', and optionally 'offset' and 'comment'.
                Example: [{"name": "health", "type": "float", "comment": "Player health"}]
        parent_namespace: The parent namespace where the class is located (optional).

    Returns:
        A status message indicating success or failure.
    """
    params = {"class_name": class_name, "members": json.dumps(members)}
    if parent_namespace:
        params["parent_namespace"] = parent_namespace

    return safe_post("add_class_members", params)


@mcp.tool()
def remove_class_members(
    class_name: str, members: list, parent_namespace: str = None
) -> str:
    """
    Remove members from an existing C++ class.

    Args:
        class_name: The name of the class to modify.
        members: A list of member names to remove from the class.
                Example: ["old_member", "unused_field"]
        parent_namespace: The parent namespace where the class is located (optional).

    Returns:
        A status message indicating success or failure.
    """
    params = {"class_name": class_name, "members": json.dumps(members)}
    if parent_namespace:
        params["parent_namespace"] = parent_namespace

    return safe_post("remove_class_members", params)


@mcp.tool()
def remove_enum_values(enum_name: str, values: list, category: str = None) -> str:
    """
    Remove values from an existing enum.

    Args:
        enum_name: The name of the enum to modify.
        values: A list of value names to remove from the enum.
                Example: ["OLD_VALUE", "DEPRECATED_OPTION"]
        category: The category path for the enum (optional, defaults to root).

    Returns:
        A status message indicating success or failure.
    """
    params = {"enum_name": enum_name, "values": json.dumps(values)}
    if category:
        params["category"] = category

    return safe_post("remove_enum_values", params)


@mcp.tool()
def remove_struct_members(struct_name: str, members: list, category: str = None) -> str:
    """
    Remove members from an existing struct.

    Args:
        struct_name: The name of the struct to modify.
        members: A list of member names to remove from the struct.
                Example: ["old_field", "unused_member"]
        category: The category path for the struct (optional, defaults to root).

    Returns:
        A status message indicating success or failure.
    """
    params = {"struct_name": struct_name, "members": json.dumps(members)}
    if category:
        params["category"] = category

    return safe_post("remove_struct_members", params)


@mcp.tool()
def set_bytes(address: str, bytes_hex: str) -> str:
    """
    Writes a sequence of bytes to the specified address in the program's memory.

    Args:
        address: Destination address (e.g., "0x140001000")
        bytes_hex: Sequence of space-separated bytes in hexadecimal format (e.g., "90 90 90 90")

    Returns:
        Result of the operation (e.g., "Bytes written successfully" or a detailed error)
    """
    return safe_post("set_bytes", {"address": address, "bytes": bytes_hex})


@mcp.tool()
def add_bookmark(address: str, category: str, comment: str, type: str = "Note") -> str:
    """
    Creates a bookmark at the specified address.

    Args:
        address: The address to create the bookmark at.
        category: The category of the bookmark.
        comment: The comment for the bookmark.
        type: The type of the bookmark. Defaults to "Note".
              Available types are: "Note", "Info", "Warning", "Error", "Analysis".

    Returns:
        A string indicating the result of the operation.
    NOTE: if a bookmark of the same type already exists at the address, it will be replaced.
    """
    # Request JSON-formatted response for consistency with other tools
    return safe_post(
        "add_bookmark",
        {
            "address": address,
            "category": category,
            "comment": comment,
            "type": type,
            "format": "json",
        },
    )


@mcp.tool()
def get_callee(address: str) -> list:
    """
    Get the functions called by the function at the specified address.

    Args:
        address: The address within the function.

    Returns:
        A list of called functions.
    """
    lines = safe_get("get_callee", {"address": address})
    # Try to parse JSON array if the bridge returned structured output
    try:
        body = "\n".join(lines).strip()
        if body.startswith("[") and body.endswith("]"):
            parsed = json.loads(body)
            if isinstance(parsed, list):
                return parsed
    except Exception:
        pass
    return lines


@mcp.tool()
def get_call_graph(address: str, depth: int = 20, include_runtime: bool = False) -> str:
    """
    Generate a call graph (call tree) starting from a function.
    Shows the hierarchy of function calls in an indented tree format.
    Each function appears only once in the tree (at its first occurrence).
    External/imported functions are filtered out.

    Args:
        address: Function name or address in various formats (required). Accepts:
                 - Function names: "FUN_001015fc", "main", "MyClass::method"
                 - Hex addresses with prefix: "0x001015fc", "0x401000"
                 - Hex addresses without prefix: "001015fc", "401000"
        depth: Maximum depth to traverse (default: 20).
               Output will show [MAX_DEPTH] if limit is reached and more calls exist.
        include_runtime: Include runtime/compiler functions like _malloc, __acrt_initialize (default: False).
                        When False, filters out functions starting with _ or __ to show only user code.

    Returns:
        A string containing the call graph in indented tree format.
        Format: "function_name (address)" with 2-space indentation per level.
    """
    params = {
        "address": address,
        "depth": depth,
        "include_runtime": str(include_runtime).lower(),
    }
    return "\n".join(safe_get("get_call_graph", params))


def main():
    parser = argparse.ArgumentParser(description="MCP server for Ghidra")
    parser.add_argument(
        "--ghidra-server",
        type=str,
        default=DEFAULT_GHIDRA_SERVER,
        help=f"Ghidra server URL, default: {DEFAULT_GHIDRA_SERVER}",
    )
    parser.add_argument(
        "--mcp-host",
        type=str,
        default="127.0.0.1",
        help="Host to run MCP server on (only used for sse/streamable-http), default: 127.0.0.1",
    )
    parser.add_argument(
        "--mcp-port",
        type=int,
        help="Port to run MCP server on (only used for sse/streamable-http), default: 8081",
    )
    parser.add_argument(
        "--transport",
        type=str,
        default="stdio",
        choices=["stdio", "sse", "streamable-http", "streamable_http"],
        help="Transport protocol for MCP, default: stdio (sse is deprecated; use streamable-http)",
    )
    parser.add_argument(
        "--ghidra-timeout",
        type=int,
        default=DEFAULT_REQUEST_TIMEOUT,
        help=f"MCP requests timeout, default: {DEFAULT_REQUEST_TIMEOUT}",
    )
    args = parser.parse_args()

    # Use the global variable to ensure it's properly updated
    global ghidra_server_url
    if args.ghidra_server:
        ghidra_server_url = args.ghidra_server

    global ghidra_request_timeout
    if args.ghidra_timeout:
        ghidra_request_timeout = args.ghidra_timeout

    transport = args.transport.replace("_", "-")
    if transport in ("sse", "streamable-http"):
        try:
            # Set up logging
            log_level = logging.INFO
            logging.basicConfig(level=log_level)
            logging.getLogger().setLevel(log_level)

            # Configure MCP settings
            mcp.settings.log_level = "INFO"
            if args.mcp_host:
                mcp.settings.host = args.mcp_host
            else:
                mcp.settings.host = "127.0.0.1"

            if args.mcp_port:
                mcp.settings.port = args.mcp_port
            else:
                mcp.settings.port = 8081

            logger.info(f"Connecting to Ghidra server at {ghidra_server_url}")
            if transport == "sse":
                logger.warning(
                    "SSE transport is deprecated in MCP; prefer streamable-http."
                )
                logger.info(
                    f"Starting MCP server on http://{mcp.settings.host}:{mcp.settings.port}{mcp.settings.sse_path}"
                )
            else:
                logger.info(
                    "Starting MCP server on http://%s:%s%s",
                    mcp.settings.host,
                    mcp.settings.port,
                    mcp.settings.streamable_http_path,
                )
            logger.info(f"Using transport: {transport}")

            mcp.run(transport=transport)
        except KeyboardInterrupt:
            logger.info("Server stopped by user")
    else:
        mcp.run()


if __name__ == "__main__":
    main()
