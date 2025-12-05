package com.lauriewired.handlers.set;

import com.lauriewired.handlers.Handler;
import com.sun.net.httpserver.HttpExchange;
import ghidra.program.disassemble.Disassembler;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.Memory;
import ghidra.util.Msg;
import ghidra.util.task.TaskMonitor;

import javax.swing.*;
import java.io.IOException;
import java.lang.reflect.InvocationTargetException;
import java.util.Map;
import java.util.concurrent.atomic.AtomicReference;

import static com.lauriewired.util.ParseUtils.parsePostParams;
import static com.lauriewired.util.ParseUtils.sendResponse;
import static ghidra.program.util.GhidraProgramUtilities.getCurrentProgram;

/**
 * Handler for writing bytes to a specific memory address in the current program.
 * Expects POST parameters: "address" (the target address) and "bytes" (hex string separated by spaces).
 */
public final class SetBytes extends Handler {

    /**
     * Constructor for the new SetBytes handler.
     *
     * @param tool the PluginTool instance to use for program access
     */
    public SetBytes(PluginTool tool) {
        super(tool, "/set_bytes");
    }

    /**
     * Handles the HTTP request to write bytes to a specified address.
     *
     * @param exchange the HttpExchange object containing the request
     * @throws IOException if an I/O error occurs
     */
    @Override
    public void handle(HttpExchange exchange) throws IOException {
        Map<String, String> params = parsePostParams(exchange);
        String addressStr = params.get("address");
        String bytesStr = params.get("bytes");

        if (addressStr == null || bytesStr == null) {
            sendResponse(exchange, "Missing 'address' or 'bytes' parameter");
            return;
        }

        String result = writeBytesToAddress(addressStr, bytesStr);
        sendResponse(exchange, result);
    }

    /**
     * Writes the given bytes to the specified memory address in the current program.
     *
     * @param addressStr the string representation of the address
     * @param bytesStr   the string of bytes in hex (e.g., "90 90 90")
     * @return a message indicating the result of the operation
     */
    private String writeBytesToAddress(String addressStr, String bytesStr) {
        Program program = getCurrentProgram(tool);
        if (program == null)
            return "No active program";

        AtomicReference<String> result = new AtomicReference<>();

        try {
            SwingUtilities.invokeAndWait(() -> {
                int txId = program.startTransaction("Write Bytes");
                boolean success = false;
                try {
                    Address address = program.getAddressFactory().getAddress(addressStr);
                    Memory memory = program.getMemory();

                    String[] byteTokens = bytesStr.trim().split("\\s+");
                    byte[] newBytes = new byte[byteTokens.length];
                    for (int i = 0; i < byteTokens.length; i++) {
                        newBytes[i] = (byte) Integer.parseInt(byteTokens[i], 16);
                    }

                    Address endAddress = address.add(newBytes.length - 1);

                    if (!memory.contains(address) || !memory.contains(endAddress)) {
                        result.set("Memory range out of bounds or unmapped");
                        return;
                    }

                    byte[] existingBytes = new byte[newBytes.length];
                    int bytesRead = memory.getBytes(address, existingBytes);
                    if (bytesRead != newBytes.length) {
                        result.set("Mismatch: memory region size differs from replacement size");
                        return;
                    }

                    Listing listing = program.getListing();
                    listing.clearCodeUnits(address, endAddress, false);
                    memory.setBytes(address, newBytes);

                    Disassembler disassembler = Disassembler.getDisassembler(program, TaskMonitor.DUMMY, null);
                    disassembler.disassemble(address, null);

                    success = true;
                    result.set("Bytes written successfully");
                } catch (Exception e) {
                    Msg.error(this, "Write bytes error", e);
                    result.set("Error: " + e.getMessage());
                } finally {
                    program.endTransaction(txId, success);
                }
            });
        } catch (InterruptedException | InvocationTargetException e) {
            Msg.error(this, "Failed to write bytes on Swing thread", e);
            return "Error: failed to execute on Swing thread: " + e.getMessage();
        }

        return result.get();
    }
}
