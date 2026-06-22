package com.netflowengine;

import java.nio.charset.StandardCharsets;

public class SniExtractor {

    public static String extractSni(byte[] payload, int offset, int length) {
        if (length < 43) return null; // Minimum Client Hello size
        
        // Check TLS record header: Content Type = Handshake (0x16)
        if (payload[offset] != 0x16) return null;
        
        // Handshake Type = Client Hello (0x01)
        if (payload[offset + 5] != 0x01) return null;

        int pos = offset + 43; // skip to session id
        if (pos >= offset + length) return null;

        // Extract session ID length (1 byte, masked to treat signed byte as unsigned 0-255)
        int sessionLen = payload[pos] & 0xFF;
        pos += 1 + sessionLen;

        if (pos + 2 > offset + length) return null;
        // Decode 16-bit Cipher Suites Length (Big-Endian format)
        int cipherLen = ((payload[pos] & 0xFF) << 8) | (payload[pos + 1] & 0xFF);
        pos += 2 + cipherLen;

        if (pos + 1 > offset + length) return null;
        // Extract compression methods length (1 byte, masked to treat as unsigned)
        int compLen = payload[pos] & 0xFF;
        pos += 1 + compLen;

        if (pos + 2 > offset + length) return null;
        // Decode 16-bit Extensions Length (Big-Endian format)
        int extLen = ((payload[pos] & 0xFF) << 8) | (payload[pos + 1] & 0xFF);
        pos += 2;

        int extEnd = pos + extLen;
        if (extEnd > offset + length) extEnd = offset + length;

        while (pos + 4 <= extEnd) {
            // Decode 16-bit extension type and extension data length (Big-Endian format)
            int extType = ((payload[pos] & 0xFF) << 8) | (payload[pos + 1] & 0xFF);
            int extDataLen = ((payload[pos + 2] & 0xFF) << 8) | (payload[pos + 3] & 0xFF);
            pos += 4;

            if (extType == 0x0000) { // SNI extension
                if (pos + 5 <= extEnd) {
                    // pos+0 to pos+1: list length
                    // pos+2: type (0x00 for hostname)
                    // pos+3 to pos+4: sni string length
                    
                    // Extract SNI name type (0x00 = Hostname)
                    int sniType = payload[pos + 2] & 0xFF;
                    if (sniType == 0x00) {
                        // Decode 16-bit SNI name length (Big-Endian format)
                        int sniLen = ((payload[pos + 3] & 0xFF) << 8) | (payload[pos + 4] & 0xFF);
                        if (pos + 5 + sniLen <= extEnd) {
                            return new String(payload, pos + 5, sniLen, StandardCharsets.UTF_8);
                        }
                    }
                }
            }
            pos += extDataLen;
        }
        return null;
    }

    public static String extractHttpHost(byte[] payload, int offset, int length) {
        if (length < 10) return null;
        String data = new String(payload, offset, length, StandardCharsets.UTF_8);
        int endOfHeaders = data.indexOf("\r\n\r\n");
        if (endOfHeaders != -1) {
            data = data.substring(0, endOfHeaders);
        }
        
        String[] lines = data.split("\r\n");
        if (lines.length > 0) {
            String firstLine = lines[0];
            if (firstLine.startsWith("GET ") || firstLine.startsWith("POST ") || 
                firstLine.startsWith("PUT ") || firstLine.startsWith("DELETE ") || 
                firstLine.startsWith("HEAD ")) {
                
                for (String line : lines) {
                    if (line.toLowerCase().startsWith("host: ")) {
                        return line.substring(6).trim();
                    }
                }
            }
        }
        return null;
    }
}
