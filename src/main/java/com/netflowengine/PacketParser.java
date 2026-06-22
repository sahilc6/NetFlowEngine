// src/main/java/com/netflowengine/PacketParser.java
package com.netflowengine;

public class PacketParser {
    
    public static boolean parse(Types.RawPacket raw, Types.ParsedPacket parsed) {
        if (raw.data == null || raw.data.length < 14) return false;
        
        // Reset parsed
        parsed.hasIp = false;
        parsed.hasTcp = false;
        parsed.hasUdp = false;
        parsed.srcMac = "";
        parsed.dstMac = "";
        parsed.srcIp = "";
        parsed.dstIp = "";
        parsed.srcPort = 0;
        parsed.dstPort = 0;
        parsed.protocol = 0;
        parsed.payloadOffset = 0;
        parsed.payloadLen = 0;
        
        // Ethernet
        int etherType = ((raw.data[12] & 0xFF) << 8) | (raw.data[13] & 0xFF);
        parsed.srcMac = formatMac(raw.data, 6);
        parsed.dstMac = formatMac(raw.data, 0);
        
        if (etherType == 0x0800) { // IPv4
            if (raw.data.length < 14 + 20) return true; // IP header too small
            parsed.hasIp = true;
            
            int ihl = raw.data[14] & 0x0F;
            if (ihl < 5) return true;
            
            int ipOffset = 14;
            if (raw.data.length < ipOffset + ihl * 4) return true;
            
            parsed.protocol = raw.data[ipOffset + 9] & 0xFF;
            parsed.srcIp = formatIp(raw.data, ipOffset + 12);
            parsed.dstIp = formatIp(raw.data, ipOffset + 16);
            
            int transportOffset = ipOffset + ihl * 4;
            
            if (parsed.protocol == 6) { // TCP
                if (raw.data.length >= transportOffset + 20) {
                    parsed.hasTcp = true;
                    parsed.srcPort = ((raw.data[transportOffset] & 0xFF) << 8) | (raw.data[transportOffset + 1] & 0xFF);
                    parsed.dstPort = ((raw.data[transportOffset + 2] & 0xFF) << 8) | (raw.data[transportOffset + 3] & 0xFF);
                    
                    int tcpOffset = (raw.data[transportOffset + 12] >> 4) & 0x0F;
                    parsed.payloadOffset = transportOffset + tcpOffset * 4;
                    parsed.payloadLen = Math.max(0, raw.data.length - parsed.payloadOffset);
                }
            } else if (parsed.protocol == 17) { // UDP
                if (raw.data.length >= transportOffset + 8) {
                    parsed.hasUdp = true;
                    parsed.srcPort = ((raw.data[transportOffset] & 0xFF) << 8) | (raw.data[transportOffset + 1] & 0xFF);
                    parsed.dstPort = ((raw.data[transportOffset + 2] & 0xFF) << 8) | (raw.data[transportOffset + 3] & 0xFF);
                    
                    parsed.payloadOffset = transportOffset + 8;
                    parsed.payloadLen = Math.max(0, raw.data.length - parsed.payloadOffset);
                }
            }
        }
        
        return true;
    }
    
    private static String formatMac(byte[] data, int offset) {
        return String.format("%02x:%02x:%02x:%02x:%02x:%02x", 
            data[offset] & 0xFF, data[offset+1] & 0xFF, data[offset+2] & 0xFF, 
            data[offset+3] & 0xFF, data[offset+4] & 0xFF, data[offset+5] & 0xFF);
    }
    
    private static String formatIp(byte[] data, int offset) {
        return (data[offset] & 0xFF) + "." + 
               (data[offset+1] & 0xFF) + "." + 
               (data[offset+2] & 0xFF) + "." + 
               (data[offset+3] & 0xFF);
    }
}
