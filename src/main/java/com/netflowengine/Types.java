package com.netflowengine;

import java.util.Objects;

public class Types {

    public enum AppType {
        UNKNOWN,
        HTTP,
        HTTPS,
        DNS,
        GOOGLE,
        YOUTUBE,
        FACEBOOK,
        TWITTER,
        WHATSAPP,
        NETFLIX,
        ZOOM,
        TEAMS,
        SLACK,
        DISCORD,
        STEAM,
        SPOTIFY,
        APP_COUNT;

        public static String appTypeToString(AppType type) {
            switch (type) {
                case HTTP: return "HTTP";
                case HTTPS: return "HTTPS";
                case DNS: return "DNS";
                case GOOGLE: return "Google";
                case YOUTUBE: return "YouTube";
                case FACEBOOK: return "Facebook";
                case TWITTER: return "Twitter";
                case WHATSAPP: return "WhatsApp";
                case NETFLIX: return "Netflix";
                case ZOOM: return "Zoom";
                case TEAMS: return "Microsoft Teams";
                case SLACK: return "Slack";
                case DISCORD: return "Discord";
                case STEAM: return "Steam";
                case SPOTIFY: return "Spotify";
                case UNKNOWN: return "Unknown";
                default: return "Unknown";
            }
        }
    }

    public static class FiveTuple {
        public long srcIp;
        public long dstIp;
        public int srcPort;
        public int dstPort;
        public int protocol;

        public static FiveTuple create(long ip1, long ip2, int port1, int port2, int protocol) {
            FiveTuple tuple = new FiveTuple();
            if (ip1 < ip2 || (ip1 == ip2 && port1 < port2)) {
                tuple.srcIp = ip1;
                tuple.dstIp = ip2;
                tuple.srcPort = port1;
                tuple.dstPort = port2;
            } else {
                tuple.srcIp = ip2;
                tuple.dstIp = ip1;
                tuple.srcPort = port2;
                tuple.dstPort = port1;
            }
            tuple.protocol = protocol;
            return tuple;
        }

        @Override
        public boolean equals(Object o) {
            if (this == o) return true;
            if (o == null || getClass() != o.getClass()) return false;
            FiveTuple fiveTuple = (FiveTuple) o;
            return srcIp == fiveTuple.srcIp &&
                   dstIp == fiveTuple.dstIp &&
                   srcPort == fiveTuple.srcPort &&
                   dstPort == fiveTuple.dstPort &&
                   protocol == fiveTuple.protocol;
        }

        @Override
        public int hashCode() {
            return Objects.hash(srcIp, dstIp, srcPort, dstPort, protocol);
        }
    }

    public static class Flow {
        public FiveTuple tuple = new FiveTuple();
        public AppType appType = AppType.UNKNOWN;
        public String sni = "";
        public long packets = 0;
        public long bytes = 0;
        public boolean blocked = false;
    }

    public static class RawPacket {
        public PcapPacketHeader header = new PcapPacketHeader();
        public byte[] data;
    }

    public static class ParsedPacket {
        public String srcMac = "";
        public String dstMac = "";
        public boolean hasIp = false;
        public String srcIp = "";
        public String dstIp = "";
        public boolean hasTcp = false;
        public boolean hasUdp = false;
        public int srcPort = 0;
        public int dstPort = 0;
        public int protocol = 0;
        public int payloadOffset = 0;
        public int payloadLen = 0;
    }

    public static class PcapGlobalHeader {
        public long magicNumber;
        public int versionMajor;
        public int versionMinor;
        public int thiszone;
        public long sigfigs;
        public long snaplen;
        public long network;
    }

    public static class PcapPacketHeader {
        public long tsSec;
        public long tsUsec;
        public long inclLen;
        public long origLen;
    }

    public static AppType sniToAppType(String sni) {
        String s = sni.toLowerCase();
        if (s.contains("youtube")) return AppType.YOUTUBE;
        if (s.contains("facebook")) return AppType.FACEBOOK;
        if (s.contains("google")) return AppType.GOOGLE;
        if (s.contains("twitter")) return AppType.TWITTER;
        if (s.contains("whatsapp")) return AppType.WHATSAPP;
        if (s.contains("netflix")) return AppType.NETFLIX;
        if (s.contains("zoom")) return AppType.ZOOM;
        if (s.contains("teams")) return AppType.TEAMS;
        if (s.contains("slack")) return AppType.SLACK;
        if (s.contains("discord")) return AppType.DISCORD;
        if (s.contains("steam")) return AppType.STEAM;
        if (s.contains("spotify")) return AppType.SPOTIFY;
        return AppType.UNKNOWN;
    }

    public static long parseIP(String ip) {
        if (ip == null || ip.isEmpty()) return 0;
        long result = 0;
        int octet = 0, shift = 0;
        int octetCount = 0;
        for (int i = 0; i < ip.length(); i++) {
            char c = ip.charAt(i);
            if (c == '.') { 
                result |= ((long)octet << shift); 
                shift += 8; 
                octet = 0; 
                octetCount++;
            } else if (c >= '0' && c <= '9') {
                octet = octet * 10 + (c - '0');
                if (octet > 255) return 0;
            } else if (!Character.isWhitespace(c)) {
                return 0; // Invalid character
            }
        }
        if (octetCount != 3) return 0;
        return result | ((long)octet << shift);
    }
}
