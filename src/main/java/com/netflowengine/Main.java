package com.netflowengine;

import java.io.FileOutputStream;
import java.io.IOException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

public class Main {

    static class BlockingRules {
        Set<Long> blockedIps = new HashSet<>();
        Set<Types.AppType> blockedApps = new HashSet<>();
        List<String> blockedDomains = new ArrayList<>();

        void blockIp(String ip) {
            blockedIps.add(Types.parseIP(ip));
            System.out.println("[Rules] Blocked IP: " + ip);
        }

        void blockApp(String app) {
            for (Types.AppType type : Types.AppType.values()) {
                if (Types.AppType.appTypeToString(type).equalsIgnoreCase(app)) {
                    blockedApps.add(type);
                    System.out.println("[Rules] Blocked app: " + app);
                    return;
                }
            }
            System.err.println("[Rules] Unknown app: " + app);
        }

        void blockDomain(String domain) {
            blockedDomains.add(domain.toLowerCase());
            System.out.println("[Rules] Blocked domain: " + domain);
        }

        boolean isBlocked(long srcIp, Types.AppType app, String sni) {
            if (blockedIps.contains(srcIp))
                return true;
            if (blockedApps.contains(app))
                return true;
            String lowerSni = sni.toLowerCase();
            for (String dom : blockedDomains) {
                if (lowerSni.contains(dom))
                    return true;
            }
            return false;
        }
    }

    public static void printUsage() {
        System.out.println("DPI Engine - Deep Packet Inspection System");
        System.out.println("==========================================");
        System.out.println();
        System.out.println("Usage: java -jar dpi-engine.jar <input.pcap> <output.pcap> [options]");
        System.out.println();
        System.out.println("Options:");
        System.out.println("  --block-ip <ip>        Block traffic from source IP");
        System.out.println("  --block-app <app>      Block application (YouTube, Facebook, etc.)");
        System.out.println("  --block-domain <dom>   Block domain (substring match)");
        System.out.println();
        System.out.println("Example:");
        System.out.println(
                "  java -jar dpi-engine.jar capture.pcap filtered.pcap --block-app YouTube --block-ip 192.168.1.50");
    }

    public static void main(String[] args) {
        if (args.length < 2) {
            printUsage();
            return;
        }

        String inputFile = args[0];
        String outputFile = args[1];
        BlockingRules rules = new BlockingRules();

        for (int i = 2; i < args.length; i++) {
            String arg = args[i];
            if (arg.equals("--block-ip") && i + 1 < args.length) {
                rules.blockIp(args[++i]);
            } else if (arg.equals("--block-app") && i + 1 < args.length) {
                rules.blockApp(args[++i]);
            } else if (arg.equals("--block-domain") && i + 1 < args.length) {
                rules.blockDomain(args[++i]);
            }
        }

        System.out.println("\n╔══════════════════════════════════════════════════════════════╗");
        System.out.println("║                    DPI ENGINE v1.0 (Java)                    ║");
        System.out.println("╚══════════════════════════════════════════════════════════════╝\n");

        try (PcapReader reader = new PcapReader();
                FileOutputStream output = new FileOutputStream(outputFile)) {

            if (!reader.open(inputFile)) {
                System.err.println("Error: Cannot open input file or invalid format");
                return;
            }

            output.write(reader.getGlobalHeaderBytes());

            Map<Types.FiveTuple, Types.Flow> flows = new HashMap<>();

            long totalPackets = 0;
            long forwarded = 0;
            long dropped = 0;
            Map<Types.AppType, Long> appStats = new HashMap<>();

            Types.RawPacket raw = new Types.RawPacket();
            Types.ParsedPacket parsed = new Types.ParsedPacket();

            System.out.println("[DPI] Processing packets... ");

            while (reader.readNextPacket(raw)) {
                totalPackets++;

                if (!PacketParser.parse(raw, parsed))
                    continue;
                if (!parsed.hasIp || (!parsed.hasTcp && !parsed.hasUdp))
                    continue;

                Types.FiveTuple tuple = Types.FiveTuple.create(
                        Types.parseIP(parsed.srcIp),
                        Types.parseIP(parsed.dstIp),
                        parsed.srcPort,
                        parsed.dstPort,
                        parsed.protocol);

                Types.Flow flow = flows.computeIfAbsent(tuple, k -> {
                    Types.Flow f = new Types.Flow();
                    f.tuple = tuple;
                    return f;
                });

                flow.packets++;
                flow.bytes += raw.data.length;

                if ((flow.appType == Types.AppType.UNKNOWN || flow.appType == Types.AppType.HTTPS) &&
                        flow.sni.isEmpty() && parsed.hasTcp && parsed.dstPort == 443) {

                    if (parsed.payloadLen > 5) {
                        String sni = SniExtractor.extractSni(raw.data, parsed.payloadOffset, parsed.payloadLen);
                        if (sni != null) {
                            flow.sni = sni;
                            flow.appType = Types.sniToAppType(sni);
                        }
                    }
                }

                if ((flow.appType == Types.AppType.UNKNOWN || flow.appType == Types.AppType.HTTP) &&
                        flow.sni.isEmpty() && parsed.hasTcp && parsed.dstPort == 80) {

                    if (parsed.payloadLen > 0) {
                        String host = SniExtractor.extractHttpHost(raw.data, parsed.payloadOffset, parsed.payloadLen);
                        if (host != null) {
                            flow.sni = host;
                            flow.appType = Types.sniToAppType(host);
                        }
                    }
                }

                if (flow.appType == Types.AppType.UNKNOWN &&
                        (parsed.dstPort == 53 || parsed.srcPort == 53)) {
                    flow.appType = Types.AppType.DNS;
                }

                if (flow.appType == Types.AppType.UNKNOWN) {
                    if (parsed.dstPort == 443)
                        flow.appType = Types.AppType.HTTPS;
                    else if (parsed.dstPort == 80)
                        flow.appType = Types.AppType.HTTP;
                }

                if (!flow.blocked) {
                    flow.blocked = rules.isBlocked(Types.parseIP(parsed.srcIp), flow.appType, flow.sni);
                    if (flow.blocked) {
                        System.out.print("[BLOCKED] " + parsed.srcIp + " -> " + parsed.dstIp +
                                " (" + Types.AppType.appTypeToString(flow.appType));
                        if (!flow.sni.isEmpty())
                            System.out.print(": " + flow.sni);
                        System.out.println(")");
                    }
                }

                appStats.put(flow.appType, appStats.getOrDefault(flow.appType, 0L) + 1);

                if (flow.blocked) {
                    dropped++;
                } else {
                    forwarded++;
                    byte[] pktHdr = new byte[16];
                    PcapReader.writeInt32(pktHdr, 0, raw.header.tsSec, reader.isLittleEndian());
                    PcapReader.writeInt32(pktHdr, 4, raw.header.tsUsec, reader.isLittleEndian());
                    PcapReader.writeInt32(pktHdr, 8, raw.header.inclLen, reader.isLittleEndian());
                    PcapReader.writeInt32(pktHdr, 12, raw.header.origLen, reader.isLittleEndian());
                    output.write(pktHdr);
                    output.write(raw.data);
                }
            }

            System.out.println("\n╔══════════════════════════════════════════════════════════════╗");
            System.out.println("║                      PROCESSING REPORT                       ║");
            System.out.println("╠══════════════════════════════════════════════════════════════╣");
            System.out.printf("║ Total Packets:      %10d                             ║\n", totalPackets);
            System.out.printf("║ Forwarded:          %10d                             ║\n", forwarded);
            System.out.printf("║ Dropped:            %10d                             ║\n", dropped);
            System.out.printf("║ Active Flows:       %10d                             ║\n", flows.size());
            System.out.println("╠══════════════════════════════════════════════════════════════╣");
            System.out.println("║                    APPLICATION BREAKDOWN                     ║");
            System.out.println("╠══════════════════════════════════════════════════════════════╣");

            List<Map.Entry<Types.AppType, Long>> sortedApps = new ArrayList<>(appStats.entrySet());
            sortedApps.sort((a, b) -> b.getValue().compareTo(a.getValue()));

            for (Map.Entry<Types.AppType, Long> entry : sortedApps) {
                double pct = 100.0 * entry.getValue() / totalPackets;
                int barLen = (int) (pct / 5);
                StringBuilder bar = new StringBuilder();
                for (int i = 0; i < barLen; i++)
                    bar.append('#');
                for (int i = barLen; i < 20; i++)
                    bar.append(' ');

                System.out.printf("║ %-15s %8d %5.1f%% %-20s  ║\n",
                        Types.AppType.appTypeToString(entry.getKey()),
                        entry.getValue(), pct, bar.toString());
            }

            System.out.println("╚══════════════════════════════════════════════════════════════╝\n");

            System.out.println("[Detected Applications/Domains]");
            Map<String, Types.AppType> uniqueSnis = new HashMap<>();
            for (Types.Flow flow : flows.values()) {
                if (!flow.sni.isEmpty()) {
                    uniqueSnis.put(flow.sni, flow.appType);
                }
            }
            for (Map.Entry<String, Types.AppType> entry : uniqueSnis.entrySet()) {
                System.out.println("  - " + entry.getKey() + " -> " + Types.AppType.appTypeToString(entry.getValue()));
            }

            System.out.println("\nOutput written to: " + outputFile);

        } catch (IOException e) {
            System.err.println("Error writing output file: " + e.getMessage());
        }
    }
}
