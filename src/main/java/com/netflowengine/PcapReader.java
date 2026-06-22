package com.netflowengine;

import java.io.Closeable;
import java.io.DataInputStream;
import java.io.FileInputStream;
import java.io.IOException;

public class PcapReader implements Closeable {
    private DataInputStream is;
    private Types.PcapGlobalHeader globalHeader;
    private boolean isLittleEndian;

    public boolean open(String filename) {
        try {
            is = new DataInputStream(new FileInputStream(filename));
            byte[] headerBytes = new byte[24];
            if (is.read(headerBytes) != 24) return false;

            globalHeader = new Types.PcapGlobalHeader();
            long magic = Integer.toUnsignedLong(readInt32(headerBytes, 0, true));
            if (magic == 0xa1b2c3d4L || magic == 0xd4c3b2a1L) {
                isLittleEndian = (magic == 0xa1b2c3d4L);
            } else {
                return false;
            }

            globalHeader.magicNumber = magic;
            globalHeader.versionMajor = readInt16(headerBytes, 4, isLittleEndian) & 0xFFFF;
            globalHeader.versionMinor = readInt16(headerBytes, 6, isLittleEndian) & 0xFFFF;
            globalHeader.thiszone = readInt32(headerBytes, 8, isLittleEndian);
            globalHeader.sigfigs = Integer.toUnsignedLong(readInt32(headerBytes, 12, isLittleEndian));
            globalHeader.snaplen = Integer.toUnsignedLong(readInt32(headerBytes, 16, isLittleEndian));
            globalHeader.network = Integer.toUnsignedLong(readInt32(headerBytes, 20, isLittleEndian));
            
            return true;
        } catch (IOException e) {
            return false;
        }
    }

    public boolean readNextPacket(Types.RawPacket pkt) {
        try {
            byte[] pktHeader = new byte[16];
            int read = 0;
            while (read < 16) {
                int r = is.read(pktHeader, read, 16 - read);
                if (r < 0) return false;
                read += r;
            }

            pkt.header.tsSec = Integer.toUnsignedLong(readInt32(pktHeader, 0, isLittleEndian));
            pkt.header.tsUsec = Integer.toUnsignedLong(readInt32(pktHeader, 4, isLittleEndian));
            pkt.header.inclLen = Integer.toUnsignedLong(readInt32(pktHeader, 8, isLittleEndian));
            pkt.header.origLen = Integer.toUnsignedLong(readInt32(pktHeader, 12, isLittleEndian));

            if (pkt.header.inclLen > 100000 || pkt.header.inclLen < 0) {
                return false;
            }

            pkt.data = new byte[(int)pkt.header.inclLen];
            read = 0;
            while (read < pkt.data.length) {
                int r = is.read(pkt.data, read, pkt.data.length - read);
                if (r < 0) return false;
                read += r;
            }
            return true;
        } catch (IOException e) {
            return false;
        }
    }

    public Types.PcapGlobalHeader getGlobalHeader() {
        return globalHeader;
    }

    public byte[] getGlobalHeaderBytes() {
        byte[] bytes = new byte[24];
        writeInt32(bytes, 0, globalHeader.magicNumber, isLittleEndian);
        writeInt16(bytes, 4, globalHeader.versionMajor, isLittleEndian);
        writeInt16(bytes, 6, globalHeader.versionMinor, isLittleEndian);
        writeInt32(bytes, 8, globalHeader.thiszone, isLittleEndian);
        writeInt32(bytes, 12, globalHeader.sigfigs, isLittleEndian);
        writeInt32(bytes, 16, globalHeader.snaplen, isLittleEndian);
        writeInt32(bytes, 20, globalHeader.network, isLittleEndian);
        return bytes;
    }

    public boolean isLittleEndian() {
        return isLittleEndian;
    }

    @Override
    public void close() {
        try {
            if (is != null) is.close();
        } catch (IOException e) {}
    }

    public static int readInt32(byte[] b, int offset, boolean le) {
        if (le) {
            return (b[offset] & 0xFF) |
                   ((b[offset + 1] & 0xFF) << 8) |
                   ((b[offset + 2] & 0xFF) << 16) |
                   ((b[offset + 3] & 0xFF) << 24);
        } else {
            return ((b[offset] & 0xFF) << 24) |
                   ((b[offset + 1] & 0xFF) << 16) |
                   ((b[offset + 2] & 0xFF) << 8) |
                   (b[offset + 3] & 0xFF);
        }
    }

    public static int readInt16(byte[] b, int offset, boolean le) {
        if (le) {
            return (b[offset] & 0xFF) | ((b[offset + 1] & 0xFF) << 8);
        } else {
            return ((b[offset] & 0xFF) << 8) | (b[offset + 1] & 0xFF);
        }
    }

    public static void writeInt32(byte[] b, int offset, long v, boolean le) {
        if (le) {
            b[offset] = (byte)(v & 0xFF);
            b[offset+1] = (byte)((v >> 8) & 0xFF);
            b[offset+2] = (byte)((v >> 16) & 0xFF);
            b[offset+3] = (byte)((v >> 24) & 0xFF);
        } else {
            b[offset+3] = (byte)(v & 0xFF);
            b[offset+2] = (byte)((v >> 8) & 0xFF);
            b[offset+1] = (byte)((v >> 16) & 0xFF);
            b[offset]   = (byte)((v >> 24) & 0xFF);
        }
    }

    public static void writeInt16(byte[] b, int offset, int v, boolean le) {
        if (le) {
            b[offset] = (byte)(v & 0xFF);
            b[offset+1] = (byte)((v >> 8) & 0xFF);
        } else {
            b[offset+1] = (byte)(v & 0xFF);
            b[offset] = (byte)((v >> 8) & 0xFF);
        }
    }
}
