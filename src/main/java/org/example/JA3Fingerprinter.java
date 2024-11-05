import org.bouncycastle.crypto.tls.*;
import org.pcap4j.core.*;
import org.pcap4j.packet.Packet;
import org.pcap4j.packet.TcpPacket;
import org.pcap4j.packet.IpPacket;
import org.pcap4j.util.NifSelector;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.security.MessageDigest;
import java.util.*;

public class JA3Fingerprinter {

    public static void main(String[] args) {
        try {
            // NIF auswählen
            NifSelector nifSelector = new NifSelector();
            PcapNetworkInterface nif = nifSelector.selectNetworkInterface();
            if (nif == null) {
                System.out.println("Keine Netzwerkschnittstelle ausgewählt.");
                return;
            }

            // PcapHandle erstellen
            try (PcapHandle handle = nif.openLive(65536, PcapNetworkInterface.PromiscuousMode.PROMISCUOUS, 10)) {
                PacketListener listener = packet -> {
                    if (packet.contains(TcpPacket.class) && packet.contains(IpPacket.class)) {
                        TcpPacket tcpPacket = packet.get(TcpPacket.class);
                        analyzeTcpPacket(tcpPacket);
                    }
                };
                handle.loop(-1, listener);
            } catch (NotOpenException e) {
                System.err.println("Fehler beim Öffnen des Handles: " + e.getMessage());
            } catch (InterruptedException e) {
                System.err.println("Paket-Capture unterbrochen: " + e.getMessage());
                Thread.currentThread().interrupt();
            }
        } catch (PcapNativeException | IOException e) {
            System.err.println("Fehler: " + e.getMessage());
        }
    }

    private static void analyzeTcpPacket(TcpPacket tcpPacket) {
        TcpPacket.TcpHeader tcpHeader = tcpPacket.getHeader();
        if (tcpHeader.getDstPort().valueAsInt() != 443 && tcpHeader.getSrcPort().valueAsInt() != 443) {
            return; // Nur TLS auf Port 443 betrachten
        }

        if (tcpPacket.getPayload() == null) {
            return;
        }

        byte[] payloadData = tcpPacket.getPayload().getRawData();

        if (payloadData.length < 5) {
            return;
        }

        // Prüfen, ob es sich um ein TLS-Handshake-Paket handelt
        if (payloadData[0] != 0x16) { // 0x16 = Handshake
            return;
        }

        // TLS-Protokollversion extrahieren
        int majorVersion = payloadData[1] & 0xFF;
        int minorVersion = payloadData[2] & 0xFF;

        // Länge des TLS-Records
        int length = ((payloadData[3] & 0xFF) << 8) | (payloadData[4] & 0xFF);

        if (length + 5 > payloadData.length) {
            return; // Unvollständiges Paket
        }

        byte[] handshakeData = Arrays.copyOfRange(payloadData, 5, 5 + length);

        try (ByteArrayInputStream bis = new ByteArrayInputStream(handshakeData)) {
            TlsClientHello clientHello = parseClientHello(bis);

            if (clientHello != null) {
                String ja3 = createJA3Fingerprint(clientHello);
                String ja3Hash = md5(ja3);
                System.out.println("JA3 String: " + ja3);
                System.out.println("JA3 Hash: " + ja3Hash);
            }
        } catch (IOException e) {
            System.err.println("Fehler beim Parsen des Client Hello: " + e.getMessage());
        }
    }

    private static TlsClientHello parseClientHello(ByteArrayInputStream bis) throws IOException {
        int handshakeType = bis.read();
        if (handshakeType != HandshakeType.client_hello) {
            return null;
        }

        // Länge der Handshake-Nachricht
        int handshakeLength = ((bis.read() & 0xFF) << 16) | ((bis.read() & 0xFF) << 8) | (bis.read() & 0xFF);

        // TLS-Version
        int majorVersion = bis.read();
        int minorVersion = bis.read();

        // Restliche Daten überspringen (Random, Session ID, etc.)
        bis.skip(handshakeLength - 2);

        // Da Bouncy Castle keine direkte Methode zum Parsen von ClientHello bietet, müssten wir hier ein vollständiges Parsen implementieren
        // Dies ist sehr komplex und würde den Rahmen dieses Beispiels sprengen
        // Daher empfehlen wir die Verwendung einer spezialisierten Bibliothek oder eines Tools

        // Platzhalter für ClientHello
        return new TlsClientHello(majorVersion, minorVersion);
    }

    private static String createJA3Fingerprint(TlsClientHello clientHello) {
        // Hier würden Sie die TLS-Version, Cipher Suites, Extensions, Elliptic Curves und Point Formats extrahieren
        // und den JA3-String gemäß der Spezifikation erstellen

        // Platzhalter für den JA3-String
        String ja3String = clientHello.getMajorVersion() + "," + clientHello.getMinorVersion();

        // Beispielhaftes Hinzufügen von Cipher Suites, Extensions etc.
        // In der Realität müssten Sie die tatsächlichen Werte aus clientHello extrahieren

        return ja3String;
    }

    private static String md5(String input) {
        try {
            MessageDigest md = MessageDigest.getInstance("MD5");
            byte[] hashInBytes = md.digest(input.getBytes());
            StringBuilder sb = new StringBuilder();
            for (byte b : hashInBytes) {
                sb.append(String.format("%02x", b));
            }
            return sb.toString();
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    // Platzhalterklasse für TlsClientHello
    static class TlsClientHello {
        private final int majorVersion;
        private final int minorVersion;

        public TlsClientHello(int majorVersion, int minorVersion) {
            this.majorVersion = majorVersion;
            this.minorVersion = minorVersion;
        }

        public int getMajorVersion() {
            return majorVersion;
        }

        public int getMinorVersion() {
            return minorVersion;
        }

        // Methoden zum Abrufen von Cipher Suites, Extensions etc.
    }
}
