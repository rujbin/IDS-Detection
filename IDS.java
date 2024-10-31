import org.pcap4j.core.*;
import org.pcap4j.packet.*;
import org.pcap4j.util.NifSelector;

import javax.mail.*;
import javax.mail.internet.*;
import java.io.*;
import java.util.HashMap;
import java.util.Map;
import java.util.Properties;
import ja3_4j.*;

public class ExtendedIDS {
    private static final int SYN_FLOOD_THRESHOLD = 100;
    private static final int ICMP_FLOOD_THRESHOLD = 50;
    private static final int UDP_FLOOD_THRESHOLD = 100;
    private static final int DNS_REQUEST_THRESHOLD = 200;
    private static final int HTTP_REQUEST_THRESHOLD = 200;

    private static final Map<String, Integer> synFloodCounter = new HashMap<>();
    private static final Map<String, Integer> icmpFloodCounter = new HashMap<>();
    private static final Map<String, Integer> udpFloodCounter = new HashMap<>();
    private static final Map<String, Integer> dnsRequestCounter = new HashMap<>();
    private static final Map<String, Integer> httpRequestCounter = new HashMap<>();

    public static void main(String[] args) {
        try {
            String nif = new NifSelector().selectNetworkInterface().getName();
            PcapHandle handle = Pcaps.openLive(nif, 65536, PcapNetworkInterface.PromiscuousMode.PROMISCUOUS, 10);
            PacketListener listener = ExtendedIDS::analyzePacket;

            handle.loop(PcapHandle.PcapDlt.EN10MB.value(), listener);
            handle.close();
        } catch (PcapNativeException | InterruptedException | IOException e) {
            System.err.println("Error occurred: " + e.getMessage());
            e.printStackTrace();
        }
    }

    private static void analyzePacket(Packet packet) {
        if (packet.contains(TcpPacket.class)) {
            TcpPacket tcpPacket = packet.get(TcpPacket.class);
            analyzeTcpPacket(tcpPacket);
            TlsAnalyzer.analyzeTlsPacket(tcpPacket);
            FtpAnalyzer.analyzeFtpPacket(tcpPacket);
        } else if (packet.contains(IcmpV4EchoPacket.class)) {
            analyzeIcmpPacket(packet);
        } else if (packet.contains(UdpPacket.class)) {
            analyzeUdpPacket(packet);
            analyzeDnsPacket(packet);
        } else if (packet.contains(HttpPacket.class)) {
            analyzeHttpPacket(packet);
        }
        // Integration von HTTP/2 Analyse
        if (packet instanceof Http2Frame) {
            Http2Frame frame = (Http2Frame) packet;
            Http2Analyzer http2Analyzer = new Http2Analyzer();
            if (frame instanceof Http2DataFrame) {
                Http2DataFrame dataFrame = (Http2DataFrame) frame;
                http2Analyzer.onDataRead(null, dataFrame.streamId(), dataFrame.content(), 0, dataFrame.isEndStream());
            } else if (frame instanceof Http2HeadersFrame) {
                Http2HeadersFrame headersFrame = (Http2HeadersFrame) frame;
                http2Analyzer.onHeadersRead(null, headersFrame.streamId(), headersFrame.headers(), 0, headersFrame.isEndStream());
            }
        }
    }

    private static synchronized void analyzeTcpPacket(Packet packet) {
        TcpPacket tcpPacket = packet.get(TcpPacket.class);
        if (tcpPacket.getHeader().getSyn() && !tcpPacket.getHeader().getAck()) {
            String srcIp = tcpPacket.getHeader().getSrcAddr().getHostAddress();
            synFloodCounter.put(srcIp, synFloodCounter.getOrDefault(srcIp, 0) + 1);
            if (synFloodCounter.get(srcIp) > SYN_FLOOD_THRESHOLD) {
                alert("SYN-Flood detected from: " + srcIp);
            }
        }
    }

    private static synchronized void analyzeIcmpPacket(Packet packet) {
        IcmpV4EchoPacket icmpPacket = packet.get(IcmpV4EchoPacket.class);
        String srcIp = icmpPacket.getHeader().getIdentifierAsInt();
        icmpFloodCounter.put(srcIp, icmpFloodCounter.getOrDefault(srcIp, 0) + 1);
        if (icmpFloodCounter.get(srcIp) > ICMP_FLOOD_THRESHOLD) {
            alert("ICMP-Ping-Flood detected from: " + srcIp);
        }
    }

    private static synchronized void analyzeUdpPacket(Packet packet) {
        IpV4Packet ipPacket = packet.get(IpV4Packet.class);
        if (ipPacket != null && ipPacket.getHeader().getProtocol() == IpNumber.UDP) {
            String srcIp = ipPacket.getHeader().getSrcAddr().getHostAddress();
            udpFloodCounter.put(srcIp, udpFloodCounter.getOrDefault(srcIp, 0) + 1);
            if (udpFloodCounter.get(srcIp) > UDP_FLOOD_THRESHOLD) {
                alert("UDP-Flood detected from: " + srcIp);
            }
        }
    }

    private static synchronized void analyzeDnsPacket(Packet packet) {
        UdpPacket udpPacket = packet.get(UdpPacket.class);
        DnsPacket dnsPacket = udpPacket.get(DnsPacket.class);
        if (dnsPacket != null) {
            String srcIp = udpPacket.getHeader().getSrcAddr().getHostAddress();
            dnsRequestCounter.put(srcIp, dnsRequestCounter.getOrDefault(srcIp, 0) + 1);
            if (dnsRequestCounter.get(srcIp) > DNS_REQUEST_THRESHOLD) {
                alert("DNS Request Flood detected from: " + srcIp);
            }
        }
    }

    private static synchronized void analyzeHttpPacket(Packet packet) {
        HttpPacket httpPacket = packet.get(HttpPacket.class);
        if (httpPacket != null) {
            String srcIp = httpPacket.getHeader().getSrcAddr().getHostAddress();
            httpRequestCounter.put(srcIp, httpRequestCounter.getOrDefault(srcIp, 0) + 1);
            if (httpRequestCounter.get(srcIp) > HTTP_REQUEST_THRESHOLD) {
                alert("HTTP Request Flood detected from: " + srcIp);
            }
        }
    }

    private static void alert(String message) {
        System.out.println("ALERT: " + message);
        logEvent(message);
        sendNotification(message);
    }

    private static void logEvent(String event) {
        try (FileWriter fw = new FileWriter("ids_log.txt", true);
             BufferedWriter bw = new BufferedWriter(fw);
             PrintWriter out = new PrintWriter(bw)) {
            out.println(event);
        } catch (IOException e) {
            System.err.println("Fehler beim Protokollieren: " + e.getMessage());
        }
    }

    private static void sendNotification(String message) {
        System.out.println("Sending notification: " + message);
        // Hier könntest du einen E-Mail-Client wie JavaMail verwenden, um die Benachrichtigung zu senden
        try {
            String host = "smtp.example.com";
            String from = "alert@example.com";
            String to = "admin@example.com";

            Properties properties = System.getProperties();
            properties.setProperty("mail.smtp.host", host);
            Session session = Session.getDefaultInstance(properties);

            MimeMessage email = new MimeMessage(session);
            email.setFrom(new InternetAddress(from));
            email.addRecipient(Message.RecipientType.TO, new InternetAddress(to));
            email.setSubject("IDS Alert");
            email.setText(message);

            Transport.send(email);
            System.out.println("Notification sent successfully.");
        } catch (MessagingException mex) {
            System.err.println("Error sending notification: " + mex.getMessage());
        }
    }
}

// JA3 Analyzer Klasse
class TlsAnalyzer {
    public static void analyzeTlsPacket(TcpPacket tcpPacket) {
        // Beispiel für JA3-Fingerprinting
        if (tcpPacket.getHeader().getDstPort().equals(TcpPort.HTTPS) || 
            tcpPacket.getHeader().getDstPort().equals(TcpPort.TLS)) {
            System.out.println("TLS/SSL Packet detected.");
            // JA3-Fingerprinting durchführen
            JA3Fingerprint fingerprint = JA3.extract(tcpPacket);
            String ja3Hash = fingerprint.getHash();
            System.out.println("JA3 Fingerprint: " + ja3Hash);
        }
    }
}

// HTTP/2 Analyzer
class Http2Analyzer implements Http2FrameListener {
    @Override
    public void onDataRead(ChannelHandlerContext ctx, int streamId, ByteBuf data, int padding, boolean endOfStream) {
        System.out.println("HTTP/2 Data read from stream: " + streamId);
        // Analysiere die Daten hier
    }

    @Override
    public void onHeadersRead(ChannelHandlerContext ctx, int streamId, Http2Headers headers, int padding, boolean endStream) {
        System.out.println("HTTP/2 Headers read from stream: " + streamId);
        // Analysiere die Header hier
    }

    // Weitere notwendige Methoden implementieren...
}
