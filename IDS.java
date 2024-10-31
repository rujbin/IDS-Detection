import org.pcap4j.core.*;
import org.pcap4j.packet.*;
import org.pcap4j.packet.namednumber.IpNumber;
import org.pcap4j.util.NifSelector;

import java.io.*;
import java.util.HashMap;
import java.util.Map;

public class ExtendedIDS {
    private static final int SYN_FLOOD_THRESHOLD = 100;
    private static final int ICMP_FLOOD_THRESHOLD = 50;
    private static final int UDP_FLOOD_THRESHOLD = 100;
    private static final Map<String, Integer> synFloodCounter = new HashMap<>();
    private static final Map<String, Integer> icmpFloodCounter = new HashMap<>();
    private static final Map<String, Integer> udpFloodCounter = new HashMap<>();
    private static final Map<String, Integer> dnsRequestCounter = new HashMap<>();
    private static final Map<String, Integer> httpRequestCounter = new HashMap<>();
    private static final int DNS_REQUEST_THRESHOLD = 200;
    private static final int HTTP_REQUEST_THRESHOLD = 200;

    public static void main(String[] args) {
        try {
            String nif = new NifSelector().selectNetworkInterface().getName();
            PcapHandle handle = Pcaps.openLive(nif, 65536, PcapNetworkInterface.PromiscuousMode.PROMISCUOUS, 10);
            PacketListener listener = ExtendedIDS::analyzePacket;

            // Start packet capture loop
            handle.loop(PcapHandle.PcapDlt.EN10MB.value(), listener);
            handle.close();
        } catch (PcapNativeException | InterruptedException | IOException e) {
            System.err.println("Error occurred: " + e.getMessage());
            e.printStackTrace();
        }
    }

    private static void analyzePacket(Packet packet) {
        System.out.println(packet);

        if (packet.contains(TcpPacket.class)) {
            analyzeTcpPacket(packet);
        } else if (packet.contains(IcmpV4EchoPacket.class)) {
            analyzeIcmpPacket(packet);
        } else if (packet.contains(UdpPacket.class)) {
            analyzeUdpPacket(packet);
        }

        if (packet.contains(UdpPacket.class)) {
            analyzeDnsPacket(packet);
        } else if (packet.contains(HttpPacket.class)) {
            analyzeHttpPacket(packet);
        }
    }

    private static void analyzeTcpPacket(Packet packet) {
        TcpPacket tcpPacket = packet.get(TcpPacket.class);
        if (tcpPacket.getHeader().getSyn() && !tcpPacket.getHeader().getAck()) {
            String srcIp = tcpPacket.getHeader().getSrcAddr().getHostAddress();
            synFloodCounter.put(srcIp, synFloodCounter.getOrDefault(srcIp, 0) + 1);
            if (synFloodCounter.get(srcIp) > SYN_FLOOD_THRESHOLD) {
                alert("SYN-Flood detected from: " + srcIp);
            }
        }
    }

    private static void analyzeIcmpPacket(Packet packet) {
        IcmpV4EchoPacket icmpPacket = packet.get(IcmpV4EchoPacket.class);
        String srcIp = icmpPacket.getHeader().getIdentifierAsInt();
        icmpFloodCounter.put(srcIp, icmpFloodCounter.getOrDefault(srcIp, 0) + 1);
        if (icmpFloodCounter.get(srcIp) > ICMP_FLOOD_THRESHOLD) {
            alert("ICMP-Ping-Flood detected from: " + srcIp);
        }
    }

    private static void analyzeUdpPacket(Packet packet) {
        IpV4Packet ipPacket = packet.get(IpV4Packet.class);
        if (ipPacket != null && ipPacket.getHeader().getProtocol() == IpNumber.UDP) {
            String srcIp = ipPacket.getHeader().getSrcAddr().getHostAddress();
            udpFloodCounter.put(srcIp, udpFloodCounter.getOrDefault(srcIp, 0) + 1);
            if (udpFloodCounter.get(srcIp) > UDP_FLOOD_THRESHOLD) {
                alert("UDP-Flood detected from: " + srcIp);
            }
        }
    }

    private static void analyzeDnsPacket(Packet packet) {
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

    private static void analyzeHttpPacket(Packet packet) {
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
