import org.pcap4j.core.*;
import org.pcap4j.packet.*;
import org.pcap4j.util.NifSelector;

import javax.mail.*;
import javax.mail.internet.*;
import java.io.IOException;
import java.net.InetAddress;
import java.util.Map;
import java.util.Properties;
import java.util.concurrent.*;

public class ExtendedIDS {

    private static int SYN_FLOOD_THRESHOLD = 100;
    private static int ICMP_FLOOD_THRESHOLD = 50;
    private static int UDP_FLOOD_THRESHOLD = 100;
    private static final int SNAPLEN = 65536;
    private static final int TIMEOUT = 1000;

    private static final Map<String, Integer> synFloodCounter = new ConcurrentHashMap<>();
    private static final Map<String, Integer> icmpFloodCounter = new ConcurrentHashMap<>();
    private static final Map<String, Integer> udpFloodCounter = new ConcurrentHashMap<>();

    private static ScheduledExecutorService scheduler = Executors.newScheduledThreadPool(1);

    public static void main(String[] args) {
        // Optional: Schwellenwerte über Kommandozeilenargumente setzen
        if (args.length == 3) {
            SYN_FLOOD_THRESHOLD = Integer.parseInt(args[0]);
            ICMP_FLOOD_THRESHOLD = Integer.parseInt(args[1]);
            UDP_FLOOD_THRESHOLD = Integer.parseInt(args[2]);
        }

        try {
            // Netzwerk-Interface auswählen
            NifSelector nifSelector = new NifSelector();
            PcapNetworkInterface nif = nifSelector.selectNetworkInterface();

            if (nif == null) {
                System.err.println("Kein Netzwerk-Interface ausgewählt oder keine Berechtigung.");
                return;
            }

            System.out.println("Ausgewähltes Interface: " + nif.getName());
            System.out.println("Interface Beschreibung: " + nif.getDescription());
            System.out.println("Interface Adressen: " + nif.getAddresses());

            // Handle für den Live-Stream erstellen
            try (PcapHandle handle = nif.openLive(SNAPLEN,
                    PcapNetworkInterface.PromiscuousMode.PROMISCUOUS,
                    TIMEOUT)) {

                System.out.println("Capture gestartet auf Interface: " + nif.getName());
                System.out.println("Data Link Type: " + handle.getDlt());

                // Scheduler zum Zurücksetzen der Zähler einrichten
                scheduler.scheduleAtFixedRate(ExtendedIDS::resetCounters, 0, 1, TimeUnit.MINUTES);

                // Listener definieren
                PacketListener listener = packet -> {
                    try {
                        analyzePacket(packet);
                    } catch (Exception e) {
                        System.err.println("Fehler bei der Paketanalyse: " + e.getMessage());
                    }
                };

                // Loop für die Paket-Analyse
                try {
                    System.out.println("Starte Packet Capture...");
                    handle.loop(-1, listener); // -1 für unbegrenzte Anzahl von Paketen
                } catch (InterruptedException e) {
                    System.err.println("Capture wurde unterbrochen: " + e.getMessage());
                    Thread.currentThread().interrupt();
                } catch (PcapNativeException e) {
                    System.err.println("Native Pcap-Fehler: " + e.getMessage());
                }
            } catch (NotOpenException e) {
                System.err.println("Konnte Handle nicht öffnen: " + e.getMessage());
            } finally {
                scheduler.shutdown();
            }
        } catch (PcapNativeException e) {
            System.err.println("Pcap Native Fehler: " + e.getMessage());
        } catch (IOException e) {
            System.err.println("IO Fehler: " + e.getMessage());
        }
    }

    private static void analyzePacket(Packet packet) {
        if (packet == null) {
            return;
        }

        if (packet.contains(TcpPacket.class)) {
            analyzeTcpPacket(packet);
        } else if (packet.contains(IcmpV4CommonPacket.class)) {
            analyzeIcmpPacket(packet);
        } else if (packet.contains(UdpPacket.class)) {
            analyzeUdpPacket(packet);
        }
    }

    private static void analyzeTcpPacket(Packet packet) {
        TcpPacket tcpPacket = packet.get(TcpPacket.class);
        IpPacket ipPacket = packet.get(IpPacket.class);

        if (tcpPacket != null && ipPacket != null) {
            TcpPacket.TcpHeader tcpHeader = tcpPacket.getHeader();
            if (tcpHeader.getSyn() && !tcpHeader.getAck()) {
                String srcIp = ipPacket.getHeader().getSrcAddr().getHostAddress();
                int count = synFloodCounter.merge(srcIp, 1, Integer::sum);
                if (count > SYN_FLOOD_THRESHOLD) {
                    alert("SYN-Flood detected from: " + srcIp);
                }
            }
        }
    }

    private static void analyzeIcmpPacket(Packet packet) {
        IpPacket ipPacket = packet.get(IpPacket.class);
        if (ipPacket != null) {
            String srcIp = ipPacket.getHeader().getSrcAddr().getHostAddress();
            int count = icmpFloodCounter.merge(srcIp, 1, Integer::sum);
            if (count > ICMP_FLOOD_THRESHOLD) {
                alert("ICMP-Ping-Flood detected from: " + srcIp);
            }
        }
    }

    private static void analyzeUdpPacket(Packet packet) {
        UdpPacket udpPacket = packet.get(UdpPacket.class);
        IpPacket ipPacket = packet.get(IpPacket.class);

        if (udpPacket != null && ipPacket != null) {
            String srcIp = ipPacket.getHeader().getSrcAddr().getHostAddress();
            int count = udpFloodCounter.merge(srcIp, 1, Integer::sum);
            if (count > UDP_FLOOD_THRESHOLD) {
                alert("UDP-Flood detected from: " + srcIp);
            }
        }
    }

    private static void alert(String message) {
        System.out.println("ALERT: " + message);
        logEvent(message);
        sendNotification(message);
    }

    private static void logEvent(String event) {
        // Hier könnten Sie ein Logging-Framework verwenden
        System.out.println("Logging event: " + event);
    }

    private static void sendNotification(String message) {
        System.out.println("Sending notification: " + message);
        try {
            String host = "smtp.example.com";  // SMTP-Server hier anpassen
            String from = "alert@example.com";  // Absender hier anpassen
            String to = "admin@example.com";  // Empfänger hier anpassen

            Properties properties = new Properties();
            properties.put("mail.smtp.host", host);
            properties.put("mail.smtp.port", "25"); // Port hier anpassen
            // Falls Authentifizierung erforderlich ist
            // properties.put("mail.smtp.auth", "true");
            // Session session = Session.getInstance(properties, new javax.mail.Authenticator() {
            //     protected PasswordAuthentication getPasswordAuthentication() {
            //         return new PasswordAuthentication("username", "password");
            //     }
            // });
            Session session = Session.getInstance(properties);

            Message email = new MimeMessage(session);
            email.setFrom(new InternetAddress(from));
            email.setRecipients(Message.RecipientType.TO, InternetAddress.parse(to));
            email.setSubject("IDS Alert");
            email.setText(message);

            Transport.send(email);
            System.out.println("Notification sent successfully.");
        } catch (MessagingException mex) {
            System.err.println("Error sending notification: " + mex.getMessage());
        }
    }

    private static void resetCounters() {
        synFloodCounter.clear();
        icmpFloodCounter.clear();
        udpFloodCounter.clear();
        System.out.println("Counters reset.");
    }
}
