import org.pcap4j.core.*;
import org.pcap4j.packet.*;
import org.pcap4j.packet.namednumber.IpNumber;
import org.pcap4j.util.NifSelector;

import javax.mail.*;
import javax.mail.internet.*;
import java.io.*;
import java.util.HashMap;
import java.util.Map;
import java.util.Properties;

public class ExtendedIDS {

    private static final int SYN_FLOOD_THRESHOLD = 100;
    private static final int ICMP_FLOOD_THRESHOLD = 50;
    private static final int UDP_FLOOD_THRESHOLD = 100;
    private static final int SNAPLEN = 65536;
    private static final int TIMEOUT = 1000;

    private static final Map<String, Integer> synFloodCounter = new HashMap<>();
    private static final Map<String, Integer> icmpFloodCounter = new HashMap<>();
    private static final Map<String, Integer> udpFloodCounter = new HashMap<>();

    public static void main(String[] args) {
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

            // Überprüfe Berechtigungen
            if (!checkPermissions(nif)) {
                System.err.println("Unzureichende Berechtigungen für das Interface. Bitte als Administrator ausführen.");
                return;
            }

            // Handle für den Live-Stream erstellen
            try (PcapHandle handle = nif.openLive(SNAPLEN,
                    PcapNetworkInterface.PromiscuousMode.PROMISCUOUS,
                    TIMEOUT)) {

                System.out.println("Capture gestartet auf Interface: " + nif.getName());
                System.out.println("Data Link Type: " + handle.getDlt());

                // Listener definieren mit zusätzlicher Fehlerbehandlung
                PacketListener listener = packet -> {
                    System.out.println("Packet captured: " + packet); // Füge dies hinzu
                    try {
                        analyzePacket(packet);
                    } catch (Exception e) {
                        System.err.println("Fehler bei der Paketanalyse: " + e.getMessage());
                        e.printStackTrace();
                    }
                };


                // Loop für die Paket-Analyse
                try {
                    System.out.println("Starte Packet Capture...");
                    handle.loop(0, listener); // 0 für unbegrenzte Anzahl von Paketen
                } catch (InterruptedException e) {
                    System.err.println("Capture wurde unterbrochen: " + e.getMessage());
                    Thread.currentThread().interrupt();
                } catch (PcapNativeException e) {
                    System.err.println("Native Pcap-Fehler: " + e.getMessage());
                    e.printStackTrace();
                }
            } catch (NotOpenException e) {
                System.err.println("Konnte Handle nicht öffnen: " + e.getMessage());
                e.printStackTrace();
            }
        } catch (PcapNativeException e) {
            System.err.println("Pcap Native Fehler: " + e.getMessage());
            e.printStackTrace();
        } catch (IOException e) {
            System.err.println("IO Fehler: " + e.getMessage());
            e.printStackTrace();
        }
    }

    private static boolean checkPermissions(PcapNetworkInterface nif) {
        try {
            // Versuche kurz zu erfassen, um Berechtigungen zu testen
            PcapHandle testHandle = nif.openLive(SNAPLEN,
                    PcapNetworkInterface.PromiscuousMode.PROMISCUOUS,
                    100);
            testHandle.getTimestamp();
            testHandle.close();
            return true;
        } catch (Exception e) {
            return false;
        }
    }

    private static void analyzePacket(Packet packet) {
        if (packet == null) {
            return;
        }

        try {
            if (packet.contains(TcpPacket.class)) {
                analyzeTcpPacket(packet);
            } else if (packet.contains(IcmpV4EchoPacket.class)) {
                analyzeIcmpPacket(packet);
            } else if (packet.contains(UdpPacket.class)) {
                analyzeUdpPacket(packet);
            }
        } catch (Exception e) {
            System.err.println("Fehler bei der Analyse des Pakets: " + e.getMessage());
            e.printStackTrace();
        }
    }

    private static synchronized void analyzeTcpPacket(Packet packet) {
        try {
            TcpPacket tcpPacket = packet.get(TcpPacket.class);
            IpV4Packet ipPacket = packet.get(IpV4Packet.class);
            if (tcpPacket.getHeader().getSyn() && !tcpPacket.getHeader().getAck() && ipPacket != null) {
                String srcIp = ipPacket.getHeader().getSrcAddr().getHostAddress();
                synFloodCounter.put(srcIp, synFloodCounter.getOrDefault(srcIp, 0) + 1);
                if (synFloodCounter.get(srcIp) > SYN_FLOOD_THRESHOLD) {
                    alert("SYN-Flood detected from: " + srcIp);
                }
            }
        } catch (Exception e) {
            System.err.println("Fehler bei der TCP-Paket Analyse: " + e.getMessage());
            e.printStackTrace();
        }
    }

    private static synchronized void analyzeIcmpPacket(Packet packet) {
        try {
            IcmpV4EchoPacket icmpPacket = packet.get(IcmpV4EchoPacket.class);
            String srcIp = packet.get(IpV4Packet.class).getHeader().getSrcAddr().getHostAddress();
            short identifier = icmpPacket.getHeader().getIdentifier();
            icmpFloodCounter.put(srcIp, icmpFloodCounter.getOrDefault(srcIp, 0) + 1);
            if (icmpFloodCounter.get(srcIp) > ICMP_FLOOD_THRESHOLD) {
                alert("ICMP-Ping-Flood detected from: " + srcIp + " with Identifier: " + identifier);
            }
        } catch (Exception e) {
            System.err.println("Fehler bei der ICMP-Paket Analyse: " + e.getMessage());
            e.printStackTrace();
        }
    }

    private static synchronized void analyzeUdpPacket(Packet packet) {
        try {
            UdpPacket udpPacket = packet.get(UdpPacket.class);
            IpV4Packet ipPacket = packet.get(IpV4Packet.class);
            if (ipPacket != null && ipPacket.getHeader().getProtocol() == IpNumber.UDP) {
                String srcIp = ipPacket.getHeader().getSrcAddr().getHostAddress();
                udpFloodCounter.put(srcIp, udpFloodCounter.getOrDefault(srcIp, 0) + 1);
                if (udpFloodCounter.get(srcIp) > UDP_FLOOD_THRESHOLD) {
                    alert("UDP-Flood detected from: " + srcIp);
                }
            }
        } catch (Exception e) {
            System.err.println("Fehler bei der UDP-Paket Analyse: " + e.getMessage());
            e.printStackTrace();
        }
    }

    private static void alert(String message) {
        System.out.println("ALERT: " + message);
        logEvent(message);
        // sendNotification(message);
    }

    private static void logEvent(String event) {
        try (FileWriter fw = new FileWriter("ids_log.txt", true);
             BufferedWriter bw = new BufferedWriter(fw);
             PrintWriter out = new PrintWriter(bw)) {
            out.println(event);
        } catch (IOException e) {
            System.err.println("Fehler beim Protokollieren: " + e.getMessage());
            e.printStackTrace();
        }
    }
/*
    private static void sendNotification(String message) {
        System.out.println("Sending notification: " + message);
        try {
            String host = "smtp.example.com";  // SMTP-Server hier anpassen
            String from = "alert@example.com";  // Absender hier anpassen
            String to = "admin@example.com";  // Empfänger hier anpassen
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
            mex.printStackTrace();
        }
    }
    */
}
