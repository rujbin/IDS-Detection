import org.pcap4j.core.*;
import org.pcap4j.packet.Packet;
import org.pcap4j.packet.TcpPacket;
import org.pcap4j.packet.IpV4Packet;
import org.pcap4j.util.NifSelector;

import java.security.MessageDigest;
import java.util.Arrays;
import java.util.List;

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
            PcapHandle handle = nif.openLive(65536, PcapNetworkInterface.PromiscuousMode.PROMISCUOUS, 10);
            PacketListener listener = packet -> {
                if (packet.contains(TcpPacket.class) && packet.contains(IpV4Packet.class)) {
                    TcpPacket tcpPacket = packet.get(TcpPacket.class);
                    IpV4Packet ipV4Packet = packet.get(IpV4Packet.class);
                    analyzeTcpPacket(tcpPacket, ipV4Packet);
                }
            };
            handle.loop(-1, listener);
            handle.close();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    private static void analyzeTcpPacket(TcpPacket tcpPacket, IpV4Packet ipV4Packet) {
        byte[] payload = tcpPacket.getPayload().getRawData();
        if (isClientHello(payload)) {
            String ja3 = createJA3Fingerprint(payload);
            System.out.println("JA3 Fingerprint: " + ja3);
        }
    }

    private static boolean isClientHello(byte[] payload) {
        return payload.length > 5 && payload[0] == 0x16 && payload[1] == 0x03;
    }

    private static String createJA3Fingerprint(byte[] payload) {
        List<String> fields = Arrays.asList(
                Integer.toString(payload[1]),
                Arrays.toString(Arrays.copyOfRange(payload, 2, 34)),
                Arrays.toString(Arrays.copyOfRange(payload, 35, payload.length))
        );
        String ja3String = String.join(",", fields);
        return md5(ja3String);
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
}
