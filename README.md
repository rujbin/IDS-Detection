Extended Intrusion Detection System (IDS)

This project is an Extended Intrusion Detection System (IDS) written in Java, utilizing the Pcap4J library for packet capturing and analysis. The IDS is designed to monitor network traffic, detect potential threats, and alert administrators through various notification channels.

Features

Packet Analysis: Real-time analysis of TCP, UDP, ICMP, DNS, and HTTP packets.

Flood Detection: Detects SYN Flood, ICMP Ping Flood, UDP Flood, DNS Request Flood, and HTTP Request Flood attacks.

Logging: Detailed logging of detected threats to a file.

Notifications: Sends alert notifications via email.

Customizable Thresholds: Configurable thresholds for different types of flood detection.


Installation
Clone the repository:

bash
git clone https://github.com/rujbin/ids.git

cd extended-ids

Build the project using Maven:

bash
mvn clean install
Run the IDS:

bash
java -jar target/extended-ids-1.0-SNAPSHOT.jar
Dependencies
Pcap4J: Library for packet capturing.

JavaMail: For sending email notifications.

Configuration
Email Notifications: Configure the email settings in the sendNotification method within ExtendedIDS.java to enable email alerts.

java
String host = "smtp.example.com";
String from = "alert@example.com";
String to = "admin@example.com";
Usage
Run the IDS and monitor the console for alerts.

Check Logs: Detected threats are logged in the ids_log.txt file.

Configure Thresholds: Adjust the thresholds for different attack types in the source code:

java

private static final int SYN_FLOOD_THRESHOLD = 100;

private static final int ICMP_FLOOD_THRESHOLD = 50;

private static final int UDP_FLOOD_THRESHOLD = 100;

private static final int DNS_REQUEST_THRESHOLD = 200;

private static final int HTTP_REQUEST_THRESHOLD = 200;


Contribution

Contributions are welcome! Please fork the repository and create a pull request with your changes. Make sure to follow the coding standards and include detailed documentation for any new features.


License

This project is licensed under the ISC License. See the LICENSE file for details.
