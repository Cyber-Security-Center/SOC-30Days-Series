# 🛡️ Day 5: OSI Model, TCP/UDP & Ports
*Part of the [30-Day SOC Level 1 Series](https://cyber-security-center.github.io/SOC-30Days-Series/)*

Today we dive deeper into how data moves across networks and how SOC analysts use this knowledge to detect threats. Understanding the OSI model, TCP/UDP protocols, and ports is essential for analyzing network traffic and identifying malicious behavior.

---

## 📌 Topics & Subtopics

1. **OSI Model**
   - 7 Layers Overview
   - Role in Threat Detection
2. **TCP vs UDP**
   - Characteristics
   - Use Cases in Cybersecurity
3. **Ports**
   - Common Ports
   - Port Scanning & Threats

---

## 🔍 Definitions & Examples

### 1. OSI Model

📘 **Definition**: The OSI (Open Systems Interconnection) Model is a conceptual framework that standardizes the functions of a network into seven layers, from physical transmission to application-level interactions.

🧠 **Example**: A SOC analyst might investigate a Layer 4 (Transport) attack like a TCP SYN flood or a Layer 7 (Application) attack like an HTTP-based DDoS.

_“The OSI model is like a delivery system—each layer is a step from packaging to delivery, ensuring data reaches the right place in the right format.”_

#### OSI Layers Overview

1. **Layer 1 – Physical**: Cables, switches, signals  
2. **Layer 2 – Data Link**: MAC addresses, Ethernet  
3. **Layer 3 – Network**: IP addressing, routing  
4. **Layer 4 – Transport**: TCP/UDP, ports  
5. **Layer 5 – Session**: Connection management  
6. **Layer 6 – Presentation**: Data formatting, encryption  
7. **Layer 7 – Application**: User-facing services (HTTP, DNS)

![OSI Model Layers](https://blog.techiescamp.com/content/images/2023/12/01-OSI_LAYER.gif)
Reference: TechiesCamp


![OSI Model Layers](https://assets.bytebytego.com/diagrams/0295-osi-model.jpeg)
Reference: ByteByteGo

*Figures: Visual representation of the OSI Model and its seven layers.*

---

### 2. TCP vs UDP

📘 **Definition**: TCP (Transmission Control Protocol) is reliable and connection-based, ensuring data arrives correctly. UDP (User Datagram Protocol) is faster but connectionless, with no guarantee of delivery.

🧠 **Example**: TCP is used for secure web browsing (HTTPS), while UDP is used for DNS lookups. SOC tools monitor both for anomalies like DNS tunneling or TCP port scans.

_“TCP is like a phone call—both sides talk and confirm. UDP is like shouting across a room—quick but no guarantee it’s heard.”_

#### Key Differences

| Feature       | TCP                          | UDP                          |
|---------------|------------------------------|------------------------------|
| Reliability   | High (acknowledgments)       | Low (no guarantees)          |
| Speed         | Slower                       | Faster                       |
| Use Cases     | HTTPS, SSH, FTP              | DNS, VoIP, Streaming         |
| SOC Relevance | Detecting scans, data exfil  | DNS abuse, fast attacks      |

---

### 3. Ports

📘 **Definition**: Ports are logical endpoints used by protocols to identify specific services on a device. Each service listens on a specific port number.

🧠 **Example**: Port 443 is used for HTTPS. If malware uses this port, it may blend in with normal traffic. SOC analysts use tools like Zeek or Suricata to inspect port activity.

_“Ports are like doors in a building—each one leads to a different room (service), and attackers often try to find open doors.”_

#### Common Ports

| Port | Protocol | Service        |
|------|----------|----------------|
| 80   | TCP      | HTTP           |
| 443  | TCP      | HTTPS          |
| 22   | TCP      | SSH            |
| 53   | UDP      | DNS            |
| 25   | TCP      | SMTP (Email)   |

#### Port Scanning

📘 **Definition**: Port scanning is a technique used to discover open ports and services on a host. It’s often a precursor to an attack.

🧠 **Example**: SOC analysts detect port scans using IDS tools like Snort or Suricata, which alert on suspicious scanning behavior.

_“Port scanning is like checking every door in a building to see which ones are unlocked.”_

---

## 🧩 OSI Layers Deep Dive

### **Layer 7 – Application**

📘 **Definition & Purpose:**  
The Application layer provides network services directly to end-users and applications. It enables user interaction with networked software.

🧠 **Example:**  
Browsing websites, sending emails, file transfers.

_“This is where you use apps like web browsers, email, or chat.”_

- **Common Protocols:**  
    HTTP, HTTPS, FTP, SMTP, DNS, POP3, IMAP.
- **Common Devices:**  
    Computers, smartphones, application servers.
- **Top Attacks:**  
    - **Phishing:** Tricking users into revealing sensitive info via fake websites or emails.  
        _Mitigation:_ User training, email filtering, web filtering.
    - **HTTP Flood (Layer 7 DDoS):** Overwhelming web servers with requests.  
        _Mitigation:_ Web Application Firewalls (WAF), rate limiting.

---

### **Layer 6 – Presentation**

📘 **Definition & Purpose:**  
The Presentation layer formats and encrypts data for the application layer. It ensures data is readable by the receiving system.

🧠 **Example:**  
Data encryption, compression, character encoding.

_“This layer makes sure data looks right and is secure.”_

- **Common Protocols:**  
    SSL/TLS, JPEG, MPEG, ASCII, EBCDIC.
- **Common Devices:**  
    Gateways, encryption devices.
- **Top Attacks:**  
    - **SSL Stripping:** Downgrading secure connections to unencrypted ones.  
        _Mitigation:_ Enforce HTTPS, use HSTS.
    - **Data Manipulation:** Altering data encoding to bypass filters.  
        _Mitigation:_ Input validation, strong parsing.

---

### **Layer 5 – Session**

📘 **Definition & Purpose:**  
The Session layer manages sessions (connections) between applications. It establishes, maintains, and terminates connections.

🧠 **Example:**  
Logging into a website, video calls.

_“This layer keeps conversations going between computers.”_

- **Common Protocols:**  
    NetBIOS, RPC, PPTP, SMB.
- **Common Devices:**  
    Application servers, proxies.
- **Top Attacks:**  
    - **Session Hijacking:** Taking over a user’s session.  
        _Mitigation:_ Use session tokens, secure cookies, timeout sessions.
    - **Replay Attacks:** Reusing valid session data to gain access.  
        _Mitigation:_ Use nonces, timestamps, encryption.

---

### **Layer 4 – Transport**

📘 **Definition & Purpose:**  
The Transport layer ensures reliable data transfer between hosts, handling error correction and flow control.

🧠 **Example:**  
Downloading files, streaming videos.

_“This layer makes sure data gets to the right place, correctly.”_

- **Common Protocols:**  
    TCP, UDP, SCTP.
- **Common Devices:**  
    Firewalls, load balancers.
- **Top Attacks:**  
    - **TCP SYN Flood:** Overloading a server with connection requests.  
        _Mitigation:_ SYN cookies, rate limiting, firewalls.
    - **UDP Flood:** Sending massive UDP packets to exhaust resources.  
        _Mitigation:_ Rate limiting, filtering, IDS/IPS.

---

### **Layer 3 – Network**

📘 **Definition & Purpose:**  
The Network layer routes data packets between devices across networks.

🧠 **Example:**  
Sending emails across the internet.

_“This layer finds the best path for data to travel.”_

- **Common Protocols:**  
    IP, ICMP, ARP, IPSec.
- **Common Devices:**  
    Routers, Layer 3 switches.
- **Top Attacks:**  
    - **IP Spoofing:** Faking IP addresses to bypass security.  
        _Mitigation:_ Packet filtering, ingress/egress filtering.
    - **ICMP Flood (Ping of Death):** Overwhelming a device with ICMP packets.  
        _Mitigation:_ Rate limiting, firewall rules.

---

### **Layer 2 – Data Link**

📘 **Definition & Purpose:**  
The Data Link layer handles node-to-node data transfer and error detection/correction on the same network.

🧠 **Example:**  
Sending files between computers on the same Wi-Fi.

_“This layer moves data between devices on the same network.”_

- **Common Protocols:**  
    Ethernet, PPP, ARP, VLAN.
- **Common Devices:**  
    Switches, bridges, network cards.
- **Top Attacks:**  
    - **MAC Flooding:** Overloading a switch’s MAC table to force broadcast.  
        _Mitigation:_ Port security, MAC limiting.
    - **ARP Spoofing:** Sending fake ARP messages to intercept traffic.  
        _Mitigation:_ Dynamic ARP Inspection, static ARP entries.

---

### **Layer 1 – Physical**

📘 **Definition & Purpose:**  
The Physical layer transmits raw bits over physical media like cables or radio waves.

🧠 **Example:**  
Ethernet cables, Wi-Fi signals.

_“This is the hardware—cables, switches, and signals.”_

- **Common Protocols:**  
    Ethernet, USB, Bluetooth, DSL.
- **Common Devices:**  
    Hubs, cables, repeaters, network interface cards.
- **Top Attacks:**  
    - **Wiretapping:** Physically intercepting network cables.  
        _Mitigation:_ Physical security, cable shielding.
    - **Jamming:** Disrupting wireless signals.  
        _Mitigation:_ Use secure frequencies, physical barriers.

---

## ⚡ OSI vs TCP/IP: Direct Comparison

| Aspect         | OSI Model (7 Layers)                                 | TCP/IP Model (4 Layers)                |
|----------------|-----------------------------------------------------|----------------------------------------|
| Purpose        | Conceptual, educational framework                   | Practical, real-world implementation   |
| Number of Layers | 7 (Physical, Data Link, Network, Transport, Session, Presentation, Application) | 4 (Network Interface, Internet, Transport, Application) |
| Layer Structure | More granular, separates Presentation and Session   | Combines Presentation, Session, and Application into one |
| Development    | Developed by ISO                                    | Developed by DARPA for ARPANET         |
| Usage          | Reference for learning and design                   | Basis for the modern internet          |
| Protocols      | Defines protocols like Ethernet, IP, TCP, HTTP      | Uses similar protocols, but mapped to fewer layers |


> **Summary:**  
OSI is mainly for understanding and teaching, while TCP/IP is the standard for real-world networking.

---

## ✅ Summary

Understanding the OSI model helps SOC analysts pinpoint where threats occur. TCP/UDP protocols and port behavior reveal how attackers communicate and exploit systems. Mastering these concepts is key to effective threat detection and response.

