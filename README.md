🚀 Deep Packet Inspection (DPI) Analyzer – Python Implementation
------------------------------------------------------------------------------------------------------------------------------------------------------

This project implements a Deep Packet Inspection (DPI) engine in Python that analyzes network traffic from PCAP files, classifies application traffic, detects suspicious activity, and applies rule-based filtering.

The system mimics how real enterprise network security tools work, including:

🔍 Traffic inspection

🌐 Application detection

🛡️ Threat identification

📊 Network analytics

⚡ Multi-thread packet processing

This project demonstrates how modern firewalls, IDS/IPS systems, and traffic monitoring tools analyze network packets internally.

-------------------------------------------------------------------------------------------------------------------------------------------------
📚 Table of Contents
----------------------------------------------------------------------------------------------------------------------------------------

1️⃣ What is Deep Packet Inspection

2️⃣ Networking Background

3️⃣ Project Overview

4️⃣ System Architecture

5️⃣ Packet Processing Flow

6️⃣ Project Structure

7️⃣ Core Components

8️⃣ Threat Detection

9️⃣ Running the Analyzer

🔟 Understanding the Output

1️⃣1️⃣ Extending the Project

--------------------------------------------------------------------------------------------------------------------


🔍 1. What is Deep Packet Inspection
----------------------------------------------------------------------------------------------------------------------------------------

Deep Packet Inspection (DPI) is a technique used to inspect network packets beyond simple header analysis.

Traditional network monitoring checks only:

Source IP

Destination IP

Port number

However DPI inspects the actual packet content (payload) to identify applications and detect malicious traffic.

----------------------------------------------------------------------------------------------------------------------------------------------

💡 Real-World Uses
------------------------------------------------------------------------------------------------------------------------------------------------------------

🏢 Enterprise Firewalls

🛡️ Intrusion Detection Systems (IDS)

📡 ISP Traffic Monitoring

👨‍👩‍👧 Parental Content Filtering

🦠 Malware Detection Systems

--------------------------------------------------------------------------------------------------------------------------------------------------
DPI Workflow
----------------------------------------------------------------------------------------------------------------------------------------------------------
PCAP Traffic

⬇

Packet Parser

⬇

Flow Tracker

⬇

Application Classification

⬇

Rule Engine

⬇

Traffic Analytics + Output

---------------------------------------------------------------------------------------------------------------------------------------------------------

🌐 2. Networking Background
--------------------------------------------------------------------------------------------------------------------------------------------


Network communication follows a layered architecture.

📡 Network Stack

Application Layer
HTTP / HTTPS / DNS

Transport Layer
TCP / UDP

Network Layer
IP Addressing

Data Link Layer
Ethernet Frames

Each packet contains multiple nested headers.

Ethernet Header ➡ IP Header ➡ TCP/UDP Header ➡ Payload (Application Data)

The DPI engine analyzes these layers to determine:

✔ Source and destination hosts
✔ Transport protocol
✔ Application type
✔ Suspicious traffic patterns

-----------------------------------------------------------------------------------------------------------------------------------------------------------

🧠 3. Project Overview
----------------------------------------------------------------------------------------------------------------------------------------------

This DPI Analyzer reads network traffic from a PCAP capture file, analyzes each packet, and generates a detailed report.

🛠️ The analyzer performs

1️⃣ Reads packets from PCAP capture

2️⃣ Parses Ethernet/IP/TCP/UDP headers

3️⃣ Extracts application information

4️⃣ Identifies application traffic

5️⃣ Applies security rules

6️⃣ Detects suspicious activity

7️⃣ Generates network statistics

8️⃣ Produces a detailed DPI report

--------------------------------------------------------------------------------------------------------------------------------------------------------------

🏗️ 4. System Architecture
-------------------------------------------------------------------------------------------------------------------------------------------------

The analyzer consists of several processing modules.

PCAP Reader

⬇

Packet Parser

⬇

Connection Tracker

⬇

Rule Engine

⬇

Threat Detector

⬇

Traffic Statistics


Each module processes packets and forwards results to the next stage.

This modular architecture makes the system easy to extend and maintain.

------------------------------------------------------------------------------------------------------------------------------------------------------
⚙️ 5. Packet Processing Flow
----------------------------------------------------------------------------------------------------------------------------------------------------

Every packet processed by the analyzer follows this pipeline:

Read packet from PCAP

⬇

Parse Ethernet Header

⬇

Parse IP Header

⬇

Parse TCP/UDP Header

⬇

Extract Payload

⬇

Identify Application

⬇

Apply Filtering Rules

⬇

Update Network Statistics

🔑 Flow Identification

Connections are tracked using the five-tuple:

Source IP

Destination IP

Source Port

Destination Port

Protocol

This allows grouping packets belonging to the same network connection.

----------------------------------------------------------------------------------------------------------------------------------------------------

📂 6. Project Structure
----------------------------------------------------------------------------------------------------------------------------------------------------

deep-packet-inspection-analyzer

app_classifier.py
➡ Application identification logic

packet_parser.py
➡ Parses Ethernet/IP/TCP/UDP headers

pcap_reader.py
➡ Reads packets from PCAP files

sni_extractor.py
➡ Extracts TLS SNI domain names

rule_engine.py
➡ Applies security rules

connection_tracker.py
➡ Tracks active connections

traffic_stats.py
➡ Packet and byte statistics

connection_stats.py
➡ Connection analytics

decision_stats.py
➡ Allow / Block decisions

bandwidth_stats.py
➡ Traffic bandwidth analysis

threat_detector.py
➡ Detects suspicious traffic

top_talkers.py
➡ Identifies most active hosts

output_writer.py
➡ Writes filtered traffic to PCAP

thread_safe_queue.py
➡ Thread-safe queues

fast_path.py
➡ Fast packet processing

load_balancer.py
➡ Distributes packets to workers

mt_dpi_engine.py
➡ Multi-thread DPI engine

test_reader.py
➡ Main entry point

----------------------------------------------------------------------------------------------------------------------------------------------------
🧩 7. Core Components
📥 PCAP Reader
----------------------------------------------------------------------------------------------------------------------------------------------------


Reads packet data from PCAP files.

Responsible for:

Opening PCAP files

Reading packet headers

Extracting raw packet data

📦 Packet Parser

Extracts protocol headers including:

Ethernet

IPv4

TCP

UDP

Key information extracted:

✔ Source IP
✔ Destination IP
✔ Ports
✔ Protocol

🧠 Application Classifier

Identifies application traffic using:

Port numbers

TLS SNI domains

Traffic patterns

Examples:

YouTube
Facebook
Google
Netflix
DNS
HTTPS
HTTP

🛡️ Rule Engine

Applies filtering rules to traffic.

Supported rules include:

Block specific ports

Block specific applications

Block specific domains

Example rule:

block_port(4444)

🔗 Connection Tracker

Maintains state for each connection using the five-tuple.

Tracks:

Packet count

Byte count

Application type

Connection status

🚨 Threat Detector

Detects suspicious activity such as:

Malware command channels

Unusual ports

Suspicious domains

Example detection:

⚠ Suspicious port: 4444
⚠ Possible trojan communication

----------------------------------------------------------------------------------------------------------------------------------------------------
🕵️ 8. Threat Detection
----------------------------------------------------------------------------------------------------------------------------------------------------

The analyzer detects traffic patterns commonly associated with malicious activity.

Examples include:

Trojan command ports

Suspicious domains

Unknown encrypted traffic

Unusual communication patterns

Threat alerts appear in the final report:

THREAT ALERTS
Possible trojan activity detected
Suspicious connection on port 4444

----------------------------------------------------------------------------------------------------------------------------------------------------
▶️ 9. Running the Analyzer
----------------------------------------------------------------------------------------------------------------------------------------------------

Install required dependency

pip install scapy

Run analyzer

python test_reader.py

Analyze a specific PCAP file

python test_reader.py capture.pcap

----------------------------------------------------------------------------------------------------------------------------------------------------

📊 10. Understanding the Output
----------------------------------------------------------------------------------------------------------------------------------------------------

The analyzer generates a detailed report.

🔗 Connection Summary

Lists detected network flows.

Example:

142.250.185.206:443 → 192.168.1.100
Application: GOOGLE
Packets: 4
Bytes: 300

📈 Traffic Statistics

Displays metrics such as:

Total packets
Total bytes
Application distribution

⚖ Decision Statistics

Shows filtering decisions:

ALLOW
BLOCK
MONITOR

🌐 Top Talkers

Identifies the most active hosts.

Example:

192.168.1.100
Packets: 72
Bytes: 5468

🚨 Threat Alerts

Displays suspicious traffic detected by the analyzer.

----------------------------------------------------------------------------------------------------------------------------------------------------

🔧 11. Extending the Project
----------------------------------------------------------------------------------------------------------------------------------------------------

This project can be extended in many ways.

Possible improvements:

📡 Real-time packet capture

🤖 Machine learning traffic classification

🦠 Malware signature detection

📊 Web dashboard for monitoring

📉 Packet visualization tools

⚡ Distributed DPI processing

----------------------------------------------------------------------------------------------------------------------------------------------------

🧾 Summary
----------------------------------------------------------------------------------------------------------------------------------------------------

This project demonstrates how Deep Packet Inspection systems work internally.

It provides practical experience with:

📡 Network packet analysis

🔍 Application traffic classification

🛡️ Security rule enforcement

🚨 Threat detection

📊 Network statistics analysis

The project serves as a learning platform for:

Cybersecurity

Network engineering

Packet analysis

Intrusion detection systems

⭐ If you found this project useful, consider giving the repository a star!
