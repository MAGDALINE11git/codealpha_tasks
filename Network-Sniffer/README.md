\# Basic Network Sniffer



\## Project Description



Basic Network Sniffer is a Python-based network packet monitoring

and analysis tool built using Scapy.



The application captures network packets in real time and displays

important packet information such as source IP, destination IP,

transport protocol, ports, TCP flags, packet size, and payload

information.



The application also supports packet filtering and basic packet

statistics.



\---



\## Technologies Used



\- Python

\- Scapy

\- Npcap

\- TCP/IP Networking

\- IPv4

\- IPv6



\---



\## Features



\### 1. Real-Time Packet Capture



The application continuously captures network packets.



\### 2. IP Analysis



The sniffer identifies:



\- IPv4

\- IPv6

\- Source IP

\- Destination IP



\### 3. Protocol Detection



The application detects:



\- TCP

\- UDP

\- ICMP

\- ICMPv6

\- ARP



\### 4. Port Analysis



For TCP and UDP packets, the application displays:



\- Source port

\- Destination port



\### 5. TCP Flag Analysis



The application displays TCP flags such as:



\- SYN

\- ACK

\- FIN

\- PSH



\### 6. Payload Analysis



The application displays:



\- Payload length

\- First few bytes of the payload



Encrypted TLS traffic is displayed as raw bytes rather than

decrypted application content.



\### 7. Packet Filtering



The application supports:



1\. All packets

2\. TCP

3\. UDP

4\. ICMP / ICMPv6

5\. HTTPS / TLS

6\. DNS



\### 8. Packet Statistics



The application maintains counts for:



\- Total packets

\- IPv4

\- IPv6

\- ARP

\- TCP

\- UDP

\- ICMP

\- ICMPv6

\- HTTPS/TLS

\- DNS

\- Total bytes



\---



\## Project Architecture



```text

&#x20;                Network

&#x20;                   |

&#x20;                   v

&#x20;             Packet Capture

&#x20;                   |

&#x20;                   v

&#x20;             Scapy / Npcap

&#x20;                   |

&#x20;                   v

&#x20;             Packet Analyzer

&#x20;                   |

&#x20;         +---------+---------+

&#x20;         |         |         |

&#x20;         v         v         v

&#x20;       IPv4      IPv6       ARP

&#x20;         |

&#x20;     +---+---+

&#x20;     |   |   |

&#x20;     v   v   v

&#x20;    TCP UDP ICMP

&#x20;     |

&#x20;     v

&#x20;Source/Destination

&#x20;IPs and Ports

&#x20;     |

&#x20;     v

&#x20;TCP Flags / Payload

&#x20;     |

&#x20;     v

&#x20;Protocol Detection

&#x20;     |

&#x20;     v

&#x20;   Statistics

