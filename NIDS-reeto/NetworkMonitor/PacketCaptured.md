# (0) WAN Miniport (Network Monitor)
# (1) WAN Miniport (IPv6)
# (2) WAN Miniport (IP)

These are virtual adapters used for VPNs, dial-up, and mobile broadband connections.
They do not have physical MAC addresses.
Their link layer address is 00:00:00:00:00:00, indicating they are virtual.
They usually do not provide actual network connectivity but act as intermediaries for certain types of network traffic.


# (3) Realtek 8852CE WiFi 6E PCI-E NIC: Real Wifi Adapter

You chose: name: [\Device\NPF_{CB574EBC-1AA1-4CB0-B049-E26F51C87599}] 
description: [Realtek 8852CE WiFi 6E PCI-E NIC] 
address: [/192.168.1.5] 
address: [/fe80:0:0:0:bca7:8daa:fc58:d86a] 

link layer address: [[B@6adca536] 
loopBack: [false]] 
up: [true]] 
running: [true]] 
local: [true]
Selected Interface: \Device\NPF_{CB574EBC-1AA1-4CB0-B049-E26F51C87599}


2025-02-22 11:48:36.324217
[data (71 bytes)]
  Hex stream: 20 0c 86 a6 62 10 b8 1e a4 ba 89 75 08 00 45 00 00 39 28 62 40 00 80 11 c1 7b c0 a8 01 05 8e fa c0 2e d0 14 01 bb 00 25 15 c1 45 f6 7e 6f 42 36 27 f1 9b f2 08 f4 1c 4f 81 68 cc 0a d5 d7 37 fb c3 70 b9 32 ef 8f 50

2025-02-22 11:48:36.333815
[data (66 bytes)]
  Hex stream: b8 1e a4 ba 89 75 20 0c 86 a6 62 10 08 00 45 80 00 34 1a 3d 00 00 7c 06 76 b4 40 e9 aa bc c0 a8 01 05 14 6c cd cd 89 6c 9e 2f ab b3 3a 19 80 10 04 17 0d 18 00 00 01 01 05 0a ab b3 3a 18 ab b3 3a 19

2025-02-22 11:48:36.370985
[data (68 bytes)]
  Hex stream: b8 1e a4 ba 89 75 20 0c 86 a6 62 10 08 00 45 80 00 36 00 00 40 00 3d 11 2c 61 8e fa c0 2e c0 a8 01 05 01 bb d0 14 00 22 93 01 4d 9f 5d 62 5c 23 11 a3 ce 16 34 2a c6 63 d3 1c 95 e4 55 b1 93 d7 c8 15 8d f5



# (4) Microsoft Wi-Fi Direct Virtual Adapter #2
# (5) Microsoft Wi-Fi Direct Virtual Adapter

These are virtual adapters used for Wi-Fi Direct, which allows your PC to create a Wi-Fi hotspot or share a connection.
MAC Addresses:
be:1e:a4:ba:89:75
ba:1e:a4:ba:89:75
IP Addresses:
169.254.231.195 (Auto-assigned private IP when no DHCP is available)
169.254.20.231
These are automatically created when Wi-Fi Direct is enabled (e.g., for mobile hotspot).
Expected output:

Captures only local Wi-Fi Direct traffic (if enabled).
May not show much if Wi-Fi Direct is not actively used

# (6) VirtualBox Host-Only Ethernet Adapter



# (7) Adapter for loopback traffic capture

Used for capturing traffic on localhost (127.0.0.1).
MAC Address: 00:00:00:00:00:00
IP Addresses:
127.0.0.1 (Loopback IPv4)
::1 (Loopback IPv6)
Useful for debugging software that communicates internally.
Expected output:

Captures localhost traffic, such as web servers running on 127.0.0.1:5000.
Does not capture real network traffic

# (8) Realtek PCIe GbE Family Controller

This is your physical Ethernet adapter.
MAC Address: 40:c2:ba:38:4e:59
IP Addresses:
169.254.171.155 (Auto-assigned when no DHCP is available)
fe80::1d85:86de:ace9:185c (Link-local IPv6)
The IPv4 address 169.254.x.x suggests that it is disconnected or not assigned an IP by DHCP.
Expected output:

If connected, it captures wired Ethernet traffic.
If not connected, it captures only link-local traffic (e.g., ARP packets).