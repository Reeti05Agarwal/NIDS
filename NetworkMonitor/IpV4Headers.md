IpV4Packet{
  header=IpV4Header{
    version=4,
    IHL=5,
    TOS=0x00,
    totalLength=60,
    identification=12345,
    flags=DF,
    fragmentOffset=0,
    TTL=64,
    protocol=TCP(6),
    headerChecksum=0x1a2b,
    srcAddr=192.168.1.100,
    dstAddr=192.168.1.1
  },
  payload=TcpPacket{ ... }
}


header=IpV4Header{} → The IPv4 header containing:

version=4 → IPv4 packet
IHL=5 → Header length (usually 5 for 20-byte headers)
TOS=0x00 → Type of Service
totalLength=60 → Total packet length
identification=12345 → Packet ID
flags=DF → "Don't Fragment" flag
fragmentOffset=0 → No fragmentation
TTL=64 → Time to Live
protocol=TCP(6) → Encapsulated protocol (TCP in this case)
headerChecksum=0x1a2b → Header checksum
srcAddr=192.168.1.100 → Source IP
dstAddr=192.168.1.1 → Destination IP
payload=TcpPacket{ ... } → The payload, which contains the encapsulated TCP packet.