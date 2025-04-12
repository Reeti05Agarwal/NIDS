//UN NORMALIZED FORM
CREATE TABLE Packet_UNF (
  PacketID INT,
  timestamp TIMESTAMP,
  protocol_type TEXT,

  -- Layer 1
  srcIP TEXT,
  destIP TEXT,
  payloadSize INT,

  -- Layer 2 - Data Link Layer
  srcMAC TEXT,
  destMAC TEXT,
  dataLink_protocolType TEXT,

  -- Layer 3 - Ethernet Header
  frameCheckSeq TEXT,
  etherType TEXT,

  -- Layer 3 - Wi-Fi Header
  bssid TEXT,
  seqControl TEXT,
  frameControl TEXT,

  -- Layer 2 - Network Layer
  net_srcIP TEXT,
  net_destIP TEXT,
  net_protocol TEXT,

  -- Layer 3 - IPv4
  ipv4_ttl INT,
  ipv4_checksum TEXT,
  ipv4_fragmentOffset TEXT,
  ipv4_options TEXT,

  -- Layer 3 - IPv6
  ipv6_flow_label TEXT,
  ipv6_hop_limit INT,
  ipv6_extensionHeaders TEXT,

  -- Layer 2 - Transport Layer
  srcPort INT,
  destPort INT,

  -- Layer 3 - TCP
  tcp_sequenceNum INT,
  tcp_ackNum INT,
  tcp_flags TEXT,
  tcp_windowSize INT,

  -- Layer 3 - UDP
  udp_length INT,
  udp_checksum TEXT,

  -- Layer 3 - ICMP
  icmp_type TEXT,
  icmp_code TEXT,

  -- Layer 2 - Application Layer
  app_protocol TEXT,

  -- Layer 3 - HTTP
  http_method TEXT,
  http_host TEXT,
  http_user_agent TEXT,
  http_auth TEXT,
  http_contentType TEXT,

  -- Layer 3 - DNS
  dns_query_type TEXT,
  dns_response_code TEXT,
  dns_transactionID TEXT,
  dns_flags TEXT,
  dns_question TEXT,

  -- Layer 3 - TLS
  tls_version TEXT,
  tls_handshake_type TEXT,
  tls_contentType TEXT
);

//anomalies in 1 NF
1. Insertion Anomalies:
An insertion anomaly happens when it is difficult to insert data into the database without introducing inconsistency or redundancy.

Examples:
Adding a new packet: If we want to insert a new network packet, we must insert data into multiple tables (like Packet_Metadata, Data_Link_Layer, Network_Layer, etc.). If we are missing data for a certain header (e.g., no transport layer data for this packet), it would be hard to insert the new row in the table, or we might end up with redundant or incomplete data.

Adding an application header: If a new packet is HTTP but doesn’t yet have an HTTP header, inserting just the packet metadata without any application layer data would create an incomplete or empty record in the application layer table, which may violate data integrity.

2. Deletion Anomalies:
A deletion anomaly occurs when deleting data can lead to unintentional loss of other valuable information.

Example:
Deleting a packet: If a packet is deleted from the Packet_Metadata table, the associated rows in the other tables (Data_Link_Layer, Transport_Layer, HTTP_Header, etc.) would also need to be deleted to maintain consistency. If not, those rows would remain as orphaned data, leading to inconsistent state or even data loss for other headers or layers that were not supposed to be deleted.

Deleting transport layer data: If a packet’s transport layer information (like TCP or UDP header) is removed, the related packet record may still be in the system, causing inconsistency where you have metadata without a corresponding transport layer record.

3. Update Anomalies:
An update anomaly happens when a change in the data leads to inconsistency in the database.

Examples:
Changing Protocol Type: If the Protocol_Type (e.g., TCP or UDP) is updated in the Packet_Metadata table, you would need to update the protocol type across all relevant rows in the related tables (e.g., Transport_Layer, TCP_Header, UDP_Header). If any row is missed, you end up with inconsistent data.

Changing MAC Address: If the SrcMAC or DestMAC address is updated in the Data_Link_Layer table, you would need to make sure that the changes propagate correctly to avoid discrepancies across multiple packets.

IP Address Changes: If there is a change in the SrcIP or DestIP in Packet_Metadata or Network_Layer, all related records for that packet should be updated across the database. If not, you might have inconsistent IPs across the layers.

4. Redundancy (Data Duplication):
Since the data is still partially redundant in the 1NF form (especially across layers), duplication of information can occur. This can lead to unnecessary data storage and potential inconsistencies.

Examples:
Duplicated Layer Information: The same data (e.g., SrcIP, DestIP) is stored in multiple layers (e.g., Network_Layer and Packet_Metadata). If any of these columns is updated in one table but not in the others, there can be data inconsistencies.

Repeated Protocol Data: For example, ProtocolType may be stored in multiple tables, including Data_Link_Layer, Network_Layer, Transport_Layer, etc. Any change in protocol type needs to be reflected across all of these tables to avoid inconsistency.

5. Inconsistent Data:
When redundant data is not properly synchronized, inconsistencies can occur, especially if there is no enforcement of foreign key constraints or cascading updates/deletes.

Examples:
Inconsistent Protocol Information: If a packet’s Protocol_Type is different in Packet_Metadata than in Transport_Layer, you may have inconsistent data about the packet's protocol across multiple layers.

Disjointed Layer Data: If some layers (e.g., Data_Link_Layer, Application_Layer) don’t have corresponding entries in other layers (e.g., missing TCP_Header for a packet marked as TCP), this can lead to inconsistent or fragmented data, where the packet data is incomplete.


// 2NF 

Converting Tables to 2NF:
1. Packet_Metadata:
Attributes: PacketID, timestamp, protocol_type, srcIP, DestIP, payloadSize.

The PacketID uniquely identifies each record, so all attributes depend entirely on PacketID.

No partial dependencies exist here, so this table is already in 2NF.

2. Data_Link_Layer:
Attributes: PacketID, srcMAC, destMAC, protocolType.

Partial Dependency:

srcMAC, destMAC, and protocolType depend on PacketID and srcMAC.

PacketID uniquely identifies the record, so we need to break out dependencies that only rely on srcMAC.

Solution: Create two tables to remove partial dependencies:

Table 1: Packet_Data_Link

Attributes: PacketID, protocolType

PacketID uniquely identifies the protocol type. No partial dependency.

Table 2: Packet_MAC_Address

Attributes: PacketID, srcMAC, destMAC

Now srcMAC and destMAC are no longer partially dependent on PacketID. The new primary key is a combination of PacketID and srcMAC.

3. Network_Layer:
Attributes: PacketID, srcIP, destIP, Protocol.

All attributes depend entirely on PacketID.

Since no partial dependencies are present, the Network_Layer table is already in 2NF.

4. Transport_Layer:
Attributes: PacketID, srcPort, destPort, Protocol, sequenceNum, ackNum, flags, windowSize.

Partial Dependency:

Attributes like sequenceNum, ackNum, etc., depend on PacketID, srcPort, and destPort.

Solution: Since PacketID, srcPort, and destPort together identify the transport layer record, there are no partial dependencies. This table is already in 2NF.

5. Application_Layer:
Attributes: PacketID, App_Protocol, http_method, host, user_agent, auth, content_type.

All attributes depend on PacketID.

There are no partial dependencies, so this table is already in 2NF.

Final Schema in 2NF:
Packet_Metadata (already in 2NF)

PacketID, timestamp, protocol_type, srcIP, DestIP, payloadSize.

Packet_Data_Link (no partial dependency)

PacketID, protocolType.

Packet_MAC_Address (eliminated partial dependency)

PacketID, srcMAC, destMAC.

Network_Layer (already in 2NF)

PacketID, srcIP, destIP, Protocol.

Transport_Layer (already in 2NF)

PacketID, srcPort, destPort, Protocol, sequenceNum, ackNum, flags, windowSize.

Application_Layer (already in 2NF)

PacketID, App_Protocol, http_method, host, user_agent, auth, content_type.

ANOMALIES OCCURING IN 2NF: 
1. Insertion Anomalies
An insertion anomaly occurs when you are unable to add data to the database without adding unnecessary or redundant information.

Example:
If you want to insert a new packet record into the Packet_Metadata table, but you don't have information for the protocolType, srcMAC, or destMAC, you might need to leave some fields null or insert irrelevant data just to comply with the schema.

For example:

If a new packet comes in with only PacketID and srcIP, you would need to insert this information into Packet_Metadata without having srcMAC and destMAC, leading to incomplete or redundant entries in other tables.

Solution: This can be mitigated by making sure the data model properly captures the relationships between attributes so that new data can be inserted in a meaningful way, ensuring relationships are respected.

2. Update Anomalies
An update anomaly occurs when data is updated in one place but not in all places where it is stored, leading to inconsistency.

Example:

In Packet_MAC_Address, if srcMAC and destMAC are updated, they would need to be updated in both the Packet_Data_Link and Packet_MAC_Address tables, as well as other places if needed.

Similarly, if a packet's protocolType changes, it needs to be updated in both the Packet_Data_Link and Packet_Metadata tables. If only one table is updated and not the other, it will cause data inconsistency.

Solution: Ensure that the appropriate foreign keys and constraints are set up to keep the data synchronized, and make use of triggers or stored procedures to automate updates when necessary.

3. Deletion Anomalies
A deletion anomaly happens when the deletion of one piece of data results in the loss of other important, non-redundant data.

Example:

If you delete a record from the Packet_Metadata table, you might lose associated information in related tables like Packet_MAC_Address or Packet_Data_Link because of the dependency on PacketID.

Deleting a packet record might inadvertently result in losing vital data about its srcMAC, destMAC, or protocolType from the Packet_MAC_Address and Packet_Data_Link tables.

Solution: To avoid deletion anomalies, referential integrity constraints and cascading deletes can be used. However, caution should be exercised when using cascading deletes to ensure that you don't accidentally lose data that is not directly related.

//3NF:
Looking at all the tables, we can see that there are no transitive dependencies in this schema, and all non-key attributes are directly dependent on the primary key. Therefore, the database is already in 3NF.
ANOMALIES IN 3NF: 
1. Insertion Anomalies
An insertion anomaly occurs when you cannot add data to the database without needing to add unnecessary or redundant information. Even in 3NF, some situations can still lead to insertion issues:

Missing Information: If you want to insert a new packet record (say, in Packet_Metadata), you may have to insert data in other tables, such as Data_Link_Layer, Transport_Layer, etc., if those tables require data for the foreign keys. If, for example, you don't have a srcMAC and destMAC for a packet yet, you cannot insert a record into the Data_Link_Layer table without violating referential integrity, leading to an insertion anomaly.

Example: If a new packet has only metadata (like PacketID, timestamp, etc.) but no data yet for srcMAC or destMAC (or for any other related table), you would not be able to insert this data into Data_Link_Layer, causing issues.

How to mitigate: You could make these fields nullable if they are not mandatory at the time of the initial packet capture or use default values to allow partial insertions.

2. Update Anomalies
Update anomalies occur when a change to data in one place requires multiple updates elsewhere. This happens if data is duplicated across multiple rows in a way that requires careful synchronization of updates to ensure data integrity.

Example: If you need to change the protocol_type or srcIP in the Packet_Metadata table, this change might need to propagate across many related records in other tables like Data_Link_Layer, Transport_Layer, etc., if there are any foreign key dependencies or if the PacketID is used in multiple places.

For example, if a certain protocol type is associated with multiple PacketIDs across different tables, and if you update the protocol_type in the Packet_Metadata table, you may need to update all relevant instances in other tables.

If these updates are not done properly, there could be inconsistencies in the data.

How to mitigate: To avoid update anomalies, you could use cascading updates for foreign key constraints. This would allow automatic updates to related tables when a change is made to the primary key or an important attribute. However, this approach needs careful planning to ensure it doesn't lead to unexpected behaviors.

3. Deletion Anomalies
A deletion anomaly occurs when deleting a record from one table inadvertently causes the loss of valuable information in another table.

Example: If you delete a record in the Packet_Metadata table, you might inadvertently remove information related to the packet in other tables, such as Data_Link_Layer, Transport_Layer, or Application_Layer, since they depend on PacketID (foreign key).

Example: Deleting a packet's metadata (PacketID) from the Packet_Metadata table would delete the record from all related tables (e.g., Ethernet_Header, IPv4_Header, TCP_Header, etc.), even though the associated data might still be useful for historical analysis, or you might want to keep records for auditing purposes.

How to mitigate: Use cascading deletes to automatically remove related data, but carefully review which data should truly be deleted and which should be preserved. Alternatively, you could use soft deletes, where records are marked as deleted but not actually removed from the database, ensuring that valuable data is not accidentally lost.



