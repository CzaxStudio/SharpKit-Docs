# PacketCrafter

Raw packet construction and basic network scanning. Builds properly framed ARP, DNS, TCP, and UDP packets with correct checksums. Uses `System.Net.Sockets` only — no raw socket library, no external dependencies.

---

## Enums

### `EtherType`

Ethernet frame type field values.

| Value | Constant | Description |
|---|---|---|
| `0x0800` | `IPv4` | IPv4 payload. |
| `0x86DD` | `IPv6` | IPv6 payload. |
| `0x0806` | `ARP` | ARP payload. |
| `0x8100` | `VLAN` | 802.1Q VLAN tag. |

---

### `ArpOperation`

ARP operation codes.

| Value | Constant | Description |
|---|---|---|
| `1` | `Request` | Who has this IP? Tell me. |
| `2` | `Reply` | I have that IP; here's my MAC. |

---

### `IpProtocol`

IP protocol number field.

| Value | Constant | Description |
|---|---|---|
| `1` | `ICMP` | |
| `6` | `TCP` | |
| `17` | `UDP` | |

---

### `DnsType`

DNS query/record types.

| Value | Constant | Description |
|---|---|---|
| `1` | `A` | IPv4 address. |
| `2` | `NS` | Name server. |
| `5` | `CNAME` | Canonical name alias. |
| `6` | `SOA` | Start of authority. |
| `12` | `PTR` | Reverse lookup. |
| `15` | `MX` | Mail exchange. |
| `16` | `TXT` | Text record. |
| `28` | `AAAA` | IPv6 address. |
| `255` | `ANY` | Any type. |

---

### `TcpFlags`

TCP control bits. This is a `[Flags]` enum so values can be OR'd together.

| Value | Constant | Description |
|---|---|---|
| `0x01` | `FIN` | No more data from sender. |
| `0x02` | `SYN` | Synchronize sequence numbers. |
| `0x04` | `RST` | Reset the connection. |
| `0x08` | `PSH` | Push buffered data. |
| `0x10` | `ACK` | Acknowledgment field is valid. |
| `0x20` | `URG` | Urgent pointer field is valid. |

---

## ARP Methods

### `BuildArpRequest(PhysicalAddress senderMac, IPAddress senderIp, IPAddress targetIp)`

Builds a 42-byte ARP request frame (14-byte Ethernet header + 28-byte ARP body). The destination MAC in the Ethernet header is set to the broadcast address (`FF:FF:FF:FF:FF:FF`). The target MAC in the ARP body is zeroed out, as it should be for a request.

```csharp
var myMac = NetworkInterface.GetAllNetworkInterfaces()
    .First(i => i.OperationalStatus == OperationalStatus.Up)
    .GetPhysicalAddress();

var frame = PacketCrafter.BuildArpRequest(
    myMac,
    IPAddress.Parse("192.168.1.50"),
    IPAddress.Parse("192.168.1.1"));

// send raw via a layer-2 socket or write to a capture file
```

---

### `BuildArpReply(PhysicalAddress senderMac, IPAddress senderIp, PhysicalAddress targetMac, IPAddress targetIp)`

Builds a 42-byte ARP reply frame. The Ethernet destination is set to `targetMac`, and the ARP operation field is set to `2` (reply). Use this for gratuitous ARP or ARP poisoning.

```csharp
// Tell 192.168.1.100 that 192.168.1.1 is at our MAC
var reply = PacketCrafter.BuildArpReply(
    myMac,
    IPAddress.Parse("192.168.1.1"),        // we're claiming to be this IP
    PhysicalAddress.Parse("AA-BB-CC-DD-EE-FF"),  // target's real MAC
    IPAddress.Parse("192.168.1.100"));
```

---

## DNS Methods

### `BuildDnsQuery(string hostname, DnsType queryType, ushort transactionId)`

Builds a DNS query packet (UDP payload only — no IP or UDP headers). The hostname is label-encoded per RFC 1035. If `transactionId` is `0`, a random ID is generated.

```csharp
// Standard A record query
var query = PacketCrafter.BuildDnsQuery("target.corp.local", DnsType.A);

// MX query with fixed transaction ID for tracking
var query = PacketCrafter.BuildDnsQuery("corp.local", DnsType.MX, 0x1234);

// Reverse lookup
var query = PacketCrafter.BuildDnsQuery("1.1.168.192.in-addr.arpa", DnsType.PTR);
```

The returned bytes can be sent directly via `UdpClient.Send` or used as the payload in `BuildUdpPacket`.

---

### `BuildDnsResponse(byte[] query, IPAddress[] answers)`

Takes an existing DNS query buffer and builds a response by appending A record answer sections. The transaction ID and question section are copied from the query. The flags are set to `0x8180` (standard query response, recursion available).

```csharp
var query = PacketCrafter.BuildDnsQuery("target.corp.local");
var response = PacketCrafter.BuildDnsResponse(query, new[]
{
    IPAddress.Parse("10.10.10.10"),
    IPAddress.Parse("10.10.10.11")
});
```

Each answer has a TTL of 60 seconds hardcoded. Throws `ArgumentException` if the query is shorter than 12 bytes.

---

### `SendDnsQueryAsync(string hostname, IPAddress dnsServer, int port, DnsType queryType, CancellationToken ct)`

Builds a DNS query and sends it over UDP to the given DNS server. Waits up to 3 seconds for a response. Returns `true` if a valid DNS response (QR bit set) was received.

```csharp
var resolved = await PacketCrafter.SendDnsQueryAsync(
    "target.corp.local",
    IPAddress.Parse("192.168.1.1"),
    queryType: DnsType.A);

Console.WriteLine(resolved ? "Got a response" : "No response");
```

This doesn't parse the response — it just confirms one arrived. If you need the answer records, use `BuildDnsQuery` and send/receive manually.

---

## TCP Methods

### `BuildTcpSyn(IPAddress srcIp, IPAddress dstIp, ushort srcPort, ushort dstPort, uint sequenceNumber)`

Builds a complete IP + TCP SYN packet (40 bytes — 20-byte IP header + 20-byte TCP header, no options). The IP and TCP checksums are computed inline. If `sequenceNumber` is `0`, a random ISN is chosen.

```csharp
var syn = PacketCrafter.BuildTcpSyn(
    IPAddress.Parse("10.0.0.5"),
    IPAddress.Parse("10.0.0.1"),
    srcPort: 54321,
    dstPort: 443);
```

The returned bytes are a raw IP packet. To send it, you need a raw socket with `SocketType.Raw` and `ProtocolType.IP` (requires elevated privileges on Windows, and `IP_HDRINCL` socket option on Linux).

---

### `BuildTcpSynAck(IPAddress srcIp, IPAddress dstIp, ushort srcPort, ushort dstPort, uint seqNumber, uint ackNumber)`

Builds a SYN-ACK packet. TCP flags are `SYN | ACK` (`0x12`). Used for crafting handshake responses.

```csharp
var synAck = PacketCrafter.BuildTcpSynAck(
    IPAddress.Parse("10.0.0.1"),
    IPAddress.Parse("10.0.0.5"),
    srcPort: 443,
    dstPort: 54321,
    seqNumber: 0x12345678,
    ackNumber: clientIsn + 1);
```

---

### `BuildTcpRst(IPAddress srcIp, IPAddress dstIp, ushort srcPort, ushort dstPort, uint seqNumber)`

Builds a TCP RST packet. Useful for tearing down connections or generating RST-based scan responses.

```csharp
var rst = PacketCrafter.BuildTcpRst(
    IPAddress.Parse("10.0.0.1"),
    IPAddress.Parse("10.0.0.5"),
    srcPort: 443,
    dstPort: 54321,
    seqNumber: 0x12345679);
```

---

## UDP Method

### `BuildUdpPacket(IPAddress srcIp, IPAddress dstIp, ushort srcPort, ushort dstPort, byte[] payload)`

Builds a complete IP + UDP packet with the given payload. Computes the UDP checksum using a pseudo-header as required by RFC 768.

```csharp
var dnsPayload = PacketCrafter.BuildDnsQuery("target.corp.local");
var udpPacket = PacketCrafter.BuildUdpPacket(
    IPAddress.Parse("10.0.0.5"),
    IPAddress.Parse("10.0.0.1"),
    srcPort: 12345,
    dstPort: 53,
    payload: dnsPayload);
```

---

## Scanning

### `TcpSynScanAsync(IPAddress target, IEnumerable<ushort> ports, IPAddress sourceIp, TimeSpan timeout, CancellationToken ct)`

Scans a list of ports by attempting a non-blocking TCP connect to each one. Returns a `List<ushort>` of ports that accepted the connection. Ports that actively refused (RST) are skipped. Ports that timed out are retried once with the given timeout before being marked closed.

```csharp
var openPorts = await PacketCrafter.TcpSynScanAsync(
    IPAddress.Parse("10.0.0.1"),
    Enumerable.Range(1, 1024).Select(p => (ushort)p),
    IPAddress.Parse("10.0.0.5"),
    timeout: TimeSpan.FromMilliseconds(500));

Console.WriteLine($"Open: {string.Join(", ", openPorts)}");
```

This uses `Socket.ConnectAsync` rather than raw SYN packets, so it completes the full TCP handshake. It's less stealthy than a pure SYN scan but works without elevated privileges. Scanning speed is bounded by `timeout` × number of ports in the worst case — pass a short timeout (200–500ms) to keep it fast on local networks.

To avoid being killed by the `CancellationToken` midway through a large scan, set the token deadline generously:

```csharp
var cts = new CancellationTokenSource(TimeSpan.FromMinutes(5));
var open = await PacketCrafter.TcpSynScanAsync(target, ports, src, TimeSpan.FromMilliseconds(300), cts.Token);
```

---

## Checksum Behavior

IP and TCP/UDP checksums are computed using the standard one's complement algorithm. The IP header checksum covers the IP header only. The TCP/UDP checksum covers a 12-byte pseudo-header (src IP, dst IP, zero byte, protocol, segment length) concatenated with the TCP/UDP header and payload.

All checksums are written into the packet before the byte array is returned — the output is always a valid, checksum-correct packet.
