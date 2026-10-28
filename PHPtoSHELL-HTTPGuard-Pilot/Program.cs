using System.Buffers;
using System.Net;
using Microsoft.AspNetCore.WebUtilities;
using Microsoft.Net.Http.Headers;

const long maxBodyBytes = 16L * 1024 * 1024;
const int maxParts = 128;
const int maxPartHeaders = 32;
const int maxPartHeaderBytes = 8192;
const int maxFieldNesting = 8;

var listenText = Environment.GetEnvironmentVariable("HTTPGUARD_LISTEN") ?? "http://127.0.0.1:18080";
var upstreamText = Environment.GetEnvironmentVariable("HTTPGUARD_UPSTREAM") ?? "http://127.0.0.1:8080";
if (!Uri.TryCreate(listenText, UriKind.Absolute, out var listen) || listen.Scheme != "http" ||
    !Uri.TryCreate(upstreamText, UriKind.Absolute, out var upstream) || upstream.Scheme != "http" ||
    listen.AbsolutePath != "/" || listen.Query.Length != 0 || listen.Fragment.Length != 0 ||
    upstream.AbsolutePath != "/" || upstream.Query.Length != 0 || upstream.Fragment.Length != 0 ||
    listen.UserInfo.Length != 0 || upstream.UserInfo.Length != 0 ||
    listen.Port == upstream.Port &&
    (listen.Host == upstream.Host ||
     IsLoopbackHost(listen.Host) && IsLoopbackHost(upstream.Host) ||
     IPAddress.TryParse(listen.Host, out var listenAddress) &&
     (listenAddress.Equals(IPAddress.Any) || listenAddress.Equals(IPAddress.IPv6Any))))
    throw new InvalidOperationException("Use distinct absolute HTTP listen and upstream URLs.");
var loopback = IsLoopbackHost(listen.Host);
if (!loopback && Environment.GetEnvironmentVariable("HTTPGUARD_ALLOW_REMOTE_LISTEN") != "1")
    throw new InvalidOperationException("Remote listening requires explicit HTTPGUARD_ALLOW_REMOTE_LISTEN=1.");

var builder = WebApplication.CreateBuilder(args);
builder.WebHost.UseUrls(listen.ToString());
builder.WebHost.ConfigureKestrel(options =>
{
    options.AddServerHeader = false;
    options.Limits.MaxRequestBodySize = maxBodyBytes;
    options.Limits.MaxRequestHeadersTotalSize = 64 * 1024;
    options.Limits.MaxRequestHeaderCount = 100;
    options.Limits.MaxRequestLineSize = 8 * 1024;
});
var app = builder.Build();
var client = new HttpClient(new SocketsHttpHandler
{
    AllowAutoRedirect = false,
    UseProxy = false,
    UseCookies = false,
    AutomaticDecompression = DecompressionMethods.None,
    PooledConnectionLifetime = TimeSpan.FromMinutes(2)
}) { Timeout = TimeSpan.FromSeconds(60) };

var activeRequests = new SemaphoreSlim(16, 16);
app.Use(async (context, next) =>
{
    if (context.Request.Path == "/_phptoshell/health")
    {
        await next(context);
        return;
    }
    if (!await activeRequests.WaitAsync(0, context.RequestAborted))
    {
        context.Response.StatusCode = StatusCodes.Status503ServiceUnavailable;
        context.Response.Headers.RetryAfter = "1";
        return;
    }
    try { await next(context); }
    finally { activeRequests.Release(); }
});
app.Run(async context =>
{
    if (context.Request.Method == "GET" && context.Request.Path == "/_phptoshell/health")
    {
        context.Response.ContentType = "text/plain";
        context.Response.Headers.CacheControl = "no-store";
        await context.Response.WriteAsync("pilot-ready", context.RequestAborted);
        return;
    }
    if (context.WebSockets.IsWebSocketRequest || context.Request.Headers.ContainsKey("Upgrade"))
    {
        context.Response.StatusCode = StatusCodes.Status501NotImplemented;
        return;
    }
    if (context.Request.ContentLength is > maxBodyBytes)
    {
        context.Response.StatusCode = StatusCodes.Status413PayloadTooLarge;
        return;
    }
    if (context.Request.ContentType?.StartsWith("multipart/form-data", StringComparison.OrdinalIgnoreCase) == true)
    {
        if (!MediaTypeHeaderValue.TryParse(context.Request.ContentType, out var contentType) ||
            !contentType.Boundary.HasValue || contentType.Boundary.Value.Length is < 1 or > 200)
        {
            context.Response.StatusCode = StatusCodes.Status400BadRequest;
            return;
        }
        context.Request.EnableBuffering(bufferThreshold: 64 * 1024, bufferLimit: maxBodyBytes);
        var boundary = HeaderUtilities.RemoveQuotes(contentType.Boundary).Value!;
        if (string.IsNullOrWhiteSpace(boundary) || boundary.Length > 200)
        {
            context.Response.StatusCode = StatusCodes.Status400BadRequest;
            return;
        }
        var reader = new MultipartReader(boundary, context.Request.Body)
        {
            HeadersCountLimit = maxPartHeaders,
            HeadersLengthLimit = maxPartHeaderBytes,
            BodyLengthLimit = maxBodyBytes
        };
        var count = 0;
        var buffer = ArrayPool<byte>.Shared.Rent(8192);
        try
        {
            MultipartSection? section;
            while ((section = await reader.ReadNextSectionAsync(context.RequestAborted)) is not null)
            {
                if (++count > maxParts) throw new InvalidDataException("Too many multipart parts.");
                if (ContentDispositionHeaderValue.TryParse(section.ContentDisposition, out var disposition))
                {
                    var name = HeaderUtilities.RemoveQuotes(disposition.Name).Value ?? "";
                    if (name.Count(ch => ch == '[') > maxFieldNesting)
                        throw new InvalidDataException("Multipart field nesting limit exceeded.");
                }
                while (await section.Body.ReadAsync(buffer.AsMemory(), context.RequestAborted) > 0) { }
            }
            context.Request.Body.Position = 0;
        }
        catch (InvalidDataException)
        {
            context.Response.StatusCode = StatusCodes.Status413PayloadTooLarge;
            return;
        }
        catch (IOException)
        {
            context.Response.StatusCode = StatusCodes.Status413PayloadTooLarge;
            return;
        }
        finally { ArrayPool<byte>.Shared.Return(buffer); }
    }

    // Uri(base, untrustedPath) would accept an absolute URI and change the upstream host.
    var target = new UriBuilder(upstream)
    {
        Path = context.Request.Path.Value ?? "/",
        Query = context.Request.QueryString.HasValue ? context.Request.QueryString.Value![1..] : ""
    }.Uri;
    using var request = new HttpRequestMessage(new HttpMethod(context.Request.Method), target);
    request.Headers.ConnectionClose = Environment.GetEnvironmentVariable("HTTPGUARD_TEST_REUSE") != "1";
    if (context.Request.ContentLength.HasValue || context.Request.Headers.ContainsKey("Transfer-Encoding") ||
        context.Request.Headers.ContainsKey("Content-Type"))
        request.Content = new StreamContent(context.Request.Body);
    var requestConnectionTokens = context.Request.Headers.Connection.ToString()
        .Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
        .ToHashSet(StringComparer.OrdinalIgnoreCase);
    foreach (var header in context.Request.Headers)
    {
        if (IsHopByHop(header.Key) || requestConnectionTokens.Contains(header.Key) ||
            header.Key.Equals("Host", StringComparison.OrdinalIgnoreCase) ||
            IsClientProxyIdentityHeader(header.Key)) continue;
        if (!request.Headers.TryAddWithoutValidation(header.Key, header.Value.ToArray()))
            request.Content?.Headers.TryAddWithoutValidation(header.Key, header.Value.ToArray());
    }
    if (context.Connection.RemoteIpAddress is { } remoteIp)
        request.Headers.TryAddWithoutValidation("X-Forwarded-For", remoteIp.ToString());
    try
    {
        using var response = await client.SendAsync(request, HttpCompletionOption.ResponseHeadersRead,
                                                     context.RequestAborted);
        context.Response.StatusCode = (int)response.StatusCode;
        var responseConnectionTokens = response.Headers.Connection.ToHashSet(StringComparer.OrdinalIgnoreCase);
        foreach (var header in response.Headers)
            if (!IsHopByHop(header.Key) && !responseConnectionTokens.Contains(header.Key))
                context.Response.Headers.Append(header.Key, header.Value.ToArray());
        foreach (var header in response.Content.Headers)
            if (!IsHopByHop(header.Key) && !responseConnectionTokens.Contains(header.Key))
                context.Response.Headers.Append(header.Key, header.Value.ToArray());
        await response.Content.CopyToAsync(context.Response.Body, context.RequestAborted);
    }
    catch (HttpRequestException error)
    {
        app.Logger.LogWarning("Upstream request failed: {Category}; inner={InnerType}",
                              error.HttpRequestError, error.InnerException?.GetType().Name ?? "none");
        if (error.GetBaseException() is System.Net.Sockets.SocketException socketError)
            app.Logger.LogWarning("Upstream socket error: {Code}", socketError.NativeErrorCode);
        if (Environment.GetEnvironmentVariable("HTTPGUARD_TEST_DIAGNOSTICS") == "1")
            app.Logger.LogWarning(error, "Synthetic test transport diagnostics enabled");
        if (!context.Response.HasStarted) context.Response.StatusCode = StatusCodes.Status502BadGateway;
    }
});

app.Run();

static bool IsHopByHop(string name) => name.Equals("Connection", StringComparison.OrdinalIgnoreCase) ||
    name.Equals("Transfer-Encoding", StringComparison.OrdinalIgnoreCase) ||
    name.Equals("Keep-Alive", StringComparison.OrdinalIgnoreCase) ||
    name.Equals("Proxy-Authenticate", StringComparison.OrdinalIgnoreCase) ||
    name.Equals("Proxy-Authorization", StringComparison.OrdinalIgnoreCase) ||
    name.Equals("TE", StringComparison.OrdinalIgnoreCase) ||
    name.Equals("Trailer", StringComparison.OrdinalIgnoreCase) ||
    name.Equals("Upgrade", StringComparison.OrdinalIgnoreCase);

static bool IsClientProxyIdentityHeader(string name) => name.Equals("X-Forwarded-For", StringComparison.OrdinalIgnoreCase) ||
    name.Equals("Forwarded", StringComparison.OrdinalIgnoreCase) ||
    name.Equals("X-Real-IP", StringComparison.OrdinalIgnoreCase) ||
    name.Equals("X-Forwarded-Host", StringComparison.OrdinalIgnoreCase) ||
    name.Equals("X-Forwarded-Proto", StringComparison.OrdinalIgnoreCase);

static bool IsLoopbackHost(string host) => host.Equals("localhost", StringComparison.OrdinalIgnoreCase) ||
    IPAddress.TryParse(host, out var address) && IPAddress.IsLoopback(address);

