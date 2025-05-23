using System.Collections.Concurrent;
using System.Text;
using JwtUtils.Json;
using JwtUtils.Utils;

namespace JwtUtils;

internal class Header
{
    private static readonly ConcurrentDictionary<string, string> HeadersCache = new();
    
    /// <summary>
    /// Create fixed for web JwtHeader
    /// No need low-allocation optimizations, because it cached
    /// </summary>
    /// <param name="algorithm"></param>
    /// <param name="kid">JWT Key id</param>
    /// <returns></returns>
    public static string Create(string algorithm, string kid = null)
    {
        var cacheKey = string.IsNullOrWhiteSpace(kid) ? algorithm : $"{algorithm}:{kid}";
        return HeadersCache.GetOrAdd(cacheKey, _ => CreateInner(algorithm, kid));
    }
        
    private static string CreateInner(string algorithm, string kid)
    {
        // Create header object
        var header = new Dictionary<string, object>
        {
            ["alg"] = algorithm,
            ["typ"] = "JWT"
        };

        if (!string.IsNullOrWhiteSpace(kid))
        {
            header["kid"] = kid;
        }

        // Serialize to JSON using our custom serializer
        var jsonHeader = SimpleJson.Serialize(header);
        
        // Convert to bytes and then to base64
        var jsonBytes = Encoding.UTF8.GetBytes(jsonHeader);
        var base64Header = Convert.ToBase64String(jsonBytes);

        // Buffer length + additional space for base64 fixing 
        Span<char> fixedBuffer = stackalloc char[base64Header.Length + 2];
        
        base64Header.AsSpan().CopyTo(fixedBuffer);

        return fixedBuffer.FixForWeb().ToString();
    }
}