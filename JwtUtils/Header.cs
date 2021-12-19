using System.Collections.Concurrent;
using System.Text.Json;
using JwtUtils.Utils.Strings;

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
        return HeadersCache.GetOrAdd(algorithm, CreateInner(algorithm, kid));
            
        static string CreateInner(string algorithm, string kid)
        {
            using var memoryStream = new MemoryStream();

            long dataLength = 0;
            
            using (var jsonWriter = new Utf8JsonWriter(memoryStream))
            {
                jsonWriter.WriteStartObject();
                    
                jsonWriter.WriteString("alg", algorithm);
                jsonWriter.WriteString("typ", "JWT");

                if (!string.IsNullOrWhiteSpace(kid))
                {
                    jsonWriter.WriteString("kid", "kid");
                }
                
                jsonWriter.WriteEndObject();
                    
                jsonWriter.Flush();

                dataLength = jsonWriter.BytesCommitted;
            }

            var buffer = Convert.ToBase64String(memoryStream.GetBuffer(), 0, (int)dataLength);

            // Buffer length + additional space for base64 fixing 
            Span<char> fixedBuffer = stackalloc char[buffer.Length + 2];
            
            buffer.AsSpan().CopyTo(fixedBuffer);

            return fixedBuffer.FixForWeb().ToString();
        }
    }
}