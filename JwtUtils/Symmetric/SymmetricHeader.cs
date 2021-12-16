using System.Collections.Concurrent;
using System.Text.Json;
using JwtUtils.Utils.Strings;

namespace JwtUtils.Symmetric;

internal class SymmetricHeader
{
    private static readonly ConcurrentDictionary<string, string> HeadersCache = new();
        
    /// <summary>
    /// Create fixed for web JwtHeader
    /// No need low-allocation optimizations, because it cached
    /// </summary>
    /// <param name="algorithm"></param>
    /// <returns></returns>
    public static string Create(string algorithm)
    {
        return HeadersCache.GetOrAdd(algorithm, CreateInner);
            
        static string CreateInner(string algorithm)
        {
            using var memoryStream = new MemoryStream();

            long dataLength = 0;
            
            using (var jsonWriter = new Utf8JsonWriter(memoryStream))
            {
                jsonWriter.WriteStartObject();
                    
                jsonWriter.WriteString("alg", algorithm);
                jsonWriter.WriteString("typ", "JWT");
                    
                jsonWriter.WriteEndObject();
                    
                jsonWriter.Flush();

                dataLength = jsonWriter.BytesCommitted;
            }

            var buffer = Convert.ToBase64String(memoryStream.GetBuffer(), 0, (int)dataLength);

            Span<char> fixedBuffer = stackalloc char[buffer.Length + 2];
            
            buffer.AsSpan().CopyTo(fixedBuffer);

            return fixedBuffer.FixForWeb().ToString();
        }
    }
}