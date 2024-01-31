using System.Buffers;
using System.Collections.Concurrent;
using System.Text.Json;
using JwtUtils.Exceptions;
using JwtUtils.Utils;
using Microsoft.IO;

namespace JwtUtils;

internal class Header
{
    private static readonly ConcurrentDictionary<string, string> HeadersCache = new();

    private const int BlockSize = 1024;
    private const int LargeBufferMultiple = 1024 * 1024;
    private const int MaximumBufferSize = 16 * LargeBufferMultiple;
    private const int MaximumFreeLargePoolBytes = MaximumBufferSize * 4;
    private const int MaximumFreeSmallPoolBytes = 250 * BlockSize;
    
    private static readonly RecyclableMemoryStreamManager.Options Options = new(
        BlockSize, 
        LargeBufferMultiple, 
        MaximumBufferSize, 
        MaximumFreeLargePoolBytes, 
        MaximumFreeSmallPoolBytes)
    {
        AggressiveBufferReturn = true,
        GenerateCallStacks = false
    };
    
    private static readonly RecyclableMemoryStreamManager PoolManager = new(Options); 
    
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
            using var pooledOutputStream = PoolManager.GetStream();

            long dataLength;
            
            using (var jsonWriter = new Utf8JsonWriter((IBufferWriter<byte>)pooledOutputStream))
            {
                jsonWriter.WriteStartObject();
                    
                jsonWriter.WriteString("alg", algorithm);
                jsonWriter.WriteString("typ", "JWT");

                if (!string.IsNullOrWhiteSpace(kid))
                {
                    jsonWriter.WriteString("kid", kid);
                }
                
                jsonWriter.WriteEndObject();
                    
                jsonWriter.Flush();

                dataLength = jsonWriter.BytesCommitted;
            }

            var buffer = Convert.ToBase64String(pooledOutputStream.GetBuffer(), 0, (int)dataLength);

            // Buffer length + additional space for base64 fixing 
            Span<char> fixedBuffer = stackalloc char[buffer.Length + 2];
            
            buffer.AsSpan().CopyTo(fixedBuffer);

            return fixedBuffer.FixForWeb().ToString();
        }
    }
}