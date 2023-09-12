using System.Collections.Concurrent;
using System.Security.Cryptography;
using System.Text;
using JwtUtils.Exceptions;
using JwtUtils.Pools;
using JwtUtils.Symmetric.Constants;

namespace JwtUtils.Symmetric.Algorithms;

internal static class PooledHmac
{
    private static readonly ConcurrentDictionary<string, Lazy<ObjectPool<HMAC>>> Pool = new();

    public static PoolGuard<HMAC> Get(string algorithm, string tokenSecret)
    {
        var hmacCacheKeyLength = algorithm.Length + tokenSecret.Length;

        var hmacCacheKey = string.Create(hmacCacheKeyLength, (algorithm, tokenSecret), (chars, state) =>
        {
            var (currentAlgorithm, currentTokenSecret) = state;
            
            currentAlgorithm.AsSpan().CopyTo(chars);
            chars = chars[currentAlgorithm.Length..];
            
            currentTokenSecret.AsSpan().CopyTo(chars);
        });

        var pool = Pool.GetOrAdd(hmacCacheKey, _ => new Lazy<ObjectPool<HMAC>>(() => new ObjectPool<HMAC>()));

        return pool.Value.Get(() => Create(algorithm, tokenSecret));
    }

    private static HMAC Create(string algorithm, string tokenSecret)
    {
        return algorithm switch
        {
            SymmetricAlgorithms.Hs256 => new HMACSHA256(Encoding.UTF8.GetBytes(tokenSecret)),
            SymmetricAlgorithms.Hs384 => new HMACSHA384(Encoding.UTF8.GetBytes(tokenSecret)),
            SymmetricAlgorithms.Hs512 => new HMACSHA256(Encoding.UTF8.GetBytes(tokenSecret)),
            _ => throw new JwtUtilsException($"Unknown HMAC algorithm: {algorithm}")
        };
    }
}