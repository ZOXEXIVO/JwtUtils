using System.Collections.Concurrent;
using System.Security.Cryptography;
using System.Text;
using JwtUtils.Exceptions;
using JwtUtils.Symmetric.Constants;
using JwtUtils.Utils.Pools;

namespace JwtUtils.Symmetric.Algorithms;

internal static class PooledHmac
{
    private static readonly ConcurrentDictionary<string, Lazy<ObjectPool<HMAC>>> Pool = new();

    public static PoolGuard<HMAC> Get(string algorithm, string tokenSecret)
    {
        var poolKeyLength = algorithm.Length + tokenSecret.Length + 1;

        var poolKey = string.Create(null, stackalloc char[poolKeyLength], $"{algorithm}.{tokenSecret}");
        
        var pool = Pool.GetOrAdd(poolKey, _ => new Lazy<ObjectPool<HMAC>>(() => new ObjectPool<HMAC>()));

        return pool.Value.Get(() => Create(algorithm, tokenSecret));
    }

    private static HMAC Create(string algorithm, string tokenSecret)
    {
        switch (algorithm)
        {
            case SymmetricAlgorithms.Hs256:
                return new HMACSHA256(Encoding.UTF8.GetBytes(tokenSecret));
            case SymmetricAlgorithms.Hs384:
                return new HMACSHA384(Encoding.UTF8.GetBytes(tokenSecret));
            case SymmetricAlgorithms.Hs512:
                return new HMACSHA256(Encoding.UTF8.GetBytes(tokenSecret));
        }

        throw new JwtUtilsException($"Unknown HMAC algorithm: {algorithm}");
    }
}