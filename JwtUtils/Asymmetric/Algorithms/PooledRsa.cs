using System.Collections.Concurrent;
using System.Security.Cryptography;
using System.Text;
using JwtUtils.Exceptions;
using JwtUtils.Utils.Pools;

namespace JwtUtils.Asymmetric.Algorithms;

internal static class PooledRsa
{
    private static readonly ConcurrentDictionary<string, Lazy<ObjectPool<RSA>>> Pool = new();
    
    public static PoolGuard<RSA> Get(string algorithm, RSA rsa, string privatePemKey)
    {
        var poolKeyLength = algorithm.Length + 1 + privatePemKey.Length;

        var poolKey = string.Create(null, stackalloc char[poolKeyLength], $"{algorithm}.{privatePemKey}");
        
        var pool = Pool.GetOrAdd(poolKey, _ => new Lazy<ObjectPool<RSA>>(() => new ObjectPool<HMAC>()));
    
        return pool.Value.Get(() => Create(algorithm, privatePemKey));
    }
    
    private static RSA Create(string algorithm, string privatePemKey)
    {
        switch (algorithm)
        {
            case "RS256":
                var rsa = RSA.Create("");
                if (rsa == null)
                {
                    throw new JwtUtilsException($"Unknown HMAC algorithm: {algorithm}");
                }
                
                rsa.ImportFromPem(privatePemKey);
                return rsa;
            
            default:
                throw new JwtUtilsException($"Unknown RSA algorithm: {algorithm}");
        }
    }
}