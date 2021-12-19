using System.Collections.Concurrent;
using System.Security.Cryptography;
using JwtUtils.Utils.Pools;

namespace JwtUtils.Asymmetric.Algorithms;

internal static class PooledRsa
{
    private static readonly ConcurrentDictionary<string, Lazy<ObjectPool<RSA>>> Pool = new();
    
    public static PoolGuard<RSA> Get(string privateKey)
    {
        var pool = Pool.GetOrAdd(privateKey, _ => new Lazy<ObjectPool<RSA>>(() => new ObjectPool<RSA>()));
    
        return pool.Value.Get(() => Create(privateKey));
    }
    
    private static RSA Create(string privatePemKey)
    {
        var rsa = RSA.Create();
        rsa.ImportRSAPrivateKey(Convert.FromBase64String(privatePemKey), out _);
        return rsa;
    }
}