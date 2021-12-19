using System.Collections.Concurrent;
using System.Security.Cryptography;
using JwtUtils.Utils.Pools;

namespace JwtUtils.Asymmetric.Algorithms;

internal static class PooledRsa
{
    private static readonly ConcurrentDictionary<string, Lazy<ObjectPool<RSA>>> PrivatePool = new();
    private static readonly ConcurrentDictionary<string, Lazy<ObjectPool<RSA>>> PublicPool = new();
    
    public static PoolGuard<RSA> GetPrivateRsa(string privateKey)
    {
        var pool = PrivatePool.GetOrAdd(privateKey, _ => new Lazy<ObjectPool<RSA>>(() => new ObjectPool<RSA>()));
    
        return pool.Value.Get(() => CreatePrivate(privateKey));
    }
    
    public static PoolGuard<RSA> GetPublicRsa(string publicKey)
    {
        var pool = PublicPool.GetOrAdd(publicKey, _ => new Lazy<ObjectPool<RSA>>(() => new ObjectPool<RSA>()));
    
        return pool.Value.Get(() => CreatePublic(publicKey));
    }
    
    private static RSA CreatePrivate(string privatePemKey)
    {
        var rsa = RSA.Create();
        rsa.ImportRSAPrivateKey(Convert.FromBase64String(privatePemKey), out _);
        return rsa;
    }
    
    private static RSA CreatePublic(string publicPemKey)
    {
        var rsa = RSA.Create();
        rsa.ImportSubjectPublicKeyInfo(Convert.FromBase64String(publicPemKey), out _);
        return rsa;
    }
}