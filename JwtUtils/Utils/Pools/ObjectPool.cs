using System.Collections.Concurrent;

namespace JwtUtils.Utils.Pools;

internal class ObjectPool<T>
{
    private readonly ConcurrentBag<T> _pool = new();

    public PoolGuard<T> Get(Func<T> generator)
    {
        var pooledObject = _pool.TryTake(out var obj) ? obj : generator();
        return new PoolGuard<T>(this, pooledObject);
    }
        
    public void Return(T obj)
    {
        _pool.Add(obj);
    }
}

internal readonly struct PoolGuard<T> : IDisposable
{
    private ObjectPool<T> Pool { get; }
        
    public T PooledObject { get; }
        
    public PoolGuard(ObjectPool<T> pool, T obj)
    {
        Pool = pool;
        PooledObject = obj;
    }
        
    public void Dispose()
    {
        Pool.Return(PooledObject);
    }
}