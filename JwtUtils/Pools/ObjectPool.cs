using System.Collections.Concurrent;

namespace JwtUtils.Pools;

internal class ObjectPool<T>
{
    private readonly ConcurrentBag<T> _pool = [];

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

internal readonly struct PoolGuard<T>(ObjectPool<T> pool, T obj) : IDisposable
{
    private ObjectPool<T> Pool { get; } = pool;

    public T PooledObject { get; } = obj;

    public void Dispose()
    {
        Pool.Return(PooledObject);
    }
}