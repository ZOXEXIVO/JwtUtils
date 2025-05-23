using System.Runtime.CompilerServices;

namespace JwtUtils.Json;

internal static class JsonExtensions
{
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    internal static string ToJson(this object obj)
    {
        return SimpleJson.Serialize(obj);
    }
}