using System.Runtime.CompilerServices;
using System.Text.Json;

namespace JwtUtils.Extensions;

internal static class JsonExtensions
{
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    internal static string ToJson(this object obj)
    {
        return JsonSerializer.Serialize(obj);
    }
}