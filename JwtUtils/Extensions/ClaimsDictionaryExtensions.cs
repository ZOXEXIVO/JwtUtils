
namespace JwtUtils.Extensions;

public class JwtClaims
{
    public const string Expiration = "exp";
}

public static class ClaimsDictionaryExtensions
{
    public static long? Exp(this Dictionary<string, object> claims)
    {
        if (!claims.TryGetValue(JwtClaims.Expiration, out var item))
            return null;

        return ConvertToLong(item);
    }
    
    public static T? Get<T>(this Dictionary<string, object> claims, string claimName) where T : struct
    {
        if (!claims.TryGetValue(claimName, out var item))
            return null;

        try
        {
            var typeCode = Type.GetTypeCode(typeof(T));
            
            return typeCode switch
            {
                TypeCode.DateTime => ConvertToDateTime(item) as T?,
                TypeCode.Int32 => ConvertToInt(item) as T?,
                TypeCode.Int64 => ConvertToLong(item) as T?,
                TypeCode.Single => ConvertToFloat(item) as T?,
                TypeCode.Double => ConvertToDouble(item) as T?,
                TypeCode.Decimal => ConvertToDecimal(item) as T?,
                TypeCode.Boolean => ConvertToBoolean(item) as T?,
                TypeCode.Byte => ConvertToByte(item) as T?,
                TypeCode.Int16 => ConvertToShort(item) as T?,
                TypeCode.UInt16 => ConvertToUShort(item) as T?,
                TypeCode.UInt32 => ConvertToUInt(item) as T?,
                TypeCode.UInt64 => ConvertToULong(item) as T?,
                _ => null
            };
        }
        catch
        {
            return null;
        }
    }

    private static long? ConvertToLong(object item)
    {
        return item switch
        {
            long l => l,
            int i => i,
            double d => (long)d,
            float f => (long)f,
            decimal dec => (long)dec,
            byte b => b,
            short s => s,
            uint ui => ui,
            ulong ul => (long)ul,
            ushort us => us,
            string str when long.TryParse(str, out var parsed) => parsed,
            _ => null
        };
    }

    private static int? ConvertToInt(object item)
    {
        return item switch
        {
            int i => i,
            long l when l >= int.MinValue && l <= int.MaxValue => (int)l,
            double d when d >= int.MinValue && d <= int.MaxValue => (int)d,
            float f when f >= int.MinValue && f <= int.MaxValue => (int)f,
            decimal dec when dec >= int.MinValue && dec <= int.MaxValue => (int)dec,
            byte b => b,
            short s => s,
            uint ui when ui <= int.MaxValue => (int)ui,
            ushort us => us,
            string str when int.TryParse(str, out var parsed) => parsed,
            _ => null
        };
    }

    private static float? ConvertToFloat(object item)
    {
        return item switch
        {
            float f => f,
            double d => (float)d,
            int i => i,
            long l => l,
            decimal dec => (float)dec,
            byte b => b,
            short s => s,
            uint ui => ui,
            ulong ul => ul,
            ushort us => us,
            string str when float.TryParse(str, out var parsed) => parsed,
            _ => null
        };
    }

    private static double? ConvertToDouble(object item)
    {
        return item switch
        {
            double d => d,
            float f => f,
            int i => i,
            long l => l,
            decimal dec => (double)dec,
            byte b => b,
            short s => s,
            uint ui => ui,
            ulong ul => ul,
            ushort us => us,
            string str when double.TryParse(str, out var parsed) => parsed,
            _ => null
        };
    }

    private static decimal? ConvertToDecimal(object item)
    {
        return item switch
        {
            decimal dec => dec,
            int i => i,
            long l => l,
            float f => (decimal)f,
            double d => (decimal)d,
            byte b => b,
            short s => s,
            uint ui => ui,
            ulong ul => ul,
            ushort us => us,
            string str when decimal.TryParse(str, out var parsed) => parsed,
            _ => null
        };
    }

    private static bool? ConvertToBoolean(object item)
    {
        return item switch
        {
            bool b => b,
            string str when bool.TryParse(str, out var parsed) => parsed,
            int i => i != 0,
            long l => l != 0,
            double d => d != 0.0,
            float f => f != 0.0f,
            _ => null
        };
    }

    private static DateTime? ConvertToDateTime(object item)
    {
        return item switch
        {
            DateTime dt => dt,
            string str when DateTime.TryParse(str, out var parsed) => parsed,
            // Handle Unix timestamp (seconds since epoch)
            long unixSeconds when unixSeconds > 0 => DateTimeOffset.FromUnixTimeSeconds(unixSeconds).DateTime,
            int unixSeconds when unixSeconds > 0 => DateTimeOffset.FromUnixTimeSeconds(unixSeconds).DateTime,
            double unixSeconds when unixSeconds > 0 => DateTimeOffset.FromUnixTimeSeconds((long)unixSeconds).DateTime,
            _ => null
        };
    }

    private static byte? ConvertToByte(object item)
    {
        return item switch
        {
            byte b => b,
            int i when i >= byte.MinValue && i <= byte.MaxValue => (byte)i,
            long l when l >= byte.MinValue && l <= byte.MaxValue => (byte)l,
            short s when s >= byte.MinValue && s <= byte.MaxValue => (byte)s,
            string str when byte.TryParse(str, out var parsed) => parsed,
            _ => null
        };
    }

    private static short? ConvertToShort(object item)
    {
        return item switch
        {
            short s => s,
            int i when i >= short.MinValue && i <= short.MaxValue => (short)i,
            long l when l >= short.MinValue && l <= short.MaxValue => (short)l,
            byte b => b,
            string str when short.TryParse(str, out var parsed) => parsed,
            _ => null
        };
    }

    private static ushort? ConvertToUShort(object item)
    {
        return item switch
        {
            ushort us => us,
            int i when i is >= ushort.MinValue and <= ushort.MaxValue => (ushort)i,
            long l when l is >= ushort.MinValue and <= ushort.MaxValue => (ushort)l,
            byte b => b,
            short s when s >= 0 => (ushort)s,
            string str when ushort.TryParse(str, out var parsed) => parsed,
            _ => null
        };
    }

    private static uint? ConvertToUInt(object item)
    {
        return item switch
        {
            uint ui => ui,
            int i when i >= 0 => (uint)i,
            long l when l is >= uint.MinValue and <= uint.MaxValue => (uint)l,
            byte b => b,
            short s when s >= 0 => (uint)s,
            ushort us => us,
            string str when uint.TryParse(str, out var parsed) => parsed,
            _ => null
        };
    }

    private static ulong? ConvertToULong(object item)
    {
        return item switch
        {
            ulong ul => ul,
            long l when l >= 0 => (ulong)l,
            int i when i >= 0 => (ulong)i,
            uint ui => ui,
            byte b => b,
            short s when s >= 0 => (ulong)s,
            ushort us => us,
            string str when ulong.TryParse(str, out var parsed) => parsed,
            _ => null
        };
    }
}