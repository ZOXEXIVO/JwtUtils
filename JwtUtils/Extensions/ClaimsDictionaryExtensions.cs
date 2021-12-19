using System.Text.Json;
using JwtUtils.Constants;

namespace JwtUtils.Extensions;

public static class ClaimsDictionaryExtensions
{
    public static long? Exp(this Dictionary<string, object> claims)
    {
        if (!claims.TryGetValue(JwtClaims.Expiration, out var item))
            return null;

        if (item is not JsonElement jElement) 
            return null;
        
        if (jElement.TryGetInt64(out var exp))
        {
            return exp;
        }

        return null;
    }
    
    public static T? Get<T>(this Dictionary<string, object> claims, string claimName) where T : struct
    {
        if (!claims.TryGetValue(claimName, out var item))
            return default;

        if (item is not JsonElement jElement) 
            return default;

        switch (Type.GetTypeCode(typeof(T)))
        {
            case TypeCode.DateTime:
            {
                if (jElement.TryGetDateTime(out var val))
                {
                    return val as T?;
                }

                break;
            }
            
            case TypeCode.Int32:
            {
                if (jElement.TryGetInt32(out var val))
                {
                    return val as T?;
                }

                break;
            }
            case TypeCode.Int64:
            {
                if (jElement.TryGetInt64(out var val))
                {
                    return val as T?;
                }
                break;
            }
        }
        
        return null;
    }
}