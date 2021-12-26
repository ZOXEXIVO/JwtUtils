using System.Text.Json;

namespace JwtUtils;

// ReSharper disable once InconsistentNaming
public static partial class JWT
{
    // ReSharper disable once InconsistentNaming
    public static partial class RS256
    {
    }
            
    // ReSharper disable once InconsistentNaming
    public static partial class RS384
    {
    }
            
    // ReSharper disable once InconsistentNaming
    public static partial class RS512
    {
    }
    
    /// <summary>
    /// Read token payload to Dictionary(string,object)
    /// </summary>
    /// <param name="token"></param>
    /// <returns></returns>
    public static Dictionary<string, object> Read(ReadOnlySpan<char> token)
    {
        // ReSharper disable once ArrangeStaticMemberQualifier
        return PayloadExt.ReadPayload<Dictionary<string, object>>(token);
    }

    /// <summary>
    /// Read token payload to your custom type object with System.Text.Json
    /// </summary>
    /// <param name="token"></param>
    /// <returns></returns>
    public static T Read<T>(ReadOnlySpan<char> token)
    {
        // ReSharper disable once ArrangeStaticMemberQualifier
        return PayloadExt.ReadPayload<T>(token);
    }
}
    
// ReSharper disable once InconsistentNaming
public static partial class JWT
{
    // ReSharper disable once InconsistentNaming
    public static partial class HS256
    {
    }
            
    // ReSharper disable once InconsistentNaming
    public static partial class HS384
    {
    }
            
    // ReSharper disable once InconsistentNaming
    public static partial class HS512
    {
    }
}

internal class PayloadExt
{
    public static T ReadPayload<T>(ReadOnlySpan<char> token)
    {
        var payload = Payload.ExtractPayload(token);
        var decodedPayload = Payload.PrepareForDecoding(payload);
        using (decodedPayload.PayloadMemory)
        {
            var actualPayloadBuffer = decodedPayload.PayloadMemory.Memory.Span.Slice(0, decodedPayload.ActualLength);

            return JsonSerializer.Deserialize<T>(actualPayloadBuffer);
        }
    }
}