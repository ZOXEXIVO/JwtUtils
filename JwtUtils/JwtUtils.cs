using System.Text.Json;

namespace JwtUtils;

public static partial class AsymmetricToken
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
}
    
public static partial class SymmetricToken
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

public class PayloadExt
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