using System.Text.Json;

namespace JwtUtils;

public partial class JwtUtils
{
    public static partial class Asymmetric
    {
        public static partial class Token
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
    }
    
    public static partial class Symmetric
    {
        public static partial class Token
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
    }

    private static T ReadPayload<T>(ReadOnlySpan<char> token)
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