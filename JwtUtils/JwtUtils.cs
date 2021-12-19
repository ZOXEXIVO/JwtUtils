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
}

internal readonly ref struct JwtPartData
{
    public readonly ReadOnlyMemory<char> Payload;
    public readonly ReadOnlyMemory<char> Signature;

    public JwtPartData(ReadOnlyMemory<char> payload, ReadOnlyMemory<char> signature)
    {
        Payload = payload;
        Signature = signature;
    }
}