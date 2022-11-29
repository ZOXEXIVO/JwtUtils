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
        return Payload.Read<Dictionary<string, object>>(token);
    }
    
    /// <summary>
    /// Read token payload to your custom type object with System.Text.Json
    /// </summary>
    /// <param name="token"></param>
    /// <returns></returns>
    public static T Read<T>(ReadOnlySpan<char> token)
    {
        // ReSharper disable once ArrangeStaticMemberQualifier
        return Payload.Read<T>(token);
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