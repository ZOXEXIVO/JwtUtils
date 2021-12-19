using System.Collections.Generic;
using Xunit;

namespace JwtUtils.Tests.Symmetric;

public class Symmetric
{
    string tokenSecret = "12345";

    readonly Dictionary<string, object> _payload = new Dictionary<string, object>
    {
        { "exp", 12345 },
        { "uname", "i.a.ivanov" },
        {
            "aud", new[]
            {
                "122",
                "123"
            }
        }
    };
    
    [Fact]
    public void JwtUtils_HS256_IsCorrect()
    {
        var token = JwtUtils.Symmetric.Token.HS256.Create(_payload, tokenSecret);
        var isTokenValid = JwtUtils.Symmetric.Token.HS256.Validate(token, tokenSecret);

        Assert.True(isTokenValid);
    }
    
    [Fact]
    public void JwtUtils_HS384_IsCorrect()
    {
        var token = JwtUtils.Symmetric.Token.HS384.Create(_payload, tokenSecret);
        var isTokenValid = JwtUtils.Symmetric.Token.HS384.Validate(token, tokenSecret);

        Assert.True(isTokenValid);
    }
    
    [Fact]
    public void JwtUtils_HS512_IsCorrect()
    {
        var token = JwtUtils.Symmetric.Token.HS512.Create(_payload, tokenSecret);
        var isTokenValid = JwtUtils.Symmetric.Token.HS512.Validate(token, tokenSecret);

        Assert.True(isTokenValid);
    }
}