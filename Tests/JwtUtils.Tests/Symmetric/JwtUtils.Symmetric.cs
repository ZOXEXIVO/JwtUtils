using System.Collections.Generic;
using JwtUtils.Extensions;
using Xunit;

namespace JwtUtils.Tests.Symmetric;

public class Symmetric
{
    string tokenSecret = "12345";

    readonly Dictionary<string, object> _payload = new()
    {
        { "exp", 1639942616 },
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
        var token = JwtUtils.Symmetric.Token.HS256.Create(_payload, tokenSecret, "kid1");
        var isTokenValid = JwtUtils.Symmetric.Token.HS256.ValidateSignature(token, tokenSecret);

        var tokenData = JwtUtils.Symmetric.Token.HS256.Read(token);

        var expiration = tokenData.Exp();
        
        Assert.True(isTokenValid);
        Assert.Equal(1639942616, expiration);
    }
    
    [Fact]
    public void JwtUtils_HS384_IsCorrect()
    {
        var token = JwtUtils.Symmetric.Token.HS384.Create(_payload, tokenSecret, "kid1");
        var isTokenValid = JwtUtils.Symmetric.Token.HS384.ValidateSignature(token, tokenSecret);

        var tokenData = JwtUtils.Symmetric.Token.HS384.Read(token);

        var expiration = tokenData.Exp();
        
        Assert.True(isTokenValid);
        Assert.Equal(1639942616, expiration);
    }
    
    [Fact]
    public void JwtUtils_HS512_IsCorrect()
    {
        var token = JwtUtils.Symmetric.Token.HS512.Create(_payload, tokenSecret, "kid1");
        var isTokenValid = JwtUtils.Symmetric.Token.HS512.ValidateSignature(token, tokenSecret);

        var tokenData = JwtUtils.Symmetric.Token.HS512.Read(token);

        var expiration = tokenData.Exp();
        
        Assert.True(isTokenValid);
        Assert.Equal(1639942616, expiration);
    }
}