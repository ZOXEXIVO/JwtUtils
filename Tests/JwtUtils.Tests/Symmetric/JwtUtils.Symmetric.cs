using System.Collections.Generic;
using JwtUtils.Extensions;
using JwtUtils.Tests.Common;
using Xunit;

namespace JwtUtils.Tests.Symmetric;

public class Symmetric
{
    string tokenSecret = "12345";

    private readonly Dictionary<string, object> _untypedPayload = new()
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

    private readonly JwtPayload _typedPayload = new()
    {
        UserId = 123,
        UserLogin = "userLogin",
        Expiration = 12345
    };
    
    [Fact]
    public void JwtUtils_HS256_Untyped_IsCorrect()
    {
        var token = JWT.HS256.Create(_untypedPayload, tokenSecret, "kid1");
        var isTokenValid = JWT.HS256.ValidateSignature(token, tokenSecret);

        var tokenData = JWT.Read(token);

        var expiration = tokenData.Exp();
        
        Assert.True(isTokenValid);
        Assert.Equal(1639942616, expiration);
    }
    
    [Fact]
    public void JwtUtils_HS256_Typed_IsCorrect()
    {
        var token = JWT.HS256.Create(_typedPayload, tokenSecret, "kid1");
        var isTokenValid = JWT.HS256.ValidateSignature(token, tokenSecret);

        var tokenData = JWT.Read<JwtPayload>(token);

        Assert.True(isTokenValid);
        
        Assert.Equal(123, tokenData.UserId);
        Assert.Equal("userLogin", tokenData.UserLogin);
        Assert.Equal(12345, tokenData.Expiration);
    }
    
    [Fact]
    public void JwtUtils_HS384_Untyped_IsCorrect()
    {
        var token = JWT.HS384.Create(_untypedPayload, tokenSecret, "kid1");
        var isTokenValid = JWT.HS384.ValidateSignature(token, tokenSecret);

        var tokenData = JwtUtils.JWT.Read(token);

        var expiration = tokenData.Exp();
        
        Assert.True(isTokenValid);
        Assert.Equal(1639942616, expiration);
    }
    
    [Fact]
    public void JwtUtils_HS384_Typed_IsCorrect()
    {
        var token = JWT.HS384.Create(_typedPayload, tokenSecret, "kid1");
        var isTokenValid = JWT.HS384.ValidateSignature(token, tokenSecret);

        var tokenData = JWT.Read<JwtPayload>(token);

        Assert.True(isTokenValid);
        
        Assert.Equal(123, tokenData.UserId);
        Assert.Equal("userLogin", tokenData.UserLogin);
        Assert.Equal(12345, tokenData.Expiration);
    }
    
    [Fact]
    public void JwtUtils_HS512_Untyped_IsCorrect()
    {
        var token = JWT.HS512.Create(_untypedPayload, tokenSecret, "kid1");
        var isTokenValid = JWT.HS512.ValidateSignature(token, tokenSecret);

        var tokenData = JWT.Read(token);

        var expiration = tokenData.Exp();
        
        Assert.True(isTokenValid);
        Assert.Equal(1639942616, expiration);
    }
    
    [Fact]
    public void JwtUtils_HS512_Typed_IsCorrect()
    {
        var token = JWT.HS512.Create(_typedPayload, tokenSecret, "kid1");
        var isTokenValid = JWT.HS512.ValidateSignature(token, tokenSecret);

        var tokenData = JWT.Read<JwtPayload>(token);

        Assert.True(isTokenValid);
        
        Assert.Equal(123, tokenData.UserId);
        Assert.Equal("userLogin", tokenData.UserLogin);
        Assert.Equal(12345, tokenData.Expiration);
    }
}