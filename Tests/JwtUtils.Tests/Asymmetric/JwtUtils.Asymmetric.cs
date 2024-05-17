using System.Collections.Generic;
using JwtUtils.Extensions;
using JwtUtils.Tests.Common;
using Xunit;

namespace JwtUtils.Tests.Asymmetric;

public class Asymmetric
{
    private readonly string _privateKey = @"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";

    private string _publicKey = @"MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEA9GF97STxVGbXpBFmudS/
RRT58mfiR/+t2zb4f/uF3qmYb/yuoekYX5s17YPcIYshiX1XEN2gitHf3IcOOELR
iNDSW1zrADzKFTeWzpji48IBObRf5Rda2Q4wIX6YUca/8eLvHcyOlDyCh0dfZNae
2w/Ts8xda1TYC41rlD5rnQDgvsCK4fzfm39hCet+nMz4jLvRQ66aDs42qCBLK9cx
RJcptsiR/pxmuJLC2jKz/PLjgrSCu1ykfW5P+fU1ulDoI9tkr1FpfZsmF02vmMnd
aRjrH9Rt+LuGHtlTXWntMjovh2jbyy7L2hZAX5V9SfW7e5a2JvPGbOQpt6AvzdU/
U7s6PEmVwoa96pPZVgqXQTu4C9ipsiAY1LdbajowElpYmHpgUzu7Ll2GtrzQHtVv
fddNu7LkIoL6c93l5CAWsh1a0F9dvE04K6c+qQtL3MhAOuEXbwHf9vaCBxje5bL0
JVtlccN8ujqAG/pk49vY80+OpKMGry+vBpO8LZpXkyzryW5vUSdhOgpfZIpU5QcO
VNj1RNxmYEbUf+hd40MGzpTLOJxva880vpcu/BxLqi3xfOhLQrXTXRKRdBPr1yM1
a9ku4ZoA7hOBuJawupx7v3oY+TZQ4tKUs554fg6zj87LUMgPEaozvMz8MWSlhnD1
UGrjbNX1LcdQ/HAtFCuqIE0CAwEAAQ==";
    
    readonly Dictionary<string, object> _untypedPayload = new()
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
    public void JwtUtils_RS256_Untyped_IsCorrect()
    {
        var token = JWT.RS256.Create(_untypedPayload, _privateKey, "kid1");
        var isTokenValid = JWT.RS256.ValidateSignature(token, _publicKey);

        var tokenData =  JWT.Read(token);

        var expiration = tokenData.Exp();
        
        Assert.True(isTokenValid);
        Assert.Equal(1639942616, expiration);
    }
    
    [Fact]
    public void JwtUtils_RS256_Typed_IsCorrect()
    {
        var token = JWT.RS256.Create(_typedPayload, _privateKey, "kid1");
        var isTokenValid = JWT.RS256.ValidateSignature(token, _publicKey);

        var tokenData =  JWT.Read<JwtPayload>(token);

        Assert.True(isTokenValid);
        Assert.Equal(123, tokenData.UserId);
        Assert.Equal("userLogin", tokenData.UserLogin);
        Assert.Equal(12345, tokenData.Expiration);
    }
    
    [Fact]
    public void JwtUtils_RS384_Untyped_IsCorrect()
    {
        var token = JWT.RS384.Create(_untypedPayload, _privateKey, "kid1");
        var isTokenValid = JWT.RS384.ValidateSignature(token, _publicKey);

        var tokenData = JWT.Read(token);

        var expiration = tokenData.Exp();
        
        Assert.True(isTokenValid);
        Assert.Equal(1639942616, expiration);
    }
    
    [Fact]
    public void JwtUtils_RS384_Typed_IsCorrect()
    {
        var token = JWT.RS384.Create(_typedPayload, _privateKey, "kid1");
        var isTokenValid = JWT.RS384.ValidateSignature(token, _publicKey);

        var tokenData =  JWT.Read<JwtPayload>(token);

        Assert.True(isTokenValid);
        Assert.Equal(123, tokenData.UserId);
        Assert.Equal("userLogin", tokenData.UserLogin);
        Assert.Equal(12345, tokenData.Expiration);
    }
    
    [Fact]
    public void JwtUtils_RS512_Untyped_IsCorrect()
    {
        var token = JWT.RS512.Create(_untypedPayload, _privateKey, "kid1");
        var isTokenValid = JWT.RS512.ValidateSignature(token, _publicKey);

        var tokenData = JWT.Read(token);

        var expiration = tokenData.Exp();
        
        Assert.True(isTokenValid);
        Assert.Equal(1639942616, expiration);
    }
    
    [Fact]
    public void JwtUtils_RS512_Typed_IsCorrect()
    {
        var token = JWT.RS512.Create(_typedPayload, _privateKey, "kid1");
        var isTokenValid = JWT.RS512.ValidateSignature(token, _publicKey);

        var tokenData =  JWT.Read<JwtPayload>(token);

        Assert.True(isTokenValid);
        Assert.Equal(123, tokenData.UserId);
        Assert.Equal("userLogin", tokenData.UserLogin);
        Assert.Equal(12345, tokenData.Expiration);
    }
}