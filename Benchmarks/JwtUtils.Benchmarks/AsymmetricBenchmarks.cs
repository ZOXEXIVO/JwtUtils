using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using BenchmarkDotNet.Attributes;
using JWT;
using JWT.Algorithms;
using JWT.Serializers;
using Microsoft.IdentityModel.Tokens;

namespace JwtUtils.Benchmarks;

[MemoryDiagnoser]
public class AsymmetricBenchmarks
{
    private static string PrivateKey = @"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";

    private static string PublicKey = @"MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEA9GF97STxVGbXpBFmudS/
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

    private const string Rs256Token =
        "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6ImtpZCJ9.eyJleHAiOjE2Mzk5NDI2MTYsInVuYW1lIjoiaS5hLml2YW5vdiIsImF1ZCI6WyIxMjIiLCIxMjMiXX0.O9CSuYOPlQ3mIAyTjUio5xeG5ErkI7NalvjlOUXU3kN-kheuGsjxEGPWOcaddPv_UkI2DHvi88W50Ex-lTiMb0Pq3ImU2vZes_k46rlXI4ln55dP5U1neNvJNofQ8OuTpFwQj8tzEKzfc96WRqO-HSSRFWItMLl2Ypkesnc9kA-mmGdB3PJs9kYasqz4zrDd5OIuH5msj7YnUi8Dj1Nc0MP-x2pKSqsfp-1zmm2EqUtS9VXYrrVE5z-7oXd6304FmQawpoXsDU8KimR-KXEnlk6GSNkRA9f67efqu-0J3A2GWe-rPoC-nnQzUph9xtCRFwYS-G9zpYkQ-kOYZe0lmrjtB5X1sQz-v1yNBqciMPvqNtN3o7aklta40O1ImfIY_03uLZZYVsYkHz9J7TZvf7Wt8I8wzHB1HtenCHYFOPvNcjBOVrzHCWWssEYoUA7jqm6vu_Decr_PExoyLJt1fLwxYqWdl-sBc5-P1Rup7ZT2pQsBWp2wIs6_tkAvjM0cLOR_HXC9KFTh2qPc5L4Ez7ac8krYyYsglfVIcIsTeyctAM2dWB7ctXet3vwpSlNMRmH3O-yZKq-DFeDhBTiU2j9zbUh_icj5QHSu0zbOpAnfd2RC5ffKpLyLO4kCKSV_d_hpNcZYURgjy2tpmWTWe-bZn7YGwRNspkANLiCjAOQ";

    private static readonly Dictionary<string, object> _payload = new()
    {
        { "exp", 1639942616 },
        { "uname", "i.a.ivanov" },
        { "claim1", "claim1_value" },
        { "claim2", "claim2_value" },
        { "claim3", "claim3_value" }
    };

    // JwtUtils

    [Benchmark]
    public string JwtUtils_RS256_Create()
    {
        return JWT.RS256.Create(_payload, PrivateKey);
    }

    // JWT

    private static readonly IJwtAlgorithm Algorithm = new RS256Algorithm(CreateRSA_Public(), CreateRSA_Private());
    private static readonly IJsonSerializer Serializer = new JsonNetSerializer();
    private static readonly IBase64UrlEncoder UrlEncoder = new JwtBase64UrlEncoder();
    private static readonly IJwtEncoder Encoder = new JwtEncoder(Algorithm, Serializer, UrlEncoder);
    
    [Benchmark]
    public string JWT_RS256_Create()
    {
        return Encoder.Encode(_payload, PrivateKey);
    }

    // JwtSecurityTokenHandler

    private static RSA CreateRSA_Private()
    {
        var rsa = RSA.Create();
        rsa.ImportRSAPrivateKey(Convert.FromBase64String(PrivateKey), out _);
        return rsa;
    }

    private static RSA CreateRSA_Public()
    {
        var rsa = RSA.Create();
        rsa.ImportSubjectPublicKeyInfo(Convert.FromBase64String(PublicKey), out _);
        return rsa;
    }
    
    static readonly RsaSecurityKey SecurityKey = new(CreateRSA_Private())
    {
        KeyId = "kid"
    };

    static readonly SigningCredentials Credentials256 = new(SecurityKey, SecurityAlgorithms.RsaSha256Signature);

    private static JwtSecurityToken TokenSecurityToken = new("123", "1234", new List<Claim>
    {
        new("uname", "i.a.ivanov"),
        new("claim1", "claim1_value"),
        new("claim2", "claim2_value"),
        new("claim3", "claim3_value"),
    }, null, null, Credentials256);
    
    [Benchmark]
    public string JwtSecurityTokenHandler_RS256_Create()
    {
        return new JwtSecurityTokenHandler().WriteToken(TokenSecurityToken);
    }
}