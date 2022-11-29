using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using BenchmarkDotNet.Attributes;
using JWT;
using JWT.Algorithms;
using JWT.Serializers;
using Microsoft.IdentityModel.Tokens;

namespace JwtUtils.Benchmarks;

[MemoryDiagnoser]
public class SymmetricBenchmarks
{
    private const string TokenSecret = "8894375109986248604888943751099862486048";

    private const string Hs256Token =
        "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6ImtpZCJ9.eyJleHAiOjE2Mzk5NDI2MTYsInVuYW1lIjoiaS5hLml2YW5vdiIsImF1ZCI6WyIxMjIiLCIxMjMiXX0.hRKQ9G_5wdzYURbQWofrEiCn9JK-ATPSLVERG26vqiA";

    private readonly Dictionary<string, object> _payload = new()
    {
        { "exp", 1639942616 },
        { "uname", "i.a.ivanov" },
        { "claim1", "claim1_value" },
        { "claim2", "claim2_value" },
        { "claim3", "claim3_value" }
    };

    // JwtUtils
    
    [Benchmark]
    public string JwtUtils_HS256_Create()
    {
        return JWT.HS256.Create(_payload, TokenSecret);
    }

    // JWT
    
    private static readonly IJwtAlgorithm Algorithm = new HMACSHA256Algorithm();
    private static readonly IJsonSerializer Serializer = new JsonNetSerializer();
    private static readonly IBase64UrlEncoder UrlEncoder = new JwtBase64UrlEncoder();
    private static readonly IJwtEncoder Encoder = new JwtEncoder(Algorithm, Serializer, UrlEncoder);

    [Benchmark]
    public string JWT_HS256_Create()
    {
        return Encoder.Encode(_payload, TokenSecret);
    }
    
    //JwtSecurityTokenHandler
    
    static readonly SymmetricSecurityKey SecurityKey = new(Encoding.UTF8.GetBytes(TokenSecret))
    {
        KeyId = "kid"
    };

    static readonly SigningCredentials Credentials256 = new(SecurityKey, SecurityAlgorithms.HmacSha256);

    private static readonly JwtSecurityToken JsonSecurityToken = new("123", "1234", new List<Claim>
    {
        new("uname", "i.a.ivanov"),
        new("claim1", "claim1_value"),
        new("claim2", "claim2_value"),
        new("claim3", "claim3_value"),
    }, null, null, Credentials256);
    
    [Benchmark]
    public string JwtSecurityTokenHandler_HS256_Create()
    {
        return new JwtSecurityTokenHandler().WriteToken(JsonSecurityToken);
    }
}