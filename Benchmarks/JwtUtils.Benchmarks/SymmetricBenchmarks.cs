using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using BenchmarkDotNet.Attributes;
using Microsoft.IdentityModel.Tokens;

namespace JwtUtils.Benchmarks;

[MemoryDiagnoser]
public class SymmetricBenchmarks
{
    private const string TokenSecret = "8894375109986248604888943751099862486048";

    private const string Hs256Token =
        "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6ImtpZCJ9.eyJleHAiOjE2Mzk5NDI2MTYsInVuYW1lIjoiaS5hLml2YW5vdiIsImF1ZCI6WyIxMjIiLCIxMjMiXX0.hRKQ9G_5wdzYURbQWofrEiCn9JK-ATPSLVERG26vqiA";
    
    private const string Hs384Token =
        "eyJhbGciOiJIUzM4NCIsInR5cCI6IkpXVCIsImtpZCI6ImtpZCJ9.eyJleHAiOjE2Mzk5NDI2MTYsInVuYW1lIjoiaS5hLml2YW5vdiIsImF1ZCI6WyIxMjIiLCIxMjMiXX0.ZX0GJzzqR-3O5LS2Nc9H1qf03ZPXYoIIaaASqfQcGC11ASS_Yte4Q8pMuSMXTWUg";
    
    private const string Hs512Token =
        "eyJhbGciOiJIUzUxMiIsInR5cCI6IkpXVCIsImtpZCI6ImtpZCJ9.eyJleHAiOjE2Mzk5NDI2MTYsInVuYW1lIjoiaS5hLml2YW5vdiIsImF1ZCI6WyIxMjIiLCIxMjMiXX0.LXzG5bzP3IqdrZV1dpYHO_80xtc8P-I8TkrWa34VLOA";
    
    private readonly Dictionary<string, object> _claims = new()
    {
        { "exp", 1639942616 },
        { "uname", "i.a.ivanov" },
        { "claim1", "claim1_value" },
        { "claim2", "claim2_value" },
        { "claim3", "claim3_value" }
    };

    [Benchmark]
    public string JwtUtils_HS256_Create()
    {
        return JwtUtils.SymmetricToken.HS256.Create(_claims, TokenSecret);
    }
    
    [Benchmark]
    public bool JwtUtils_HS256_Validate()
    {
        return JwtUtils.SymmetricToken.HS256.ValidateSignature(Hs256Token, TokenSecret);
    }

    [Benchmark]
    public string JwtUtils_HS384_Create()
    {
        return JwtUtils.SymmetricToken.HS384.Create(_claims, TokenSecret);
    }

    [Benchmark]
    public string JwtUtils_HS512_Create()
    {
        return JwtUtils.SymmetricToken.HS512.Create(_claims, TokenSecret);
    }

    static readonly SymmetricSecurityKey SecurityKey = new(Encoding.UTF8.GetBytes(TokenSecret))
    {
        KeyId = "kid"
    };

    static readonly SigningCredentials Credentials256 = new(SecurityKey, SecurityAlgorithms.HmacSha256);
    static readonly SigningCredentials Credentials384 = new(SecurityKey, SecurityAlgorithms.HmacSha384);
    static readonly SigningCredentials Credentials512 = new(SecurityKey, SecurityAlgorithms.HmacSha512);

    [Benchmark]
    public string JwtSecurityTokenHandler_HS256_Create()
    {
        var token = new JwtSecurityToken("123", "1234", new List<Claim>
        {
            new("uname", "i.a.ivanov"),
            new("claim1", "claim1_value"),
            new("claim2", "claim2_value"),
            new("claim3", "claim3_value"),
        }, null, null, Credentials256);

        return new JwtSecurityTokenHandler().WriteToken(token);
    }
    
    [Benchmark]
    public string JwtSecurityTokenHandler_HS384_Create()
    {
        var token = new JwtSecurityToken("123", "1234", new List<Claim>
        {
            new("uname", "i.a.ivanov"),
            new("claim1", "claim1_value"),
            new("claim2", "claim2_value"),
            new("claim3", "claim3_value"),
        }, null, null, Credentials384);

        return new JwtSecurityTokenHandler().WriteToken(token);
    }
    
    [Benchmark]
    public string JwtSecurityTokenHandler_HS512_Create()
    {
        var token = new JwtSecurityToken("123", "1234", new List<Claim>
        {
            new("uname", "i.a.ivanov"),
            new("claim1", "claim1_value"),
            new("claim2", "claim2_value"),
            new("claim3", "claim3_value"),
        }, null, null, Credentials512);

        return new JwtSecurityTokenHandler().WriteToken(token);
    }
}