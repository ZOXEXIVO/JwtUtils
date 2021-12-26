using System.Text.Json.Serialization;

namespace JwtUtils.Tests.Common;

public class JwtPayload
{
    [JsonPropertyName("uid")]
    public int UserId { get; set; }
    
    [JsonPropertyName("uname")]
    public string UserLogin { get; set; }
    
    [JsonPropertyName("exp")]
    public long Expiration { get; set; }
}