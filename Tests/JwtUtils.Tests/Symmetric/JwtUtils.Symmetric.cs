using System.Collections.Generic;
using Xunit;

namespace JwtUtils.Tests.Symmetric;

public class Symmetric
{
    [Fact]
    public void JwtUtils_Symmetric_Create_IsCorrect()
    {
        var payload = new Dictionary<string, object>
        {
            { "exp", 12345 },
            { "uname", "i.a.ivanov" }
        };

        var token = JwtUtils.Symmetric.Create(payload, "12345");
    }
}