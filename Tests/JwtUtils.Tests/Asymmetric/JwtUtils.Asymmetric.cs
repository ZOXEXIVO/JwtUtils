using System.Collections.Generic;
using Xunit;

namespace JwtUtils.Tests.Asymmetric;

public class Asymmetric
{
    [Fact]
    public void JwtUtils_Symmetric_Create_IsCorrect()
    {
        string pemKey = @"MIIBOAIBAAJAaIxeuuv3WMmZM53WDbvLHURBINBS/l8RmvEg8E7sek4ENwSzhkFA
T9/U2rDJ7vdpYKxnA0MrR72SEfoCJ3+u9QIDAQABAkBARQp3HlgP3N6xPHY6OxfC
BhODeI2MkiTgexskn2AATumIhgIbvJplMJZ73LdJJ2QkI83sEVafXJxOMk1az4AB
AiEAwZe1UxFHsAbq0YwjoElxku9Cn1dsGWComGUfPEM2HwECIQCKQEDfU9bbGeqr
lwU2a2CK7p4gOZHrKadnnH6wqVcD9QIgZWKgMZqxInzc6VUtKzqLYlovV+ee00ON
yBHdY+AHLgECIAO6PcWHtihMJ5aeyMYx2PWF/39w7e1AP0I85vGOb0ktAiB4DpEG
2IjDQwUo7LgKujGNgui1/upIBUi8CA+59/ZwMQ==";
        
        var payload = new Dictionary<string, object>
        {
            { "exp", 12345 },
            { "uname", "i.a.ivanov" }
        };

        var token = JwtUtils.Asymmetric.Token.RS256(payload, pemKey);
    }
}