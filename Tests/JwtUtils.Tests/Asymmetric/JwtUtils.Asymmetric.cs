using System.Collections.Generic;
using Xunit;

namespace JwtUtils.Tests.Asymmetric;

public class Asymmetric
{
    private string _privateKey = @"MIICXAIBAAKBgQCLtd970kSopMogXY8kWMIWdVZjbaJFCvZZ0Ac/I31mzHGOLwN+
DLKbFVo9cvxJkVbzcsB9xBbGq94RqBoYCCiynFwzCpd1b6TvaeoTho0wxMACEsHl
du6+Mp5XnuuFIhTbUjkfduNX80Px0nCEKSOnWzPqA0Nh4EJwUt9bt42FUwIDAQAB
AoGAXFIrwxvYiQSUGL0aeO86GjMhigSJhUxQLFs+XqeqF0MkCsvgZ+wmHjsG7bJN
KqQjLC55KuJoFpK95TcLPzQtB5f7UyX0z6tLhpijnOPIAglG/cQzHdBK+/IuDmkR
6Tgwnv1EJNs0uR5040EY/DlBysVHSXhmI318F+dDwRSKB7ECQQDGFDGlN1vbPMCa
pF7avBTXgIemEyi2ULXkt67DI5D2W3Wb+pwCZEN605x36fx45KkicsAZpnPfQmrQ
ml4BvyGpAkEAtJBUScyrNaFT7/1xbY9ORX9TZCW5uTGlyrGyaRCVg0b1rpCMsTzC
ZCa3SreiF72hXegY0CTChdE5uh8P7VGEmwJAEkqjGwK1tNUzZBRxvflIY243GJsE
U3G4mlpsBREvvdBMWA8YgRAJOzp3ZItzCSb0h33ZR4Ubhi539rOKotanoQJAIA2n
CNrOYdzbu7SwGBTifi/WK+cOizOnDM5yr3gEMqO8JVr/vs7ca078JsVmfvRo2vTC
wuBjr8Guj73H5AcelQJBALtw50waa4lIkSrTKcn0AGNH/p8JAXIfupd+Xn3DohMt
BMdlI3aC8dN8y/PonNV/uHipxI8csod05UsMud2nMZk=";

    private string _publicKey = @"MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCLtd970kSopMogXY8kWMIWdVZj
baJFCvZZ0Ac/I31mzHGOLwN+DLKbFVo9cvxJkVbzcsB9xBbGq94RqBoYCCiynFwz
Cpd1b6TvaeoTho0wxMACEsHldu6+Mp5XnuuFIhTbUjkfduNX80Px0nCEKSOnWzPq
A0Nh4EJwUt9bt42FUwIDAQAB";
    
    readonly Dictionary<string, object> _payload = new()
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
    public void JwtUtils_RS256_IsCorrect()
    {
        var token = JwtUtils.Asymmetric.Token.RS256.Create(_payload, _privateKey);
        var isTokenValid = JwtUtils.Asymmetric.Token.RS256.Validate(token, _publicKey);

        Assert.True(isTokenValid);
    }
}