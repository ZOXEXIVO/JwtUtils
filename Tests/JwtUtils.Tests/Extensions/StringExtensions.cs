using System;
using JwtUtils.Utils.Strings;
using Xunit;

namespace JwtUtils.Tests.Extensions;

public class StringExtensions
{
    [Fact]
    public void FixForWeb_IsCorrect()
    {
        string str = "abcd+/====";

        Span<char> strSpanned = stackalloc char[str.Length];
        
        str.AsSpan().CopyTo(strSpanned);

        var strFixedForWeb = strSpanned.FixForWeb().ToString();
        
        Assert.Equal("abcd-_", strFixedForWeb);
    }
    
    [Fact]
    public void UnfixForWeb_IsCorrect()
    {
        string str = "abcd-_";

        Span<char> strSpanned = stackalloc char[str.Length+3];
        
        str.AsSpan().CopyTo(strSpanned);

        var strUnfixedForWeb = strSpanned.UnfixForWeb(str.Length).ToString();

        Assert.Equal("abcd+/==", strUnfixedForWeb);
    }
}