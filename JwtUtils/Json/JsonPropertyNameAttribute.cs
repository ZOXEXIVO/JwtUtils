namespace JwtUtils.Json;

/// <summary>
/// Custom JsonPropertyName attribute to replace System.Text.Json dependency
/// </summary>
[AttributeUsage(AttributeTargets.Property | AttributeTargets.Field)]
public sealed class JsonPropertyNameAttribute : Attribute
{
    public string Name { get; }

    public JsonPropertyNameAttribute(string name)
    {
        Name = name ?? throw new ArgumentNullException(nameof(name));
    }
}