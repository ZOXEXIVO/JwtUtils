using System;
using System.Collections.Generic;
using System.Linq;
using JwtUtils.Extensions;
using JwtUtils.Json;
using Xunit;

namespace JwtUtils.Tests.Common;

public class ComplexSerializerTests
{
    private const string TokenSecret = "test-secret-key-12345";

    [Fact]
    public void JwtUtils_ComplexTokenData_SerializeDeserialize_IsCorrect()
    {
        // Arrange
        var complexPayload = new ComplexTokenData
        {
            UserId = 12345,
            Username = "john.doe@example.com",
            Email = "john.doe@example.com",
            Roles = new[] { "admin", "user", "moderator" },
            Permissions = new List<string> { "read", "write", "delete", "manage_users" },
            Metadata = new UserMetadata
            {
                Department = "Engineering",
                EmployeeId = 98765,
                HireDate = new DateTime(2020, 3, 15, 9, 30, 0, DateTimeKind.Utc),
                Salary = 85000.50m,
                Tags = new List<string> { "senior", "fullstack", "team-lead" },
                IsManager = true,
                DirectReports = new[] { 1001, 1002, 1003, 1004 }
            },
            Settings = new Dictionary<string, object>
            {
                { "theme", "dark" },
                { "notifications", true },
                { "max_sessions", 5 },
                { "timeout_minutes", 30.5 },
                { "features", new[] { "beta", "experimental" } }
            },
            Scores = new[] { 95.5, 87.2, 92.8, 89.1 },
            IsActive = true,
            Balance = 1250.75m,
            LastLogin = new DateTime(2024, 1, 15, 14, 30, 45, DateTimeKind.Utc),
            Expiration = DateTimeOffset.UtcNow.AddHours(1).ToUnixTimeSeconds(),
            IssuedAt = DateTimeOffset.UtcNow.ToUnixTimeSeconds(),
            NullableField = null
        };

        // Act
        var token = JWT.HS256.Create(complexPayload, TokenSecret);
        var isValid = JWT.HS256.ValidateSignature(token, TokenSecret);
        var deserializedPayload = JWT.Read<ComplexTokenData>(token);

        // Assert
        Assert.True(isValid);
        Assert.NotNull(deserializedPayload);

        // Basic fields
        Assert.Equal(complexPayload.UserId, deserializedPayload.UserId);
        Assert.Equal(complexPayload.Username, deserializedPayload.Username);
        Assert.Equal(complexPayload.Email, deserializedPayload.Email);
        Assert.Equal(complexPayload.IsActive, deserializedPayload.IsActive);
        Assert.Equal(complexPayload.Balance, deserializedPayload.Balance);
        Assert.Equal(complexPayload.Expiration, deserializedPayload.Expiration);
        Assert.Equal(complexPayload.IssuedAt, deserializedPayload.IssuedAt);
        Assert.Equal(complexPayload.NullableField, deserializedPayload.NullableField);

        // Arrays
        Assert.Equal(complexPayload.Roles.Length, deserializedPayload.Roles.Length);
        Assert.True(complexPayload.Roles.SequenceEqual(deserializedPayload.Roles));
        Assert.Equal(complexPayload.Scores.Length, deserializedPayload.Scores.Length);
        Assert.True(complexPayload.Scores.SequenceEqual(deserializedPayload.Scores));

        // Lists
        Assert.Equal(complexPayload.Permissions.Count, deserializedPayload.Permissions.Count);
        Assert.True(complexPayload.Permissions.SequenceEqual(deserializedPayload.Permissions));

        // Nested object
        Assert.NotNull(deserializedPayload.Metadata);
        Assert.Equal(complexPayload.Metadata.Department, deserializedPayload.Metadata.Department);
        Assert.Equal(complexPayload.Metadata.EmployeeId, deserializedPayload.Metadata.EmployeeId);
        Assert.Equal(complexPayload.Metadata.Salary, deserializedPayload.Metadata.Salary);
        Assert.Equal(complexPayload.Metadata.IsManager, deserializedPayload.Metadata.IsManager);
        Assert.True(complexPayload.Metadata.Tags.SequenceEqual(deserializedPayload.Metadata.Tags));
        Assert.True(complexPayload.Metadata.DirectReports.SequenceEqual(deserializedPayload.Metadata.DirectReports));

        // Dictionary (will be deserialized as Dictionary<string, object>)
        Assert.NotNull(deserializedPayload.Settings);
        Assert.Equal(complexPayload.Settings.Count, deserializedPayload.Settings.Count);
    }

    [Fact]
    public void JwtUtils_SimpleNestedData_SerializeDeserialize_IsCorrect()
    {
        // Arrange
        var nestedPayload = new SimpleNestedData
        {
            Id = 42,
            Name = "Test Object",
            Nested = new NestedObject
            {
                Value = "nested-value",
                Count = 100,
                Active = true
            },
            Items = new[] { 1, 2, 3, 4, 5 }
        };

        // Act
        var token = JWT.HS512.Create(nestedPayload, TokenSecret);
        var isValid = JWT.HS512.ValidateSignature(token, TokenSecret);
        var deserializedPayload = JWT.Read<SimpleNestedData>(token);

        // Assert
        Assert.True(isValid);
        Assert.NotNull(deserializedPayload);
        Assert.Equal(nestedPayload.Id, deserializedPayload.Id);
        Assert.Equal(nestedPayload.Name, deserializedPayload.Name);
        Assert.True(nestedPayload.Items.SequenceEqual(deserializedPayload.Items));

        Assert.NotNull(deserializedPayload.Nested);
        Assert.Equal(nestedPayload.Nested.Value, deserializedPayload.Nested.Value);
        Assert.Equal(nestedPayload.Nested.Count, deserializedPayload.Nested.Count);
        Assert.Equal(nestedPayload.Nested.Active, deserializedPayload.Nested.Active);
    }

    [Fact]
    public void JwtUtils_ComplexDictionary_Untyped_IsCorrect()
    {
        // Arrange
        var complexDictionary = new Dictionary<string, object>
        {
            { "string_field", "hello world" },
            { "int_field", 42 },
            { "long_field", 1234567890L },
            { "double_field", 3.14159 },
            { "bool_field", true },
            { "array_field", new[] { "a", "b", "c" } },
            { "number_array", new[] { 1, 2, 3, 4, 5 } },
            { "nested_dict", new Dictionary<string, object>
                {
                    { "inner_string", "inner value" },
                    { "inner_number", 99 },
                    { "inner_bool", false }
                }
            },
            { "exp", DateTimeOffset.UtcNow.AddHours(1).ToUnixTimeSeconds() }
        };

        // Act
        var token = JWT.HS384.Create(complexDictionary, TokenSecret);
        var isValid = JWT.HS384.ValidateSignature(token, TokenSecret);
        var deserializedData = JWT.Read(token);

        // Assert
        Assert.True(isValid);
        Assert.NotNull(deserializedData);

        Assert.Equal("hello world", deserializedData["string_field"]);
        Assert.Equal(42L, deserializedData["int_field"]); // Numbers are deserialized as long
        Assert.Equal(1234567890L, deserializedData["long_field"]);
        Assert.Equal(3.14159, (double)deserializedData["double_field"], 5);
        Assert.Equal(true, deserializedData["bool_field"]);

        // Test expiration extension method
        var exp = deserializedData.Exp();
        Assert.NotNull(exp);
        Assert.True(exp > DateTimeOffset.UtcNow.ToUnixTimeSeconds());
    }

    [Fact]
    public void JwtUtils_ExtensionMethods_WithComplexData_IsCorrect()
    {
        // Arrange
        var payload = new Dictionary<string, object>
        {
            { "exp", 1699999999L },
            { "iat", 1699999900L },
            { "user_id", 12345 },
            { "score", 95.5 },
            { "is_admin", true },
            { "username", "testuser" }
        };

        // Act
        var token = JWT.HS256.Create(payload, TokenSecret);
        var deserializedData = JWT.Read(token);

        // Assert - Test extension methods
        var exp = deserializedData.Exp();
        var userId = deserializedData.Get<int>("user_id");
        var score = deserializedData.Get<double>("score");
        var isAdmin = deserializedData.Get<bool>("is_admin");
        var iat = deserializedData.Get<long>("iat");

        Assert.Equal(1699999999L, exp);
        Assert.Equal(12345, userId);
        Assert.Equal(95.5, score);
        Assert.True(isAdmin);
        Assert.Equal(1699999900L, iat);
    }

    [Fact]
    public void JwtUtils_SpecialCharacters_InStrings_IsCorrect()
    {
        // Arrange
        var payload = new Dictionary<string, object>
        {
            { "message", "Hello \"World\" with \n newlines and \t tabs" },
            { "json_string", "{\"key\": \"value with \\\"quotes\\\"\"}" },
            { "unicode", "Unicode: 🚀 🌟 ❤️" },
            { "escaped", "Line 1\nLine 2\rCarriage\tTab\\Backslash" },
            { "exp", DateTimeOffset.UtcNow.AddMinutes(30).ToUnixTimeSeconds() }
        };

        // Act
        var token = JWT.HS256.Create(payload, TokenSecret);
        var isValid = JWT.HS256.ValidateSignature(token, TokenSecret);
        var deserializedData = JWT.Read(token);

        // Assert
        Assert.True(isValid);
        Assert.Equal(payload["message"], deserializedData["message"]);
        Assert.Equal(payload["json_string"], deserializedData["json_string"]);
        Assert.Equal(payload["unicode"], deserializedData["unicode"]);
        Assert.Equal(payload["escaped"], deserializedData["escaped"]);
    }

    [Fact]
    public void JwtUtils_NullAndEmptyValues_IsCorrect()
    {
        // Arrange
        var payload = new Dictionary<string, object>
        {
            { "null_field", null },
            { "empty_string", "" },
            { "empty_array", new object[0] },
            { "zero_number", 0 },
            { "false_bool", false },
            { "exp", DateTimeOffset.UtcNow.AddMinutes(15).ToUnixTimeSeconds() }
        };

        // Act
        var token = JWT.HS256.Create(payload, TokenSecret);
        var isValid = JWT.HS256.ValidateSignature(token, TokenSecret);
        var deserializedData = JWT.Read(token);

        // Assert
        Assert.True(isValid);
        Assert.Null(deserializedData["null_field"]);
        Assert.Equal("", deserializedData["empty_string"]);
        Assert.IsType<object[]>(deserializedData["empty_array"]);
        Assert.Empty((object[])deserializedData["empty_array"]);
        Assert.Equal(0L, deserializedData["zero_number"]);
        Assert.Equal(false, deserializedData["false_bool"]);
    }
}

public class ComplexTokenData
{
    [JsonPropertyName("user_id")]
    public int UserId { get; set; }

    [JsonPropertyName("username")]
    public string Username { get; set; }

    [JsonPropertyName("email")]
    public string Email { get; set; }

    [JsonPropertyName("roles")]
    public string[] Roles { get; set; }

    [JsonPropertyName("permissions")]
    public List<string> Permissions { get; set; }

    [JsonPropertyName("metadata")]
    public UserMetadata Metadata { get; set; }

    [JsonPropertyName("settings")]
    public Dictionary<string, object> Settings { get; set; }

    [JsonPropertyName("scores")]
    public double[] Scores { get; set; }
    
    [JsonPropertyName("is_active")]
    public bool IsActive { get; set; }

    [JsonPropertyName("balance")]
    public decimal Balance { get; set; }

    [JsonPropertyName("last_login")]
    public DateTime LastLogin { get; set; }

    [JsonPropertyName("exp")]
    public long Expiration { get; set; }

    [JsonPropertyName("iat")]
    public long IssuedAt { get; set; }

    [JsonPropertyName("nullable_field")]
    public int? NullableField { get; set; }
}

public class UserMetadata
{
    [JsonPropertyName("department")]
    public string Department { get; set; }

    [JsonPropertyName("employee_id")]
    public int EmployeeId { get; set; }

    [JsonPropertyName("hire_date")]
    public DateTime HireDate { get; set; }

    [JsonPropertyName("salary")]
    public decimal Salary { get; set; }

    [JsonPropertyName("tags")]
    public List<string> Tags { get; set; }

    [JsonPropertyName("is_manager")]
    public bool IsManager { get; set; }

    [JsonPropertyName("direct_reports")]
    public int[] DirectReports { get; set; }
}

public class SimpleNestedData
{
    [JsonPropertyName("id")]
    public int Id { get; set; }

    [JsonPropertyName("name")]
    public string Name { get; set; }

    [JsonPropertyName("nested")]
    public NestedObject Nested { get; set; }

    [JsonPropertyName("items")]
    public int[] Items { get; set; }
}

public class NestedObject
{
    [JsonPropertyName("value")]
    public string Value { get; set; }

    [JsonPropertyName("count")]
    public int Count { get; set; }

    [JsonPropertyName("active")]
    public bool Active { get; set; }
}