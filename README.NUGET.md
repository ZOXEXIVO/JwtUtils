# JwtUtils

Fastest, low-allocation, simple API library to work with JWT-tokens

It wrap most useful API to work with JWT (Create, Validate, Read)

Now you don't need to use strange and inconvenient API in other packages<br/><br/>


##### Available algorithms:

Symmetric: **HS256, HS384, HS512**

Asymmetric: **RS256, RS384, RS512**


###Benchmarks:

Comparing [JwtUtils](https://github.com/ZOXEXIVO/JwtUtils) (Current) VS [JWT-Dotnet](https://github.com/jwt-dotnet/jwt) VS [System.IdentityModel.Tokens.Jwt](https://duckduckgo.com)

See https://github.com/ZOXEXIVO/JwtUtils

## Usage

### Symmetric algorithms: HS256, HS384, HS512

#### Create (Untyped payload)

 ```C# 
 var claims =  new Dictionary<string, object>
 {
    { "exp", 1639942616 },
    { "uname", "i.a.ivanov" },
    { "claim1", "claim1_value" },   
    { "claims_array", new [] {"claim_item1", "claim_item2"}}
};
        
var token = JWT.HS256.Create(claims, "{TOKEN_SECRET}");
```

#### Create (Typed payload)

 ```C#
public class JwtPayload
{
    [JsonPropertyName("uid")] 
    public int UserId { get; set; }
}
        
var payload =  new JwtPayload
{
    UserId = 123
};
        
var token = JWT.HS256.Create(payload, "{TOKEN_SECRET}");
```

#### Validate

```C#
string token = "{YOUR_JWT_TOKEN}";
string tokenSecret = "{TOKEN_SECRET}";

if (JWT.HS256.ValidateSignature(token, tokenSecret))
{
   // Token signature valid
}
```

#### Read

```C#
string token = "{JWT-TOKEN}";

// Default - no typed
var tokenResult = JWT.Read(tokenSecret);
var expiration = token.Exp();

// You can map Jwt to your own model
var tokenResult = JWT.Read<CustomJwtModel>(tokenSecret);
```

### Asymmetric algorithms: RS256, RS384, RS512

#### Create (Untyped payload)

 ```C#
 // Private key in default PEM format
 string privateKey = "@"MIIJKgIBAAKCAgEA9GF97STxVGbXpBFmudS/RRT58mfiR/+t2zb4f/uF3qmYb/yu
                        b3CtKwYPtGkQncSvba2HSurYArAxsCU2QeSAYbmCgtiXcF2Hw8Xt/ADY711iBDwq
                        .............................................
                        O9wqUEJy2v8xOMbHvMkoKLPLc590zGV88HNvzJHkF5N5HWTB9ZZEWcehf6RcTA==";
        
var payload =  new Dictionary<string, object>
{
    { "exp", 1639942616 },
    { "uname", "i.a.ivanov" },
    { "claim1", "claim1_value" },
    { "claim2", "claim2_value" },
    { "claim3", "claim3_value" },
    { "claims_array", new [] {"claim_item1", "claim_item2"}}
};
        
var token = JWT.RS256.Create(payload, privateKey);
```

#### Create (Typed payload)

 ```C#
 // Private key in default PEM format
 string privateKey = "@"MIIJKgIBAAKCAgEA9GF97STxVGbXpBFmudS/RRT58mfiR/+t2zb4f/uF3qmYb/yu
                        b3CtKwYPtGkQncSvba2HSurYArAxsCU2QeSAYbmCgtiXcF2Hw8Xt/ADY711iBDwq
                        .............................................
                        O9wqUEJy2v8xOMbHvMkoKLPLc590zGV88HNvzJHkF5N5HWTB9ZZEWcehf6RcTA==";
        
public class JwtPayload
{
   [JsonPropertyName("uid")] 
   public int UserId { get; set; }
}
        
var payload =  new JwtPayload
{
    UserId = 123
};
        
var token = JWT.RS256.Create(payload, privateKey);
```

#### Validate

```C#
// Public key with PEM format
string publicKey = "@"MIIJKgIBAAKCAgEA9GF97STxVGbXpBFmudS/RRT58mfiR/+t2zb4f/uF3qmYb/yu
                       b3CtKwYPtGkQncSvba2HSurYArAxsCU2QeSAYbmCgtiXcF2Hw8Xt/ADY711iBDwq
                       .............................................
                       O9wqUEJy2v8xOMbHvMkoKLPLc590zGV88HNvzJHkF5N5HWTB9ZZEWcehf6RcTA==";

if (JWT.RS256.ValidateSignature("{YOUR_JWT_TOKEN}", publicKey))
{
   // Token signature valid
}
```

#### Read

```C#
string token = "{JWT-TOKEN}";

// Default - untyped Dictionary<string, object>
var tokenResult = JWT.Read(token);
var expiration = token.Exp();

// You can map Jwt to your own model
var tokenResult = JWT.Read<CustomJwtModel>(token); 
```