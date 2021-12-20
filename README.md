# JwtUtils

[![Build Status](http://drone.zoxexivo.com/api/badges/ZOXEXIVO/JwtUtils/status.svg)](http://drone.zoxexivo.com/ZOXEXIVO/JwtUtils)

Fastest, low-allocation library to work with JWT-tokens

It wrap most useful API to work with JWT (Create, Validate, Read)

If you have simple app - you no need to work with dubious standard API: JwtSecurityTokenHandler e.t.c

Benchmarks:
[HS256, HS384, HS512]
![Symmetric algorithms](.//Docs/Symmetric.jpg)

[RS256, RS384, RS512]
![Symmetric algorithms](.//Docs/Asymmetric.jpg)

## Usage

### Symmetric algorithms: HS256, HS384, HS512

#### Create

 ```C#
 string tokenSecret = "{TOKEN_SECRET}";
        
 var claims =  new Dictionary<string, object>
 {
    { "exp", 1639942616 },
    { "uname", "i.a.ivanov" },
    { "claim1", "claim1_value" },
    { "claim2", "claim2_value" },
    { "claim3", "claim3_value" },
    { "claims_array", new [] {"claim_item1", "claim_item2"}}
};
        
var token = SymmetricToken.HS256.Create(claims, tokenSecret);
```

#### Validate

```C#
 string token = "{YOUR_JWT_TOKEN}";
 string tokenSecret = "{TOKEN_SECRET}";

 if (SymmetricToken.HS256.ValidateSignature(token, tokenSecret))
 {
    // Token signature valid
 }
        
```

#### Read

```C#
string token = "{JWT-TOKEN}";

// Default - no typed
var tokenResult = SymmetricToken.HS256.Read(tokenSecret);
var expiration = token.Exp();

// You can map Jwt to your own model
var tokenResult = SymmetricToken.HS256.Read<CustomJwtModel>(tokenSecret);
        
```

### Asymmetric algorithms: RS256, RS384, RS512

#### Create

 ```C#
 // Private key in default PEM format
 string privateKey = "@"MIIJKgIBAAKCAgEA9GF97STxVGbXpBFmudS/RRT58mfiR/+t2zb4f/uF3qmYb/yu
                        b3CtKwYPtGkQncSvba2HSurYArAxsCU2QeSAYbmCgtiXcF2Hw8Xt/ADY711iBDwq
                        .............................................
                        O9wqUEJy2v8xOMbHvMkoKLPLc590zGV88HNvzJHkF5N5HWTB9ZZEWcehf6RcTA==";
        
 var claims =  new Dictionary<string, object>
 {
    { "exp", 1639942616 },
    { "uname", "i.a.ivanov" },
    { "claim1", "claim1_value" },
    { "claim2", "claim2_value" },
    { "claim3", "claim3_value" },
    { "claims_array", new [] {"claim_item1", "claim_item2"}}
};
        
var token = AsymmetricToken.RS256.Create(claims, privateKey);
```

#### Validate

```C#
 string token = "{YOUR_JWT_TOKEN}";
 // Public key with PEM format
 string publicKey = "@"MIIJKgIBAAKCAgEA9GF97STxVGbXpBFmudS/RRT58mfiR/+t2zb4f/uF3qmYb/yu
                        b3CtKwYPtGkQncSvba2HSurYArAxsCU2QeSAYbmCgtiXcF2Hw8Xt/ADY711iBDwq
                        .............................................
                        O9wqUEJy2v8xOMbHvMkoKLPLc590zGV88HNvzJHkF5N5HWTB9ZZEWcehf6RcTA==";

 if (AsymmetricToken.RS256.ValidateSignature(token, publicKey))
 {
    // Token signature valid
 }
        
```

#### Read

```C#
string token = "{JWT-TOKEN}";

// Default - no typed
var tokenResult = AsymmetricToken.RS256.Read(tokenSecret);
var expiration = token.Exp();

// You can map Jwt to your own model
var tokenResult = AsymmetricToken.RS256.Read<CustomJwtModel>(tokenSecret);
        
```