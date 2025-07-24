## JWTExample

JWT Example



### Key Requirements for Snowflake JWT

Based on the documentation, ensure your JWT meets these requirements:

- Algorithm: Must use RS256 (RSA with SHA-256)
- Issuer (iss): Format: ACCOUNT.USER.SHA256:public_key_fingerprint
- Subject (sub): Format: ACCOUNT.USER
- Account and User: Must be in UPPERCASE
- Key Size: Minimum 2048-bit RSA key pair
- Token Lifetime: Recommended maximum 59 minutes


#### Versions

Alternative Simplified Version (for unencrypted keys) - SimpleSnowflakeJwtGenerator.cs

For encrypted keys - SnowflakeJwtGenerator.cs


#### Prerequisites

Before using this code:

-Generate RSA Key Pair: Use OpenSSL to generate your public/private key pair
-Assign Public Key: Assign the public key to your Snowflake user using ALTER USER
-Verify Setup: Test withSnowSQL using the private key1

.NET Package Requirements

````
<PackageReference Include="System.IdentityModel.Tokens.Jwt" Version="7.0.3" />
<PackageReference Include="Microsoft.IdentityModel.Tokens" Version="7.0.3" />
<PackageReference Include="Portable.BouncyCastle" Version="1.9.0" />
````


#### Usage with Snowflake APIs

Once you have the JWT token, use it in your API calls:


````

// Example HTTP client usage
var client = new HttpClient();
client.DefaultRequestHeaders.Authorization = 
    new System.Net.Http.Headers.AuthenticationHeaderValue("Bearer", jwtToken);

// Make your Snowflake API calls
var response = await client.PostAsync("https://your-account.snowflakecomputing.com/api/v2/statements", content);

````



#### Resources

* https://learn.microsoft.com/en-us/answers/questions/2280672/how-to-connect-to-snowflake-using-net

* https://docs.snowflake.com/en/user-guide/key-pair-auth
