Absolutely! Here's a C# implementation for generating Snowflake JWT tokens using only built-in .NET libraries without BouncyCastle:

## C# JWT Generator for Snowflake (No BouncyCastle)

### Required NuGet Packages

You only need these standard JWT packages:

```xml
<PackageReference Include="System.IdentityModel.Tokens.Jwt" Version="7.0.3" />
<PackageReference Include="Microsoft.IdentityModel.Tokens" Version="7.0.3" />
```

### Complete Implementation

```csharp
using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text.RegularExpressions;

public class SnowflakeJwtGenerator
{
    private readonly string _account;
    private readonly string _user;
    private readonly RSA _privateKey;
    private readonly string _publicKeyFingerprint;

    public SnowflakeJwtGenerator(string account, string user, string privateKeyPath, string passphrase = null)
    {
        _account = account.ToUpper().Replace(".", "-"); // Replace periods with hyphens as required by Snowflake
        _user = user.ToUpper();
        _privateKey = LoadPrivateKey(privateKeyPath, passphrase);
        _publicKeyFingerprint = GeneratePublicKeyFingerprint(_privateKey);
    }

    /// <summary>
    /// Generates a JWT token for Snowflake authentication
    /// </summary>
    /// <param name="lifetimeMinutes">Token lifetime in minutes (default: 59)</param>
    /// <returns>JWT token string</returns>
    public string GenerateJwtToken(int lifetimeMinutes = 59)
    {
        var now = DateTimeOffset.UtcNow;
        var expiry = now.AddMinutes(lifetimeMinutes);

        // Create the issuer string: ACCOUNT.USER.SHA256:fingerprint
        var issuer = $"{_account}.{_user}.SHA256:{_publicKeyFingerprint}";
        var subject = $"{_account}.{_user}";

        var tokenHandler = new JwtSecurityTokenHandler();
        var key = new RsaSecurityKey(_privateKey);
        var credentials = new SigningCredentials(key, SecurityAlgorithms.RsaSha256);

        var tokenDescriptor = new SecurityTokenDescriptor
        {
            Subject = new ClaimsIdentity(new[]
            {
                new Claim(JwtRegisteredClaimNames.Iss, issuer),
                new Claim(JwtRegisteredClaimNames.Sub, subject),
                new Claim(JwtRegisteredClaimNames.Iat, 
                    new DateTimeOffset(now.DateTime).ToUnixTimeSeconds().ToString(), 
                    ClaimValueTypes.Integer64)
            }),
            Expires = expiry.DateTime,
            IssuedAt = now.DateTime,
            SigningCredentials = credentials
        };

        var token = tokenHandler.CreateToken(tokenDescriptor);
        return tokenHandler.WriteToken(token);
    }

    /// <summary>
    /// Loads RSA private key from PEM file using built-in .NET methods
    /// </summary>
    private RSA LoadPrivateKey(string privateKeyPath, string passphrase)
    {
        var privateKeyText = File.ReadAllText(privateKeyPath);
        var rsa = RSA.Create();

        try
        {
            if (!string.IsNullOrEmpty(passphrase))
            {
                // For encrypted keys (.NET 5.0+)
                rsa.ImportEncryptedPkcs8PrivateKey(Encoding.UTF8.GetBytes(passphrase), 
                    Convert.FromBase64String(ExtractBase64FromPem(privateKeyText)));
            }
            else
            {
                // For unencrypted keys
                rsa.ImportFromPem(privateKeyText);
            }
        }
        catch (Exception ex)
        {
            // Fallback: try different import methods
            try
            {
                var keyBytes = Convert.FromBase64String(ExtractBase64FromPem(privateKeyText));
                
                if (!string.IsNullOrEmpty(passphrase))
                {
                    rsa.ImportEncryptedPkcs8PrivateKey(Encoding.UTF8.GetBytes(passphrase), keyBytes);
                }
                else
                {
                    rsa.ImportPkcs8PrivateKey(keyBytes, out _);
                }
            }
            catch
            {
                throw new InvalidOperationException($"Unable to load private key: {ex.Message}");
            }
        }

        return rsa;
    }

    /// <summary>
    /// Extracts Base64 content from PEM format
    /// </summary>
    private string ExtractBase64FromPem(string pemContent)
    {
        var lines = pemContent.Split('\n');
        var base64Content = new StringBuilder();
        
        bool inKey = false;
        foreach (var line in lines)
        {
            var trimmedLine = line.Trim();
            if (trimmedLine.StartsWith("-----BEGIN"))
            {
                inKey = true;
                continue;
            }
            if (trimmedLine.StartsWith("-----END"))
            {
                break;
            }
            if (inKey)
            {
                base64Content.Append(trimmedLine);
            }
        }
        
        return base64Content.ToString();
    }

    /// <summary>
    /// Generates SHA-256 fingerprint of the public key
    /// </summary>
    private string GeneratePublicKeyFingerprint(RSA rsa)
    {
        var publicKeyBytes = rsa.ExportRSAPublicKey();
        using (var sha256 = SHA256.Create())
        {
            var hash = sha256.ComputeHash(publicKeyBytes);
            return Convert.ToBase64String(hash);
        }
    }

    /// <summary>
    /// Gets the public key fingerprint (useful for verification)
    /// </summary>
    public string GetPublicKeyFingerprint()
    {
        return _publicKeyFingerprint;
    }

    /// <summary>
    /// Disposes the RSA key
    /// </summary>
    public void Dispose()
    {
        _privateKey?.Dispose();
    }
}
```

### Simplified Static Version

For simpler use cases with unencrypted keys:

```csharp
public static class SimpleSnowflakeJwt
{
    /// <summary>
    /// Generates JWT token for Snowflake authentication (unencrypted keys only)
    /// </summary>
    public static string GenerateToken(string account, string user, string privateKeyPath, int lifetimeMinutes = 59)
    {
        // Load private key
        var privateKeyText = File.ReadAllText(privateKeyPath);
        using var rsa = RSA.Create();
        rsa.ImportFromPem(privateKeyText);

        // Generate public key fingerprint
        var publicKeyBytes = rsa.ExportRSAPublicKey();
        var fingerprint = Convert.ToBase64String(SHA256.HashData(publicKeyBytes));

        // Prepare account and user (uppercase, replace periods with hyphens)
        var accountFormatted = account.ToUpper().Replace(".", "-");
        var userFormatted = user.ToUpper();

        // Create JWT claims
        var now = DateTimeOffset.UtcNow;
        var expiry = now.AddMinutes(lifetimeMinutes);

        var issuer = $"{accountFormatted}.{userFormatted}.SHA256:{fingerprint}";
        var subject = $"{accountFormatted}.{userFormatted}";

        var tokenHandler = new JwtSecurityTokenHandler();
        var key = new RsaSecurityKey(rsa);
        var credentials = new SigningCredentials(key, SecurityAlgorithms.RsaSha256);

        var tokenDescriptor = new SecurityTokenDescriptor
        {
            Subject = new ClaimsIdentity(new[]
            {
                new Claim(JwtRegisteredClaimNames.Iss, issuer),
                new Claim(JwtRegisteredClaimNames.Sub, subject),
                new Claim(JwtRegisteredClaimNames.Iat, 
                    now.ToUnixTimeSeconds().ToString(), 
                    ClaimValueTypes.Integer64)
            }),
            Expires = expiry.DateTime,
            IssuedAt = now.DateTime,
            SigningCredentials = credentials
        };

        var token = tokenHandler.CreateToken(tokenDescriptor);
        return tokenHandler.WriteToken(token);
    }
}
```

### Usage Examples

#### Basic Usage (Unencrypted Key)

```csharp
public class Program
{
    public static void Main()
    {
        try
        {
            var account = "MYORGANIZATION-MYACCOUNT";
            var user = "MYUSER";
            var privateKeyPath = @"C:\path\to\rsa_key.pem";

            // Simple method for unencrypted keys
            var jwtToken = SimpleSnowflakeJwt.GenerateToken(account, user, privateKeyPath);
            
            Console.WriteLine("Generated JWT Token:");
            Console.WriteLine(jwtToken);
        }
        catch (Exception ex)
        {
            Console.WriteLine($"Error: {ex.Message}");
        }
    }
}
```

#### Advanced Usage (With Encrypted Key Support)

```csharp
public class Program
{
    public static void Main()
    {
        try
        {
            var account = "MYORGANIZATION-MYACCOUNT";
            var user = "MYUSER";
            var privateKeyPath = @"C:\path\to\rsa_key.p8";
            var passphrase = "your_passphrase"; // null for unencrypted keys

            using var jwtGenerator = new SnowflakeJwtGenerator(account, user, privateKeyPath, passphrase);
            
            var jwtToken = jwtGenerator.GenerateJwtToken(59); // 59 minutes lifetime
            
            Console.WriteLine("Generated JWT Token:");
            Console.WriteLine(jwtToken);
            Console.WriteLine($"Public Key Fingerprint: SHA256:{jwtGenerator.GetPublicKeyFingerprint()}");
        }
        catch (Exception ex)
        {
            Console.WriteLine($"Error: {ex.Message}");
        }
    }
}
```

### HTTP Client Usage

```csharp
public class SnowflakeApiClient
{
    private readonly HttpClient _httpClient;
    private readonly SnowflakeJwtGenerator _jwtGenerator;

    public SnowflakeApiClient(string account, string user, string privateKeyPath, string passphrase = null)
    {
        _httpClient = new HttpClient();
        _jwtGenerator = new SnowflakeJwtGenerator(account, user, privateKeyPath, passphrase);
        
        // Set base URL
        _httpClient.BaseAddress = new Uri($"https://{account.ToLower()}.snowflakecomputing.com/");
    }

    public async Task<string> ExecuteSqlAsync(string sql)
    {
        // Generate fresh JWT token
        var jwtToken = _jwtGenerator.GenerateJwtToken();
        
        // Set authorization header
        _httpClient.DefaultRequestHeaders.Authorization = 
            new System.Net.Http.Headers.AuthenticationHeaderValue("Bearer", jwtToken);

        // Prepare SQL request
        var requestBody = new
        {
            statement = sql,
            timeout = 60,
            database = "YOUR_DATABASE",
            schema = "YOUR_SCHEMA",
            warehouse = "YOUR_WAREHOUSE"
        };

        var json = System.Text.Json.JsonSerializer.Serialize(requestBody);
        var content = new StringContent(json, Encoding.UTF8, "application/json");

        // Execute request
        var response = await _httpClient.PostAsync("api/v2/statements", content);
        return await response.Content.ReadAsStringAsync();
    }

    public void Dispose()
    {
        _httpClient?.Dispose();
        _jwtGenerator?.Dispose();
    }
}
```

### Key Features

1. **No External Dependencies**: Uses only built-in .NET cryptography libraries
2. **Encrypted Key Support**: Handles both encrypted and unencrypted private keys
3. **Proper Formatting**: Automatically formats account identifiers and usernames per Snowflake requirements
4. **Error Handling**: Comprehensive error handling for key loading issues
5. **Memory Management**: Proper disposal of cryptographic resources
6. **Flexible Lifetime**: Configurable token lifetime (default 59 minutes)

### .NET Version Requirements

- **.NET 5.0+**: Full support for encrypted keys
- **.NET Core 3.1+**: Basic support (unencrypted keys work best)
- **.NET Framework 4.7.2+**: Limited support (may require additional setup for some PEM formats)

This implementation provides all the functionality you need for Snowflake JWT authentication without any external dependencies beyond the standard Microsoft JWT libraries.
