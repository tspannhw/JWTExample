using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;

public class SimpleSnowflakeJwtGenerator
{
    public static string GenerateJwtToken(string account, string user, string privateKeyPath, int lifetimeMinutes = 59)
    {
        // Load private key
        var privateKeyText = File.ReadAllText(privateKeyPath);
        var rsa = RSA.Create();
        rsa.ImportFromPem(privateKeyText);

        // Generate public key fingerprint
        var publicKey = rsa.ExportRSAPublicKey();
        var fingerprint = Convert.ToBase64String(SHA256.HashData(publicKey));

        // Create JWT
        var now = DateTimeOffset.UtcNow;
        var expiry = now.AddMinutes(lifetimeMinutes);

        var issuer = $"{account.ToUpper()}.{user.ToUpper()}.SHA256:{fingerprint}";
        var subject = $"{account.ToUpper()}.{user.ToUpper()}";

        var tokenHandler = new JwtSecurityTokenHandler();
        var key = new RsaSecurityKey(rsa);
        var credentials = new SigningCredentials(key, SecurityAlgorithms.RsaSha256);

        var tokenDescriptor = new SecurityTokenDescriptor
        {
            Subject = new ClaimsIdentity(new[]
            {
                new Claim("iss", issuer),
                new Claim("sub", subject)
            }),
            Expires = expiry.DateTime,
            IssuedAt = now.DateTime,
            SigningCredentials = credentials
        };

        var token = tokenHandler.CreateToken(tokenDescriptor);
        return tokenHandler.WriteToken(token);
    }
}
