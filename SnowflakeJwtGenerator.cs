using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.OpenSsl;
using Org.BouncyCastle.Security;

public class SnowflakeJwtGenerator
{
    private readonly string _account;
    private readonly string _user;
    private readonly RSA _privateKey;
    private readonly string _publicKeyFingerprint;

    public SnowflakeJwtGenerator(string account, string user, string privateKeyPath, string passphrase = null)
    {
        _account = account.ToUpper();
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

    /// <summary>
    /// Loads RSA private key from file (supports both encrypted and unencrypted keys)
    /// </summary>
    private RSA LoadPrivateKey(string privateKeyPath, string passphrase)
    {
        var privateKeyText = File.ReadAllText(privateKeyPath);
        
        using (var stringReader = new StringReader(privateKeyText))
        {
            var pemReader = new PemReader(stringReader, new PasswordFinder(passphrase));
            var keyObject = pemReader.ReadObject();

            AsymmetricKeyParameter privateKeyParam;

            if (keyObject is AsymmetricCipherKeyPair keyPair)
            {
                privateKeyParam = keyPair.Private;
            }
            else if (keyObject is AsymmetricKeyParameter keyParam)
            {
                privateKeyParam = keyParam;
            }
            else
            {
                throw new InvalidOperationException("Unable to read private key from file");
            }

            // ConvertBouncyCastle key to .NET RSA
            var rsaParams = DotNetUtilities.ToRSAParameters((RsaPrivateCrtKeyParameters)privateKeyParam);
            var rsa = RSA.Create();
            rsa.ImportParameters(rsaParams);
            return rsa;
        }
    }

    /// <summary>
    /// Generates SHA-256 fingerprint of the public key
    /// </summary>
    private string GeneratePublicKeyFingerprint(RSA rsa)
    {
        var publicKey = rsa.ExportRSAPublicKey();
        using (var sha256 = SHA256.Create())
        {
            var hash = sha256.ComputeHash(publicKey);
            return Convert.ToBase64String(hash);
        }
    }

    /// <summary>
    /// Helper class for handling encrypted private keys
    /// </summary>
    private class PasswordFinder : IPasswordFinder
    {
        private readonly string _password;

        public PasswordFinder(string password)
        {
            _password = password;
        }

        public char[] GetPassword()
        {
            return _password?.ToCharArray();
        }
    }
}

// Usage example
public class Program
{
    public static void Main()
    {
        try
        {
            // Configuration
            var account = "MYORGANIZATION-MYACCOUNT";  // Your Snowflake account identifier
            var user = "MYUSER";                       // Your Snowflake username
            var privateKeyPath = "path/to/rsa_key.p8"; // Path to your private key file
            var passphrase = "your_passphrase";        // Passphrase (if key is encrypted)

            // Create JWT generator
            var jwtGenerator = new SnowflakeJwtGenerator(account, user, privateKeyPath, passphrase);

            // Generate JWT token
            var jwtToken = jwtGenerator.GenerateJwtToken();

            Console.WriteLine("Generated JWT Token:");
            Console.WriteLine(jwtToken);

            // You can now use this token for Snowflake API calls
            // Example: Add as Authorization header: "Bearer " + jwtToken
        }
        catch (Exception ex)
        {
            Console.WriteLine($"Error generating JWT: {ex.Message}");
        }
    }
}
