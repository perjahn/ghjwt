using System;
using System.IO;
using System.Collections.Generic;
using System.Security.Cryptography;
using Jose;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.OpenSsl;

public class Program
{
    public static int Main(string[] args)
    {
        if (args.Length != 3)
        {
            Console.WriteLine("Usage: ghjwt <private key file> <app integration id> <expiration seconds>");
            return 1;
        }

        var filename = args[0];
        if (!File.Exists(filename))
        {
            Console.WriteLine($"File not found: '{filename}'");
            return 1;
        }
        if (!int.TryParse(args[1], out var appIntegrationId))
        {
            Console.WriteLine($"Invalid app integration id: '{args[1]}'");
            return 1;
        }
        if (!int.TryParse(args[2], out var expirationSeconds))
        {
            Console.WriteLine($"Invalid expiration seconds: '{args[2]}'");
            return 1;
        }

        var token = GetJwt(filename, appIntegrationId, expirationSeconds);

        Console.WriteLine(token);

        return 0;
    }

    static string GetJwt(string privateKeyFilename, int appIntegrationId, int expirationSeconds)
    {
        using var privateKeyReader = new StreamReader(privateKeyFilename);

        var pemReader = new PemReader(privateKeyReader);
        if (pemReader.ReadObject() is not AsymmetricCipherKeyPair keyPair)
        {
            Console.WriteLine($"Expected RSA private key, got: {pemReader.ReadObject().GetType().Name}");
            return string.Empty;
        }
        if (keyPair.Private is not RsaPrivateCrtKeyParameters privKey)
        {
            Console.WriteLine($"Expected RSA private key, got: {keyPair.Private.GetType().Name}");
            return string.Empty;
        }

        var rp = new RSAParameters
        {
            Modulus = privKey.Modulus.ToByteArrayUnsigned(),
            Exponent = privKey.PublicExponent.ToByteArrayUnsigned(),
            P = privKey.P.ToByteArrayUnsigned(),
            Q = privKey.Q.ToByteArrayUnsigned()
        };
        rp.D = ConvertRSAParametersField(privKey.Exponent, rp.Modulus.Length);
        rp.DP = ConvertRSAParametersField(privKey.DP, rp.P.Length);
        rp.DQ = ConvertRSAParametersField(privKey.DQ, rp.Q.Length);
        rp.InverseQ = ConvertRSAParametersField(privKey.QInv, rp.Q.Length);

        using var rsa = new RSACryptoServiceProvider();

        rsa.ImportParameters(rp);

        var utcNow = DateTime.UtcNow;
        var ticksSince1970 = new DateTime(1970, 1, 1).Ticks;
        var iat = (utcNow.ToUniversalTime().Ticks - ticksSince1970) / TimeSpan.TicksPerSecond;
        var exp = (utcNow.AddSeconds(expirationSeconds).ToUniversalTime().Ticks - ticksSince1970) / TimeSpan.TicksPerSecond;

        var payload = new Dictionary<string, object> { { "iat", iat }, { "exp", exp }, { "iss", appIntegrationId } };

        return JWT.Encode(payload, rsa, JwsAlgorithm.RS256);
    }

    static byte[] ConvertRSAParametersField(BigInteger n, int size)
    {
        var bs = n.ToByteArrayUnsigned();

        if (bs.Length == size)
        {
            return bs;
        }
        if (bs.Length > size)
        {
            throw new ArgumentException($"Size too small: {size}");
        }

        var padded = new byte[size];
        Array.Copy(bs, 0, padded, size - bs.Length, bs.Length);
        return padded;
    }
}
