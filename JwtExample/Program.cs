using System;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Security.Claims;
using System.Xml;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using Org.BouncyCastle.Asn1.Sec;
using System.Linq;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Crypto.Parameters;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;

namespace JwtExample
{
    class Program
    {
        static void Main(string[] args)
        {
            var jwt = new JwtManager();

            var token = jwt.GenerateJWTTokenEcdsa(1, "123@123.ru");

            bool isValid = jwt.CheckTokenEcdsa(token);

            Console.WriteLine(isValid);
        }
    }

    public class JwtManager
    {
        private const string _privateKeyEcdsa = "b046dda9f8105460075ff33e50fc9c3462331f7518435ae70252ed73facad881";
        private const string _publicKeyEcdsa = "0426f7a6c1c733b91104be87c54c49765d0fcc8ba5551c694b56f8bebfd12b9f935f08aeced1292ad5c31dbbc60cc339e95ae7c414195d5d3dec325c894ceebc36";

        private const string _company = "Example";

        public bool CheckTokenEcdsa(string jwt)
        {
            var publicECDsa = Util.LoadPublicKey(Util.FromHexString(_publicKeyEcdsa));
            var prms = new TokenValidationParameters()
            {
                RequireSignedTokens = true,
                RequireExpirationTime = true,
                IssuerSigningKey = new ECDsaSecurityKey(publicECDsa),
                ValidateAudience = false,
                ValidIssuer = _company
            };
            var handler = new JwtSecurityTokenHandler();

            try
            {
                handler.ValidateToken(jwt, prms, out SecurityToken token);
                handler.ReadJwtToken(jwt);
                return true;
            }
            catch // And here is the problem on Mac and Linux
            {
                return false;
            }
        }

        public string GenerateJWTTokenEcdsa(int id, string email)
        {
            var privateECDsa = Util.LoadPrivateKey(Util.FromHexString(_privateKeyEcdsa));

            var credentials = new SigningCredentials(
                new ECDsaSecurityKey(privateECDsa), SecurityAlgorithms.EcdsaSha256);

            var header = new JwtHeader(credentials);
            var payload = new JwtPayload(
                _company,
                email,
                new List<Claim>()
                {
                    new Claim("sub", id.ToString())
                },
                DateTime.UtcNow,
                DateTime.UtcNow.AddMinutes(30));

            var secToken = new JwtSecurityToken(header, payload);
            var handler = new JwtSecurityTokenHandler();
            var tokenString = handler.WriteToken(secToken);

            return tokenString;
        }
    }

    public static class Util
    {
        public static byte[] FromHexString(string hex)
        {
            var numberChars = hex.Length;
            var hexAsBytes = new byte[numberChars / 2];
            for (var i = 0; i < numberChars; i += 2)
                hexAsBytes[i / 2] = Convert.ToByte(hex.Substring(i, 2), 16);

            return hexAsBytes;
        }

        public static ECDsa LoadPublicKey(byte[] key)
        {
            var pubKeyX = key.Skip(1).Take(32).ToArray();
            var pubKeyY = key.Skip(33).ToArray();

            return ECDsa.Create(new ECParameters
            {
                Curve = ECCurve.NamedCurves.nistP256,
                Q = new ECPoint
                {
                    X = pubKeyX,
                    Y = pubKeyY
                }
            });
        }

        public static ECDsa LoadPrivateKey(byte[] key)
        {
            var privKeyInt = new Org.BouncyCastle.Math.BigInteger(+1, key);
            var parameters = SecNamedCurves.GetByName("secp256r1");
            var ecPoint = parameters.G.Multiply(privKeyInt);
            var privKeyX = ecPoint.Normalize().XCoord.ToBigInteger().ToByteArrayUnsigned();
            var privKeyY = ecPoint.Normalize().YCoord.ToBigInteger().ToByteArrayUnsigned();

            return ECDsa.Create(new ECParameters
            {
                Curve = ECCurve.NamedCurves.nistP256,
                D = privKeyInt.ToByteArrayUnsigned(),
                Q = new ECPoint
                {
                    X = privKeyX,
                    Y = privKeyY
                }
            });
        }
    }
}