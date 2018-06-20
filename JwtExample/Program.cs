using System;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Security.Claims;
using System.Xml;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;

namespace JwtExample
{
    class Program
    {
        static void Main(string[] args)
        {
            var jwt = new JwtManager();

            string token = jwt.GenerateJWTToken(1, "1@example.com");

            bool isValid = jwt.CheckToken(token);
        }        
    }

    public class JwtManager
    {
        private const string _privateKey = "<RSAKeyValue><Modulus>wCnmTiH/rFym9g2SSEn6f2pV6YQqFiV5ls3VqxUC3yeyk7UXFuEH/Kttbl2h4eOmXy7NCutmkyF+Mul5DeIs3X1jF6ZxTs3tIzBovV7lpIyQp9DUideSOy3jyu2pznP+l+XwkPwS5f4G43uFOTxU7KvXjJ8MLCNQ0TeY1wWVEkTX8JGEjv68dXEp8xOfMEDXkRYppEHy2g/FsDcqL+S33e/O5TQf2VSZpTH+COAz0nYwNs4RPuR6dpzOqeRhVMTVuOaAYYbzff15/bh1ytjXuZcuHsBUEe5zQnjV5iqIhzwtSw2p7jbIhOFq8DNUbOHKnLR1iI6tNXdz0NwMbTpLtw==</Modulus><Exponent>AQAB</Exponent><P>/23p95aUkenEzmgcH8+EIrkzotFVV15eRg7jtnY4rGbzZhY0mFMgnu1WGd0URFdY+D0QQEDI0+K68IlCYFMnZXPTX/4uD7cJtSfLKtTVc5kt1V6eE6r0nuGee1NImlVdokwtb1L/BMfco9wAm22NFCSm2f7RHWb8M2iNfxj/lbM=</P><Q>wJfNdK5AlVqCiFo1/iMhXiRrfry9Ri4WBg+G9kdelJh5rFYnFv4SGTeo/327pzaLSA59/idOTFG1wJjo9nnQZKfhVz3qPaq+OaThCU2d2YdMt1Kyl8VK4kziYf+9auem3J9WD5xiPPq4usDhuvhVKAJkjU6UkvTddrVUkvef9+0=</Q><DP>6vyvdjttyx8JE+rrlMhQg7FmM6/pl0sV59Xi4AW69cBww8ZB9LDlHdCymXCuKIFDNHzY6oOvPl8kJA3ipsNZRxhbqcApmAOIRsSpQGo1RPfzFozJWMa57UEbj9F6xaErVxhF5FiyjC9iaM0JMfSDCbj+Vyb6MtZ/xru1EOxqlck=</DP><DQ>NNoz3t5nCNWi1spy4MBBSvWRrmEbTCQflSAzuGhTk1HYqiumZI/q5ZK5xQt7MOMuC+M2PkYJHbaauzT7UZCSWN0dYPSz0KKHu4f83bG4LNcNfY2rRy00ZLAWvDATij/yMb9kPbp71yIzCcUe7VFzBRzK/WBgM4gRMp+GiyJ7eu0=</DQ><InverseQ>zDYpl2+9M4huyFY0L/WvZd7MYnYqEFMKIiRqTF2fUzT0mzCcLQcIb+a8LNkOIbIe199Zc64mdcjztMA0y2OW8Gsw2Twg6R2s1a3QNL7Fxsv9GE3JckLODcjJI8XprXwNxXu8HxFC/e6iG/urCvBAFAGlhGAlJ8qp3y3p9/oCDR8=</InverseQ><D>RSVOh8LYGw9jzJnpjzV/e6WpsFMsSbfGXqtGPT9cPywrp9a7rjHfC94rjFEI1R1zWkCe61T1HfApVuyH8KT3++MIaxQrJW4X7FeY+LtS6rjhvGD6eXcmWUET/Is0VOOMMuA8hg8ORc/4bpadw5CgBmF3OFRqrt8uT3ov9v89OssFqi48G0OHOZ+RLLQUazSgKAem00TI7xoIzpvEcALLyRlF9D39kB6Q4+5sNu4I8xOIPyBCH6TY24LARXwh++eeTDwD4wJDp1bk9Qsx/QQ8sQeKVrSc+0DWPrU1rsyuqWAL0LkI65Wt3fA7Zyd3oNEIU/I2+rau9Sc/0rT8j6Hm0Q==</D></RSAKeyValue>";
        private const string _publicKey = "<RSAKeyValue><Modulus>wCnmTiH/rFym9g2SSEn6f2pV6YQqFiV5ls3VqxUC3yeyk7UXFuEH/Kttbl2h4eOmXy7NCutmkyF+Mul5DeIs3X1jF6ZxTs3tIzBovV7lpIyQp9DUideSOy3jyu2pznP+l+XwkPwS5f4G43uFOTxU7KvXjJ8MLCNQ0TeY1wWVEkTX8JGEjv68dXEp8xOfMEDXkRYppEHy2g/FsDcqL+S33e/O5TQf2VSZpTH+COAz0nYwNs4RPuR6dpzOqeRhVMTVuOaAYYbzff15/bh1ytjXuZcuHsBUEe5zQnjV5iqIhzwtSw2p7jbIhOFq8DNUbOHKnLR1iI6tNXdz0NwMbTpLtw==</Modulus><Exponent>AQAB</Exponent></RSAKeyValue>";
        private const string _company = "Example";

        public bool CheckToken(string jwt)
        {
            RsaSecurityKey publicKey;
            using (var rsa = RSA.Create())
            {
                // rsa.FromXmlString(_publicKey); Not supported on Net Core
                rsa.FromXML(_publicKey);
                publicKey = new RsaSecurityKey(rsa);
            }
            var prms = new TokenValidationParameters()
            {
                RequireSignedTokens = true,
                RequireExpirationTime = true,
                IssuerSigningKey = publicKey,
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

        public string GenerateJWTToken(int id, string email)
        {
            RsaSecurityKey privateKey;
            using (RSA privateRsa = RSA.Create())
            {
                // rsa.FromXmlString(_publicKey); Not supported on Net Core
                privateRsa.FromXML(_privateKey);
                privateKey = new RsaSecurityKey(privateRsa);
            }
            var credentials = new SigningCredentials(privateKey, SecurityAlgorithms.RsaSha256);

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
        public static void FromXML(this RSA rsa, string xmlString)
        {
            var parameters = new RSAParameters();

            var xmlDoc = new XmlDocument();
            xmlDoc.LoadXml(xmlString);

            if (xmlDoc.DocumentElement.Name.Equals("RSAKeyValue"))
            {
                foreach (XmlNode node in xmlDoc.DocumentElement.ChildNodes)
                {
                    switch (node.Name)
                    {
                        case "Modulus": parameters.Modulus = (string.IsNullOrEmpty(node.InnerText) ? null : Convert.FromBase64String(node.InnerText)); break;
                        case "Exponent": parameters.Exponent = (string.IsNullOrEmpty(node.InnerText) ? null : Convert.FromBase64String(node.InnerText)); break;
                        case "P": parameters.P = (string.IsNullOrEmpty(node.InnerText) ? null : Convert.FromBase64String(node.InnerText)); break;
                        case "Q": parameters.Q = (string.IsNullOrEmpty(node.InnerText) ? null : Convert.FromBase64String(node.InnerText)); break;
                        case "DP": parameters.DP = (string.IsNullOrEmpty(node.InnerText) ? null : Convert.FromBase64String(node.InnerText)); break;
                        case "DQ": parameters.DQ = (string.IsNullOrEmpty(node.InnerText) ? null : Convert.FromBase64String(node.InnerText)); break;
                        case "InverseQ": parameters.InverseQ = (string.IsNullOrEmpty(node.InnerText) ? null : Convert.FromBase64String(node.InnerText)); break;
                        case "D": parameters.D = (string.IsNullOrEmpty(node.InnerText) ? null : Convert.FromBase64String(node.InnerText)); break;
                    }
                }
            }
            else
            {
                throw new Exception("Invalid XML RSA key.");
            }

            rsa.ImportParameters(parameters);
        }
    }
}