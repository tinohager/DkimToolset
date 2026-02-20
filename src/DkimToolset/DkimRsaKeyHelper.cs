using System.Numerics;
using System.Security.Cryptography;

namespace DkimToolset
{
    public static class DkimRsaKeyHelper
    {
        public static void GenerateVulnerableSharedPrimeKey(
            int keySize = 512)
        {
            int halfLen = keySize / 16;
            int nLen = keySize / 8;

            using var tempRsa = RSA.Create();
            tempRsa.KeySize = keySize;
            var parameters = tempRsa.ExportParameters(true);

            if (parameters.P is null ||
                parameters.Q is null ||
                parameters.Exponent is null)
            {
                return;
            }

            BigInteger p = FromBigEndian(parameters.P);
            BigInteger q = FromBigEndian(parameters.Q);
            BigInteger e = FromBigEndian(parameters.Exponent);

            // Inject a constant prime factor 'q' to simulate an RSA key collision for testing.
            q = BigInteger.Parse("92647841457256719255272602951835034094598204706626374974561170771055591835127");

            BigInteger n = p * q;
            BigInteger phi = (p - 1) * (q - 1);
            BigInteger d = ModInverse(e, phi);

            var rsaParameters = new RSAParameters
            {
                Modulus = ToFixedBytes(n, nLen),
                Exponent = ToFixedBytes(e, 3),
                D = ToFixedBytes(d, nLen),
                P = ToFixedBytes(p, halfLen),
                Q = ToFixedBytes(q, halfLen),
                DP = ToFixedBytes(d % (p - 1), halfLen),
                DQ = ToFixedBytes(d % (q - 1), halfLen),
                InverseQ = ToFixedBytes(ModInverse(q, p), halfLen)
            };

            using var rsa = RSA.Create();
            rsa.ImportParameters(rsaParameters);

            Console.WriteLine($"RSA KeySize: {rsa.KeySize} Bit");
            Console.WriteLine("DKIM Public Key (Base64):");
            Console.WriteLine(Convert.ToBase64String(rsa.ExportSubjectPublicKeyInfo()));
        }

        public static void GenerateLegacyExponentKey(
            int keySize = 1024)
        {
            using var rsa = RSA.Create();
            rsa.KeySize = keySize;

            RSAParameters parameters = rsa.ExportParameters(true);

            // Change the exponent to 17
            parameters.Exponent = [0x11]; // 17 in hex

            rsa.ImportParameters(parameters);

            var publicKey = rsa.ExportSubjectPublicKeyInfo();
            var base64Public = Convert.ToBase64String(publicKey);

            Console.WriteLine("DKIM Public Key (Base64):");
            Console.WriteLine(base64Public);

            var privateKey = rsa.ExportRSAPrivateKey();
            string base64Private = Convert.ToBase64String(privateKey);
            Console.WriteLine("Private Key (Base64):");
            Console.WriteLine(base64Private);
        }

        static BigInteger ModInverse(
            BigInteger a,
            BigInteger m)
        {
            BigInteger m0 = m, x0 = 0, x1 = 1;

            while (a > 1)
            {
                if (m == 0)
                {
                    return 0;
                }
                BigInteger q = a / m;
                (a, m) = (m, a % m);
                (x0, x1) = (x1 - q * x0, x0);
            }

            return x1 < 0 ? x1 + m0 : x1;
        }

        static byte[] ToFixedBytes(
            BigInteger value,
            int size)
        {
            byte[] raw = value.ToByteArray(isUnsigned: true, isBigEndian: true);
            if (raw.Length == size)
            {
                return raw;
            }

            byte[] result = new byte[size];
            if (raw.Length > size) // Truncate if necessary (e.g., stripping leading zero bytes)
            {
                Array.Copy(raw, raw.Length - size, result, 0, size);
            }
            else // Apply zero-padding to reach the required size
            {
                Array.Copy(raw, 0, result, size - raw.Length, raw.Length);
            }

            return result;
        }

        static BigInteger FromBigEndian(byte[] data) => new BigInteger(data, isUnsigned: true, isBigEndian: true);
    }
}
