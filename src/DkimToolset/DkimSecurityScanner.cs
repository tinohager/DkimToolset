using Nager.EmailAuthentication;
using Nager.EmailAuthentication.Models.Dkim;
using System.Numerics;
using System.Security.Cryptography;

namespace DkimToolset
{
    public class DkimSecurityScanner
    {
        /// <summary>
        /// Performs a Batch-GCD attack on a list of DKIM records 
        /// to identify moduli that share common prime factors.
        /// </summary>
        public List<CompromisedKey> ScanForSharedPrimes(
            string[] dkimRecords)
        {
            var moduli = new List<BigInteger>();
            var results = new List<CompromisedKey>();
            var lockObj = new object();

            // 1. Moduli extrahieren
            foreach (var record in dkimRecords)
            {
                var n = this.GetRsaModulusFromDkim(record);
                if (!n.IsZero)
                {
                    moduli.Add(n);
                }
            }

            if (moduli.Count < 2)
            {
                return results;
            }

            var tree = this.BuildProductTree(moduli);

            Parallel.For(0, moduli.Count, i =>
            {
                if (this.HasSharedPrime(moduli, tree, i))
                {
                    BigInteger n = moduli[i];
                    BigInteger product = BigInteger.One;
                    int idx = i;

                    // Berechnung des Produkts aller anderen Moduli via Tree
                    for (int level = 0; level < tree.Count; level++)
                    {
                        int pair = idx ^ 1;
                        if (pair < tree[level].Count)
                        {
                            product *= tree[level][pair];
                        }
                        idx >>= 1;
                    }

                    // Den gemeinsamen Teiler mittels GCD finden
                    BigInteger p = this.Gcd(n, product);
                    if (p > 1 && p < n)
                    {
                        BigInteger q = n / p;

                        lock (lockObj)
                        {
                            results.Add(new CompromisedKey
                            {
                                Index = i,
                                Modulus = n,
                                P = p,
                                Q = q
                            });
                        }
                    }
                }
            });

            return results;
        }

        private BigInteger GetRsaModulusFromDkim(
            string dkimRecord)
        {
            if (!DkimPublicKeyRecordParser.TryParse(dkimRecord, out var dkimPublicKeyRecord))
            {
                return BigInteger.Zero;
            }

            if (dkimPublicKeyRecord is not DkimPublicKeyRecordV1 dkimPublicKeyRecordV1)
            {
                return BigInteger.Zero;
            }

            if (dkimPublicKeyRecordV1.KeyType == "ed25519")
            {
                return BigInteger.Zero;
            }

            try
            {
                var keyBytes = Convert.FromBase64String(dkimPublicKeyRecordV1.PublicKeyData);

                using var rsa = RSA.Create();
                rsa.ImportSubjectPublicKeyInfo(keyBytes, out _);

                var parameters = rsa.ExportParameters(false);

                var n = new BigInteger(parameters.Modulus, isUnsigned: true, isBigEndian: true);
                var exponent = new BigInteger(parameters.Exponent, isUnsigned: true, isBigEndian: true);

                if (exponent != 65537)
                {
                    /*
                    * RSA Public Exponent (e) Security Analysis:
                    * -----------------------------------------
                    * The choice of the public exponent affects both the speed of verification 
                    * and the security of the signature.
                    * 
                    * | Exponent | Rating       | Description                                                                          |
                    * | -------- | ------------ | ------------------------------------------------------------------------------------ |
                    * | 3        | ❌ DANGEROUS | Highly vulnerable to mathematical attacks (e.g., Coppersmith's) if padding is weak.  |
                    * | 17       | ⚠️ LEGACY    | Historical compromise; rarely used in modern DKIM/SSL implementations.               |
                    * | 65537    | ✅ STANDARD  | The 4th Fermat Prime (F4). Optimal balance of security and performance.              |
                    * 
                    * * Why 65537? 
                    * It is large enough to prevent low-exponent attacks while being computationally 
                    * efficient ($2^{16} + 1$), requiring only 17 bitwise operations.
                    */

                    Console.WriteLine($"Warning: Non-standard exponent detected: {exponent}");
                }

                return new BigInteger(parameters.Modulus, isUnsigned: true, isBigEndian: true);
            }
            catch
            {
                return BigInteger.Zero;
            }
        }

        private List<List<BigInteger>> BuildProductTree(
            List<BigInteger> moduli)
        {
            var tree = new List<List<BigInteger>>
            {
                moduli
            };

            while (tree.Last().Count > 1)
            {
                var prev = tree.Last();
                var next = new List<BigInteger>();

                for (int i = 0; i < prev.Count; i += 2)
                {
                    if (i + 1 < prev.Count)
                    {
                        next.Add(prev[i] * prev[i + 1]);
                    }
                    else
                    {
                        next.Add(prev[i]);
                    }
                }

                tree.Add(next);
            }

            return tree;
        }

        private bool HasSharedPrime(
            List<BigInteger> moduli,
            List<List<BigInteger>> tree,
            int index)
        {
            BigInteger product = BigInteger.One;

            int idx = index;
            for (int level = 0; level < tree.Count; level++)
            {
                var layer = tree[level];
                int pairIndex = idx ^ 1;

                if (pairIndex < layer.Count)
                {
                    product *= layer[pairIndex];
                }

                idx >>= 1;
            }

            var gcd = this.Gcd(moduli[index], product);
            return gcd > 1 && gcd < moduli[index];
        }

        private BigInteger Gcd(
            BigInteger a,
            BigInteger b)
        {
            while (b != 0)
            {
                var t = b;
                b = a % b;
                a = t;
            }

            return a;
        }
    }
}
