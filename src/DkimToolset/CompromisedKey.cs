using System.Numerics;

namespace DkimToolset
{
    public class CompromisedKey
    {
        public int Index { get; set; }
        public BigInteger Modulus { get; set; }
        public BigInteger P { get; set; }
        public BigInteger Q { get; set; }
        public long BitLength => Modulus.GetBitLength();
    }
}
