using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace DES
{
    class DES
    {
        private List<long> message;

        private long fullKey;
        private long permutatedKey;
        private long[] keys;
        private byte[] NumBitsToShiftKey = { 1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1 };
        public PermutationLibrary pl;

        public DES(long k, List<long> s)
        {
            this.fullKey = k;
            this.message = s;

            this.pl = new PermutationLibrary();

            Console.WriteLine("Applying key permutation to key");
            this.permutatedKey = this.ApplyPermutation(k, this.pl.keyPermutation, true);

            Console.WriteLine("Applying expansion to first message block right half");
            this.ExpandRightHalf(message[0]);

            Console.WriteLine("Applying compression to permutated key");
            this.CompressKey();
        }

        private void Encrypt()
        {
            ApplyInitialPermutation();

            GenerateKeys();
        }

        /// <summary>
        /// Apply the initial permutation to a block of the message
        /// </summary>
        public void ApplyInitialPermutation()
        {

        }

        /// <summary>
        /// Generate the 16 48-bit keys
        /// </summary>
        public void GenerateKeys()
        {

        }

        public void ExpandRightHalf(long l)
        {
            long r = Program.GetRightHalf(l);
            r = ApplyPermutation(r, pl.expansionPermutation, true);
        }

        public void CompressKey()
        {
            long ck = ApplyPermutation(permutatedKey, pl.compressionPermutation, true);
        }

        public long ApplyPermutation(long l, Permutation p, bool debug = false)
        {
            long res = 0;

            if (debug) Console.WriteLine("Applying permutation to\t" + Program.LongToBitString(l));

            for (int i = 0; i < p.length; i++)
            {
                res += ((l >> (63 - p.permutation[i])) & 1) << (63 - i);
            }

            if (debug)
            {
                Console.WriteLine("Permutation resulted in\t" + Program.LongToBitString(res));
                Console.WriteLine();
            }
            return res;
        }
    }
}
