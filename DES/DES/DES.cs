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
        private long[] keys;

        public readonly Permutation initialPermutation;
        public readonly Permutation keyPermutation;

        public DES(long k, List<long> s)
        {
            this.fullKey = k;
            this.message = s;

            byte[] kp = 
            {
                56, 48, 40, 32, 24, 16,  8,  0, 57, 49, 41, 33, 25, 17,
                 9,  1, 58, 50, 42, 34, 26, 18, 10,  3, 59, 51, 43, 35,
                62, 54, 46, 38, 30, 22, 14,  6, 61, 53, 45, 37, 29, 21,
                13,  5, 60, 52, 44, 36, 28, 20, 13,  5, 27, 20, 12,  4
            };

            this.keyPermutation = new Permutation(kp);

            byte[] ip =
            {
                57, 49, 41, 33, 25, 17,  9,  1, 59, 51, 43, 35, 27, 19, 11,  3,
                61, 53, 45, 37, 29, 21, 13,  5, 63, 55, 47, 39, 31, 23, 15,  7,
                56, 48, 40, 32, 24, 16,  8,  0, 58, 50, 42, 34, 26, 18, 10,  2,
                60, 52, 44, 36, 28, 20, 12,  4, 62, 54, 46, 38, 30, 22, 14,  6
            };

            this.initialPermutation = new Permutation(ip);
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
