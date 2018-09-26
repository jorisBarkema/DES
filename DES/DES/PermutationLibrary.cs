using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace DES
{
    class PermutationLibrary
    {
        public readonly Permutation initialPermutation;
        public readonly Permutation keyPermutation;
        public readonly Permutation compressionPermutation;
        public readonly Permutation expansionPermutation;

        public PermutationLibrary()
        {
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

            byte[] cp =
            {
                14, 17, 11, 24,  1,  5,  3, 28, 15,  6, 21, 10,
                23, 19, 12,  4, 26,  8, 16,  7, 27, 20, 13,  2,
                41, 52, 31, 37, 47, 55, 30, 40, 51, 45, 33, 48,
                44, 49, 39, 56, 34, 53, 46, 42, 50, 36, 29, 32
            };

            this.compressionPermutation = new Permutation(cp);

            byte[] ep =
            {
                32, 1, 2, 3, 4, 5, 4, 5, 6, 7, 8, 9,
                8, 9, 10, 11, 12, 13, 12, 13, 14, 15, 16, 17,
                16, 17, 18, 19, 20, 21, 20, 21, 22, 23, 24, 25,
                24, 25, 26, 27, 28, 29, 28, 29, 30, 31, 32, 1
            };

            this.expansionPermutation = new Permutation(ep);
        }
    }
}
