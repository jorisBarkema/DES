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
        private long[] keys = new long[16];
        private byte[] NumBitsToShiftKey = { 1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1 };
        public PermutationLibrary pl;

        public DES(long k, List<long> s)
        {
            this.fullKey = k;
            this.message = s;

            this.pl = new PermutationLibrary();
            
            //Console.WriteLine("Applying expansion to first message block right half");
            //this.ExpandedRightHalfOfMessage(message[0]);

            //Console.WriteLine("Applying compression to permutated key");
            //this.CompressKey(permutatedKey);
        }

        public List<long> Encrypt()
        {
            GenerateKeys(true);

            for (int i = 0; i < message.Count; i++)
            {
                long l = ApplyInitialPermutation(message[i], true);

                long exRightHalf = ExpandedRightHalf(Program.GetRightHalf(l));

                for(int t = 0; t < 16; t++)
                {
                    long xorresult = exRightHalf ^ keys[t];
                }
            }

            return null;
        }

        /// <summary>
        /// Apply the initial permutation to a block of the message
        /// </summary>
        public long ApplyInitialPermutation(long l, bool debug = false)
        {
            return ApplyPermutation(l, pl.initialPermutation, debug);
        }

        /// <summary>
        /// Generate the 16 48-bit keys
        /// </summary>
        public void GenerateKeys(bool debug = false)
        {
            Console.WriteLine("Applying key permutation to key");
            long permutatedKey = this.ApplyPermutation(fullKey, this.pl.keyPermutation, true);

            Console.WriteLine();

            long shiftedKey = permutatedKey, compressedKey;
            for(int i = 0; i < 16; i++)
            {
                for(int j = 0; j < NumBitsToShiftKey[i]; j++)
                {
                    shiftedKey = ShiftKeyHalves(shiftedKey, false);
                }
                compressedKey = CompressKey(shiftedKey, false);
                keys[i] = compressedKey;

                if (debug) Program.WriteLongAsBits(keys[i], "key number " + i);
            }

            if (debug) Console.WriteLine();

        }

        /// <summary>
        /// Compresses the 56-bit key to a 48-bit key
        /// </summary>
        /// <param name="l"></param>
        /// <returns></returns>
        public long CompressKey(long l, bool debug = false) => ApplyPermutation(l, pl.compressionPermutation, debug);

        /// <summary>
        /// Shift the 2 halves of the 56-bit key by 1 bit
        /// </summary>
        /// <param name="l"> The key to be shifted</param>
        /// <param name="debug">Whether or not debug info will be printed on the console</param>
        /// <returns> Shifted key</returns>
        public long ShiftKeyHalves(long l, bool debug = false)
        {
            if (debug) Program.WriteLongAsBits(l, "original key\t");
            bool leftHead, rightHead;

            //Look what the bit values in the heads are, which have to circle around
            leftHead = (byte)((l >> 63) & 1) == 1;
            // 63 - 28 = 35
            rightHead = (byte)((l >> 35) & 1) == 1;

            // Shift the key 1 bit to the left
            l = l << 1;

            // Set the tails to 0
            // Since we cannot set them to 0 directly, we flip all the bits, then set them to 1 with bitwise or operator, then flip again
            l = ~l;
            l |= ((long)1 << 36);
            l |= ((long)1 << 8);
            l = ~l;

            //if (debug) Program.WriteLongAsBits(l, "before added heads");

            // Place the head values on the tail
            if (leftHead) l |= (long)1 << 36;
            if (rightHead) l |= (long)1 << 8;

            if (debug) Program.WriteLongAsBits(l, "shifted key\t");
            return l;
        }

        public long ExpandedRightHalf(long l)
        {
            long r = Program.GetRightHalf(l);
            return ApplyPermutation(r, pl.expansionPermutation, true);
        }
        
        public long ApplyPermutation(long l, Permutation p, bool debug = false)
        {
            long res = 0;

            if (debug) Console.WriteLine("Applying permutation to\t" + Program.LongToBitString(l));

            for (int i = 0; i < p.length; i++)
            {
                res |= ((l >> (63 - p.permutation[i])) & 1) << (63 - i);
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
