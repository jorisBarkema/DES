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
        private long[] encryptionKeys = new long[16];
        private long[] decryptionKeys = new long[16];
        private byte[] NumBitsToShiftKeyLeft     = { 1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1 };
        private byte[] NumBitsToShiftKeyRight = { 0, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1 };

        public PermutationLibrary pl;

        public DES(long k, List<long> s)
        {
            // this.fullKey = k;

            //0001001 0011010 0101011 0111100 1001101 1011110 1101111 1111000
            // with 0 on every 8th digit
            //000100100011010001010110011110001001101010111100110111101111000
            // binary to long results in 
            this.fullKey = 655884233731895200;
            this.message = s;

            this.pl = new PermutationLibrary();

            GenerateKeys(encryptionKeys, "left", true);
            //GenerateKeys(decryptionKeys, "right", true);
        }

        private long Feistel(long message, long[] keys)
        {
            Console.WriteLine("Applying initial transformation to mesage block");
            long l = ApplyPermutation(message, pl.initialPermutation, true);
            Console.WriteLine();

            // 16 rounds of encryption
            for (int t = 0; t < 16; t++)
            {
                long left = Program.GetLeftHalf(l);
                long right = Program.GetRightHalf(l);
                long newLeft = right;
                long newRight = left ^ F(right, keys[t]);

                l = newLeft | (newRight >> 32);
            }

            l = ApplyPermutation(l, pl.finalPermutation, true);

            return l;
        }

        /// <summary>
        /// DES F function
        /// 1. Expand right half to 48 bits
        /// 2. XOR with key
        /// 3. Apply S-Boxes
        /// 4. Apply P-Box
        /// </summary>
        /// <param name="righthalf">32-btis right half</param>
        /// <param name="key">48-bits key</param>
        /// <returns></returns>
        private long F(long righthalf, long key)
        {
            long exRightHalf = ExpandedRightHalf(righthalf);

            long xorresult = exRightHalf ^ key;

            long sBoxed = ApplySBoxes(xorresult, true);
            
            long pBoxed = ApplyPermutation(sBoxed, pl.PBox, true);

            return pBoxed;
        }

        public List<long> Encrypt()
        {
            List<long> result = new List<long>();

            // for all message blocks
            for (int i = 0; i < message.Count; i++) result.Add(Feistel(message[i], encryptionKeys));

            return result;
        }

        public List<long> Decrypt(List<long> ll)
        {
            List<long> result = new List<long>();

            // for all message blocks
            for (int i = 0; i < ll.Count; i++)
            {
                //long swapped = Program.SwapHalves(ll[i]);
                result.Add(Feistel(ll[i], decryptionKeys));
            }

            return result;
        }
        
        /// <summary>
        /// Apply the initial permutation to a block of the message
        /// </summary>
        public long ApplyInitialPermutation(long l, bool debug = false)
        {
            return ApplyPermutation(l, pl.initialPermutation, debug);
        }

        /// <summary>
        /// 1. Generate 56-bit subkey.
        /// 2. Shift the key a certain amount of steps depending on the round.
        /// 3. Compress the key to 48 bits.
        /// </summary>
        /// <param name="shiftDirection"> The direction to shift the keys in, "left" for encryption and "right" for decryption</param>
        public void GenerateKeys(long[] keys, string shiftDirection, bool debug = false)
        {
            long key56 = this.ApplyPermutation(fullKey, this.pl.keyPermutation, true);
            
            long shiftedKey = key56, key48;
            for (int i = 0; i < 16; i++)
            {
                if (shiftDirection == "left")
                {
                    for (int j = 0; j < NumBitsToShiftKeyLeft[i]; j++)
                    {
                        shiftedKey = ShiftKeyHalvesLeft(shiftedKey, false);
                    }
                }

                else if (shiftDirection == "right")
                {
                    for (int j = 0; j < NumBitsToShiftKeyRight[i]; j++)
                    {
                        shiftedKey = ShiftKeyHalvesRight(shiftedKey, false);
                    }
                }
                
                key48 = CompressKey(shiftedKey, false);
                keys[i] = key48;

                if (debug) Program.WriteLongAsBits(keys[i], "key number " + i);
            }
            if (debug) Console.WriteLine();
        }

        /// <summary>
        /// Generate the 16 48-bit decryption keys
        /// </summary>
        public void GenerateDecryptionKeys(bool debug = false)
        {
            if (debug) Console.WriteLine("Applying key permutation to key");
            long permutatedKey = this.ApplyPermutation(fullKey, this.pl.keyPermutation, true);

            if (debug) Console.WriteLine();

            long shiftedKey = permutatedKey, compressedKey;
            for (int i = 0; i < 16; i++)
            {
                for (int j = 0; j < NumBitsToShiftKeyRight[i]; j++)
                {
                    shiftedKey = ShiftKeyHalvesLeft(shiftedKey, false);
                }
                compressedKey = CompressKey(shiftedKey, false);
                // add in reverse order, so we can use them in normal order
                encryptionKeys[15 - i] = compressedKey;

                if (debug) Program.WriteLongAsBits(encryptionKeys[15 - i], "key number " + (15 - i));
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
        /// Shift the 2 halves of the 56-bit key by 1 bit to the left
        /// </summary>
        /// <param name="l"> The key to be shifted</param>
        /// <param name="debug">Whether or not debug info will be printed on the console</param>
        /// <returns> Shifted key</returns>
        public long ShiftKeyHalvesLeft(long l, bool debug = false)
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

        /// <summary>
        /// Shift the 2 halves of the 56-bit key by 1 bit to the right
        /// </summary>
        /// <param name="l"> The key to be shifted</param>
        /// <param name="debug">Whether or not debug info will be printed on the console</param>
        /// <returns> Shifted key</returns>
        public long ShiftKeyHalvesRight(long l, bool debug = false)
        {
            if (debug) Program.WriteLongAsBits(l, "original key\t");
           
            // Shift the key 1 bit to the right
            l = l >> 1;

            // the most left tail is definintely 0, so we can simply or it with the bit that is supposed to loop around
            // which is now on the head of the right half
            l |= ((l >> 35) & 1) << 63;

            // now we need to set the head of the right half to 0 so we can do the same
            // Since we cannot set it to 0 directly, we flip all the bits, then set them to 1 with bitwise or operator, then flip again
            l = ~l;
            l |= ((long)1 << 35);
            l = ~l;

            // Now we place the bit that is supposed to loop around on the head.
            l |= ((l >> 7) & 1) << 35;

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
                // the +1 is because Thsi works 0-based, while the permutations are 1-based
                res |= ((l >> (63 - p.permutation[i] + 1)) & 1) << (63 - i);
            }

            if (debug)
            {
                Console.WriteLine("Permutation resulted in\t" + Program.LongToBitString(res));
                Console.WriteLine();
            }
            return res;
        }

        public long ApplySBoxes(long l, bool debug = false)
        {
            long res = 0;

            if (debug)
            {
                Console.WriteLine("Applying S-Boxes to");
                Program.WriteLongAsBits(l);
            }

            int t = 0;
            for (int i = 58; i >= 16; i -= 6)
            {
                byte b = ApplySBox(l >> i, t, debug);
                // Move the 32-bit result to the left
                res |= ((long)b << (i + 2 * t + 2));
                t++;
            }

            if (debug)
            {
                Console.WriteLine("Applied S-Boxes resulted in");
                Program.WriteLongAsBits(res);
            }
            return res;
        }

        public byte ApplySBox(long l, int s, bool debug = false)
        {
            // look at the rightmost and leftmost bits
            // do not move the leftmost bit 5 positions, but 4 so it is in the second spot.
            int row = (((int)l & 32) >> 4) + ((int)l & 1);
            if (debug) Console.WriteLine("row:\t" + row);
            // Move the 4 center bits on to the right, and despose of the leftmost one.
            int col = ((int)l >> 1) & 15;
            if (debug) Console.WriteLine("col:\t" + col);

            return pl.SBoxes[s].permutation[row * 16 + col];
        }
    }
}
