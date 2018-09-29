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
        private byte[] NumBitsToShiftKeyLeft = { 1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1 };
        private byte[] NumBitsToShiftKeyRight = { 0, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1 };

        public PermutationLibrary pl;

        public DES(long k, List<long> s)
        {
            this.fullKey = k;
            this.message = s;

            // verification with example key from Cryptography: Theory and Practice by Douglas Stinson
            //0001001 0011010 0101011 0111100 1001101 1011110 1101111 1111000
            // with 0 on every 8th digit
            //0001001000110100010101100111100010011010101111001101111011110000
            // binary to long results in 
            this.fullKey = Convert.ToInt64("0001001000110100010101100111100010011010101111001101111011110000", 2);


            // verification with example message from Cryptography: Theory and Practice by Douglas Stinson
            this.message = new List<long>();
            this.message.Add(Convert.ToInt64("0123456789ABCDEF", 16));

            this.pl = new PermutationLibrary();

            Console.WriteLine("Encryption keys:");
            GenerateKeys(encryptionKeys, "left", true);
            Console.WriteLine("Decryption keys:");
            GenerateKeys(decryptionKeys, "right", true);
        }

        private long Feistel(long message, long[] keys)
        {
            //Console.WriteLine("Applying initial transformation to message block");
            long l = ApplyPermutation(message, pl.initialPermutation);
            Console.WriteLine();

            Console.WriteLine("L0: \t\t" + Program.LongToBitString(Program.GetLeftHalf(l)));
            Console.WriteLine("R0: \t\t" + Program.LongToBitString(Program.GetRightHalf(l)));
            Console.WriteLine("L1: \t\t" + Program.LongToBitString(Program.GetRightHalf(l)));
            Console.WriteLine();

            // 16 rounds of encryption
            for (int t = 0; t < 16; t++)
            {
                long left = Program.GetLeftHalf(l);
                long right = Program.GetRightHalf(l);
                long newLeft = right;

                Console.WriteLine("Round: " + t);

                long newRight = left ^ F(right, keys[t]);

                Console.WriteLine("L" + (t + 2) + " = R" + (t + 1) + " = \t" + Program.LongToBitString(newRight));

                // bitshifting to the right fills the value with zeroes,
                // this is not what we want; we only want the rightmost 32 bits.
                // to clear this, bitwise & with the rightmost 32 bits, which happens to be the amount of bits a uint uses.
                l = newLeft | ((newRight >> 32) & (long)uint.MaxValue);

                /*
                Console.WriteLine();
                Console.WriteLine("new left: \t" + Program.LongToBitString(newLeft));
                Console.WriteLine("new right: \t" + Program.LongToBitString(newRight));
                Console.WriteLine("nr >> 32: \t" + Program.LongToBitString(((newRight >> 32) & (long)uint.MaxValue)));
                Console.WriteLine("temp result: \t" + Program.LongToBitString(l));
                Console.WriteLine();
                */
            }

            Console.WriteLine();
            Console.WriteLine("before fin p: \t" + Program.LongToBitString(l));

            long r = Program.GetRightHalf(l);
            l = (l >> 32) & uint.MaxValue;
            l |= r;
            Console.WriteLine("r and l shift: \t" + Program.LongToBitString(l));
            l = ApplyPermutation(l, pl.finalPermutation);

            Console.WriteLine("Feistel result: " + Program.LongToBitString(l));

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
            Console.WriteLine("E(R): \t\t" + Program.LongToBitString(exRightHalf));
            long xorresult = exRightHalf ^ key;

            Console.WriteLine("K: \t\t" + Program.LongToBitString(key));
            Console.WriteLine("E(R) XOR K: \t" + Program.LongToBitString(xorresult));

            long sBoxed = ApplySBoxes(xorresult);

            Console.WriteLine("S-box outputs:  " + Program.LongToBitString(sBoxed));

            long pBoxed = ApplyPermutation(sBoxed, pl.PBox);

            Console.WriteLine("f(R, K): \t" + Program.LongToBitString(pBoxed));

            return pBoxed;
        }

        public List<long> Encrypt()
        {
            List<long> result = new List<long>();

            // for all message blocks
            for (int i = 0; i < message.Count; i++)
            {
                Console.WriteLine("enc block:\t" + Program.LongToBitString(message[i]));
                long feistelValue = Feistel(message[i], encryptionKeys);
                result.Add(feistelValue);
            }

            Console.WriteLine();
            Console.Write("in hex: \t");
            List<byte> b = Program.LongListToByteList(result);
            for (int i = 0; i < b.Count; i++)
            {
                Console.Write(b[i].ToString("X").PadLeft(2, '0'));
            }
            Console.WriteLine();
            return result;
        }
        /*
        public List<long> Decrypt(List<long> ll)
        {
            List<long> result = new List<long>();

            // for all message blocks
            for (int i = 0; i < message.Count; i++)
            {
                Console.WriteLine("dec block:\t" + Program.LongToBitString(ll[i]));
                long feistelValue = Feistel(ll[i], decryptionKeys);
                result.Add(feistelValue);
            }

            Console.WriteLine();
            Console.Write("in hex: \t");
            List<byte> b = Program.LongListToByteList(result);
            for (int i = 0; i < b.Count; i++)
            {
                Console.Write(b[i].ToString("X").PadLeft(2, '0'));
            }
            Console.WriteLine();
            return result;
        }
        */

        public List<long> Decrypt(List<long> message)
        {
            List<long> result = new List<long>();

            long[] decTestKeys = new long[16];

            for(int i = 0; i < 16; i++)
            {
                decTestKeys[15 - i] = encryptionKeys[i];
            }
            // for all message blocks
            for (int i = 0; i < message.Count; i++)
            {
                Console.WriteLine("dec block:\t" + Program.LongToBitString(message[i]));
                long feistelValue = Feistel(message[i], decTestKeys);
                result.Add(feistelValue);
            }

            Console.WriteLine();
            Console.Write("in hex: \t");
            List<byte> b = Program.LongListToByteList(result);
            for (int i = 0; i < b.Count; i++)
            {
                Console.Write(b[i].ToString("X").PadLeft(2, '0'));
            }
            Console.WriteLine();
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
            long key56 = this.ApplyPermutation(fullKey, this.pl.keyPermutation);

            if (debug) Console.WriteLine("56-bit key: \t\t" + Program.LongToBitString(key56));

            long shiftedKey = key56, key48;
            for (int i = 0; i < 16; i++)
            {
                if (shiftDirection == "left")
                {
                    for (int j = 0; j < NumBitsToShiftKeyLeft[i]; j++)
                    {
                        shiftedKey = ShiftKeyHalvesLeft(shiftedKey, false);
                        if (debug) Console.WriteLine("shifted 56-bit key:\t" + Program.LongToBitString(shiftedKey));
                    }
                }

                else if (shiftDirection == "right")
                {
                    for (int j = 0; j < NumBitsToShiftKeyRight[i]; j++)
                    {
                        shiftedKey = ShiftKeyHalvesRight(shiftedKey, false);
                        if (debug) Console.WriteLine("shifted 56-bit key:\t" + Program.LongToBitString(shiftedKey));
                    }
                }

                key48 = CompressKey(shiftedKey, false);
                keys[i] = key48;

                //if (debug) Program.WriteLongAsBits(keys[i], "key number " + i);
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

            bool leftTail, rightTail;

            //Look what the bit values in the tails are, which have to circle around
            leftTail = (byte)((l >> 36) & 1) == 1;
            // 63 - 28 = 35
            rightTail = (byte)((l >> 8) & 1) == 1;

            // Shift the key 1 bit to the right
            l = l >> 1;

            // Set the heads to 0
            // Since we cannot set them to 0 directly, we flip all the bits, then set them to 1 with bitwise or operator, then flip again
            l = ~l;
            l |= ((long)1 << 63);
            l |= ((long)1 << 35);
            l = ~l;

            // Place the head values on the tail
            if (leftTail) l |= (long)1 << 63;
            if (rightTail) l |= (long)1 << 35;

            if (debug) Program.WriteLongAsBits(l, "shifted key\t");
            return l;
        }

        public long ExpandedRightHalf(long l)
        {
            return ApplyPermutation(l, pl.expansionPermutation);
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
