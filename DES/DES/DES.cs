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
        private byte[] NumBitsToShiftKeyLeft = { 1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1 };

        public PermutationLibrary pl;

        public DES(string k, string m, bool debug = false)
        {
            this.fullKey = Program.StringToLongList(k)[0];
            this.message = Program.StringToLongList(m);
            
            if (debug)
            {
                Console.WriteLine("Key:\t\t" + Program.LongToBitString(fullKey));
                Console.WriteLine("Message:\t");
                for (int i = 0; i < message.Count; i++) Console.Write(Program.LongToBitString(message[i]) + "\t");
            } else
            {
                Console.WriteLine("Original message:\t" + m);
            }
            
            // verification with example key from Cryptography: Theory and Practice by Douglas Stinson
            //0001001 0011010 0101011 0111100 1001101 1011110 1101111 1111000
            // with 0 on every 8th digit
            //0001001000110100010101100111100010011010101111001101111011110000
            // binary to long results in 
            //this.fullKey = Convert.ToInt64("0001001000110100010101100111100010011010101111001101111011110000", 2);


            // verification with example message from Cryptography: Theory and Practice by Douglas Stinson
            //this.message = new List<long>();
            //this.message.Add(Convert.ToInt64("0123456789ABCDEF", 16));

            this.pl = new PermutationLibrary();

            GenerateKeys(encryptionKeys);
        }

        /// <summary>
        /// A Feistel network as used in the DES encryption algorithm.
        /// </summary>
        /// <param name="message"> The message to be encrypted or decrypted </param>
        /// <param name="keys"> The array of keys to be used in the 16 rounds </param>
        /// <param name="debug"> Whether or not debug info will be printed on the console </param>
        /// <returns> The result of the Feistel network </returns>
        private long Feistel(long message, long[] keys, bool debug = false)
        {
            long l = ApplyPermutation(message, pl.initialPermutation);

            if (debug)
            {
                Console.WriteLine("L0: \t\t" + Program.LongToBitString(Program.GetLeftHalf(l)));
                Console.WriteLine("R0: \t\t" + Program.LongToBitString(Program.GetRightHalf(l)));
                Console.WriteLine("L1: \t\t" + Program.LongToBitString(Program.GetRightHalf(l)));
                Console.WriteLine();
            }

            // 16 rounds of encryption
            for (int t = 0; t < 16; t++)
            {
                long left = Program.GetLeftHalf(l);
                long right = Program.GetRightHalf(l);
                long newLeft = right;

                if (debug) Console.WriteLine("Round: " + t);

                long newRight = left ^ F(right, keys[t]);

                if (debug) Console.WriteLine("L" + (t + 2) + " = R" + (t + 1) + " = \t" + Program.LongToBitString(newRight));

                // we only want the rightmost 32 bits, bitwise & with the rightmost 32 bits, 
                // which happens to be the amount of bits a uint uses. int.MinValue would work too.
                l = newLeft | ((newRight >> 32) & (long)uint.MaxValue);
            }

            // shift the left and right half
            long r = Program.GetRightHalf(l);
            l = (l >> 32) & uint.MaxValue;
            l |= r;
            l = ApplyPermutation(l, pl.finalPermutation);

            return l;
        }

        /// <summary>
        /// DES F function
        /// 1. Expand right half to 48 bits
        /// 2. XOR with key
        /// 3. Apply S-Boxes
        /// 4. Apply P-Box
        /// </summary>
        /// <param name="righthalf">32-bits right half</param>
        /// <param name="key">48-bits key</param>
        /// <returns></returns>
        private long F(long righthalf, long key, bool debug = false)
        {
            long expandedRightHalf = ApplyPermutation(righthalf, pl.expansionPermutation);
            long xorresult = expandedRightHalf ^ key;
            long sBoxed = ApplySBoxes(xorresult);
            long pBoxed = ApplyPermutation(sBoxed, pl.PBox);

            if (debug)
            {
                Console.WriteLine("E(R): \t\t" + Program.LongToBitString(expandedRightHalf));
                Console.WriteLine("K: \t\t" + Program.LongToBitString(key));
                Console.WriteLine("E(R) XOR K: \t" + Program.LongToBitString(xorresult));
                Console.WriteLine("S-box outputs:  " + Program.LongToBitString(sBoxed));
                Console.WriteLine("f(R, K): \t" + Program.LongToBitString(pBoxed));
            }

            return pBoxed;
        }

        /// <summary>
        /// Encrypts the given string in ASCII format using DES encryption algorithm
        /// </summary>
        /// <param name="debug"> Whether or not debug info will be printed on the console </param>
        /// <returns> Encrypted message in HEX format, HEX was chosen because many characters would be unknown in other text formats such as Unicode and UTF8</returns>
        public List<long> Encrypt(bool debug = false)
        {
            List<long> result = new List<long>();

            // for all message blocks
            for (int i = 0; i < message.Count; i++)
            {
                long feistelValue = Feistel(message[i], encryptionKeys);
                result.Add(feistelValue);
            }

            if (debug)
            {
                Console.WriteLine();
                Console.Write("End result:\t");
                for (int i = 0; i < result.Count; i++)
                {
                    Console.Write(Program.LongToBitString(result[i]) + "\t");
                }
                Console.WriteLine();
                Console.Write("in hex: \t");
            }
            else
            {
                Console.Write("Encrypted message:\t");
            }
            List<byte> b = Program.LongListToByteList(result);
            for (int i = 0; i < b.Count; i++)
            {
                Console.Write(b[i].ToString("X").PadLeft(2, '0'));
            }
            Console.WriteLine();

            return result;
        }

        /// <summary>
        /// Decrypts the given encrypted message.
        /// </summary>
        /// <param name="message"> The encrypted message to be decrypted</param>
        /// <param name="debug"> Whether or not debug info will be printed on the console </param>
        /// <returns> The decrypted message in ASCII format </returns>
        public List<long> Decrypt(List<long> message, bool debug = false)
        {
            List<long> result = new List<long>();

            long[] decTestKeys = new long[16];

            for (int i = 0; i < 16; i++)
            {
                decTestKeys[15 - i] = encryptionKeys[i];
            }
            // for all message blocks
            for (int i = 0; i < message.Count; i++)
            {
                //Console.WriteLine("dec block:\t" + Program.LongToBitString(message[i]));
                long feistelValue = Feistel(message[i], decTestKeys);
                result.Add(feistelValue);
            }

            if (debug)
            {
                Console.WriteLine();
                Console.Write("End result:\t");
                for (int i = 0; i < result.Count; i++)
                {
                    Console.Write(Program.LongToBitString(result[i]) + "\t");
                }
                Console.WriteLine();
                Console.WriteLine("in text:");
            }
            else
            {
                Console.Write("Decrypted message:\t");
            }
            List<byte> b = Program.LongListToByteList(result);
            Console.Write(System.Text.Encoding.ASCII.GetString(b.ToArray()));
            return result;
        }
        
        /// <summary>
        /// 1. Generate 56-bit subkey.
        /// 2. Shift the key a certain amount of steps depending on the round.
        /// 3. Compress the key to 48 bits.
        /// </summary>
        /// <param name="shiftDirection"> The direction to shift the keys in, "left" for encryption and "right" for decryption</param>
        public void GenerateKeys(long[] keys, bool debug = false)
        {
            long key56 = this.ApplyPermutation(fullKey, this.pl.keyPermutation);

            if (debug) Console.WriteLine("56-bit key: \t\t" + Program.LongToBitString(key56));

            long shiftedKey = key56, key48;
            for (int i = 0; i < 16; i++)
            {
                for (int j = 0; j < NumBitsToShiftKeyLeft[i]; j++)
                {
                    shiftedKey = ShiftKeyHalvesLeft(shiftedKey, false);
                    if (debug) Console.WriteLine("shifted 56-bit key:\t" + Program.LongToBitString(shiftedKey));
                }
                key48 = ApplyPermutation(shiftedKey, pl.compressionPermutation, false);
                keys[i] = key48;

                //if (debug) Program.WriteLongAsBits(keys[i], "key number " + i);
            }
            if (debug) Console.WriteLine();
        }
        
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
            
            // Place the head values on the tail
            if (leftHead) l |= (long)1 << 36;
            if (rightHead) l |= (long)1 << 8;

            if (debug) Program.WriteLongAsBits(l, "shifted key\t");
            return l;
        }

        /// <summary>
        /// Applies a given permutation to a long, counting the leftmost bit as bit 1 and the rightmost bit as bit 64
        /// </summary>
        /// <param name="l"> The long to be permuted </param>
        /// <param name="p"></param>
        /// <param name="debug"></param>
        /// <returns></returns>
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

        /// <summary>
        /// Applies the S-Boxes to the long
        /// </summary>
        /// <param name="l"> The long which the S-Boxes will permute </param>
        /// <param name="debug"> Whether or not debug info will be printed on the console </param>
        /// <returns> The permuted long </returns>
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

        /// <summary>
        /// Applies a given S-Box to a long
        /// </summary>
        /// <param name="l"> The 6-bit section of a long which the S-Box should permute the center of </param>
        /// <param name="s"> The index of the S-Box, note this is 0-based while in literature S-Box indices are usually 1-based </param>
        /// <param name="debug"> Whether or not debug info will be printed on the console </param>
        /// <returns> The permuted section of the long </returns>
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
