using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Security.Cryptography;
using System.IO;

namespace DES
{
    class Program
    {
        static void Main(string[] args)
        {
            //Console.Write("key:\t\t");
            //string k = Console.ReadLine();
            //long key = StringToLongList(k)[0];

            //Console.Write("message:\t");
            //string s = Console.ReadLine();
            
            Console.WriteLine();



            string k = "0";
            long key = StringToLongList(k)[0];

            string s = "0";

            DES des = new DES(key, StringToLongList(s));

            //Console.WriteLine(LongToBitString(des.ShiftKeyHalvesRight(2323123172222922231, true)));
            //Console.WriteLine(LongToBitString(des.ShiftKeyHalvesRight(2323111111111111231, true)));
            //Console.WriteLine(LongToBitString(des.ShiftKeyHalvesRight(2312309882222922231, true)));
            //Console.WriteLine(LongToBitString(des.ShiftKeyHalvesRight(2323098765657922231, true)));
            //Console.WriteLine(LongToBitString(des.ShiftKeyHalvesRight(2323999999999999231, true)));
            //Console.ReadLine();

            List<long> res = des.Encrypt();

            List<long> dec = des.Decrypt(res);

            Console.ReadLine();
        }

        public static string LongToBitString(long l) => Convert.ToString(l, 2).PadLeft(64, '0');
        public static void WriteLongAsBits(long l, string name = "long") => Console.WriteLine(name + ":\t" + LongToBitString(l) + "\t");
        public static long GetRightHalf(long l) => (l << 32);
        public static long GetLeftHalf(long l) => (l >> 32) << 32;
        public static long SwapHalves(long l) => (Program.GetLeftHalf(l) >> 32) | Program.GetRightHalf(l);

        static void WriteByteArray(byte[] array, string name = "byte[]")
        {
            Console.Write(name + ":\t");
            for (int i = 0; i < array.Length; i++) Console.Write(array[i] + "\t");
            Console.WriteLine();
        }

        /// <summary>
        /// Converts a string to a list of longs
        /// </summary>
        /// <param name="s">The string to be converted</param>
        /// <param name="debug">Whether or not debug info will be printed on the console</param>
        /// <returns>List of longs from the converted string</returns>
        static List<long> StringToLongList(string s, bool debug = false)
        {
            if (debug) Console.WriteLine("Converting string " + s + " to List<long>");
            byte[] bytes = Encoding.ASCII.GetBytes(s);
            //bytes = Convert.FromBase64String(s);

            if (debug)
            {
                Console.WriteLine("byte form:");
                WriteByteArray(bytes);
            }

            byte[] paddedBytes = (bytes.Length % 8 == 0) ? new byte[bytes.Length] : new byte[bytes.Length + 8 - (bytes.Length % 8)];
            for (int i = 0; i < bytes.Length; i++) paddedBytes[i] = bytes[i];

            if (debug)
            {
                Console.WriteLine("padded byte form:");
                WriteByteArray(paddedBytes);
            }

            List<long> longs = new List<long>();

            for (int i = 0; i <= paddedBytes.Length - 8; i += 8)
            {
                long res = ByteArrayToLong(paddedBytes, i);
                if (debug)
                {
                    Console.WriteLine("long:\t\t" + res);
                    Console.WriteLine("in bit form:\t" + LongToBitString(res));
                    Console.WriteLine();
                }
                    longs.Add(res);
            }

            return longs;
        }

        /// <summary>
        /// Converts a byte array of length 8 to a long, choosing a sub-array stating from index i
        /// </summary>
        /// <param name="b">The full array</param>
        /// <param name="i">The index to start</param>
        /// <param name="debug">Whether or not debug info will be printed on the console</param>
        /// <returns> long converted from the byte array</returns>
        static long ByteArrayToLong(byte[] b, int i, bool debug = false)
        {
            if (b.Length - i < 8) throw new Exception();

            long l = 0;

            for (int t = 0; t < 8; t++)
            {
                if (debug) Console.Write("");
                l += (Int64)b[i + t] << (8 * (8 - t - 1));
            }

            if (debug)
            {
                Console.WriteLine();
                Console.WriteLine();
            }
            return l;
        }

        /// <summary>
        /// Converts a list of longs to a byte list
        /// </summary>
        /// <param name="ll">The list of longs to be converted</param>
        /// <param name="debug">Whether or not debug info will be printed on the console</param>
        /// <returns>The converted byte list</returns>
        public static List<byte> LongListToByteList(List<long> ll, bool debug = false)
        {
            if (debug)
            {
                Console.WriteLine("Longs in the list:");
                foreach (long l in ll) WriteLongAsBits(l);
            }
            List<byte> res = new List<byte>();

            for(int i = 0; i < ll.Count; i++)
            {
                for(int t = 7; t >= 0; t--)
                {
                    byte b = (byte)(ll[i] >> (8 * t));
                    res.Add(b);
                }
            }

            if (debug)
            {
                WriteByteArray(res.ToArray(), "resulting byte list");
            }

            return res;
        }

        // DES implementation from https://www.codeproject.com/Articles/19538/Encrypt-Decrypt-String-using-DES-in-C
        static byte[] bytekey = ASCIIEncoding.ASCII.GetBytes("hello123");

        /// <summary>
        /// Encrypt a string.
        /// </summary>
        /// <param name="originalString">The original string.</param>
        /// <returns>The encrypted string.</returns>
        /// <exception cref="ArgumentNullException">This exception will be 
        /// thrown when the original string is null or empty.</exception>
        public static string Encrypt(string originalString)
        {
            if (String.IsNullOrEmpty(originalString))
            {
                throw new ArgumentNullException
                       ("The string which needs to be encrypted can not be null.");
            }
            DESCryptoServiceProvider cryptoProvider = new DESCryptoServiceProvider();
            MemoryStream memoryStream = new MemoryStream();
            CryptoStream cryptoStream = new CryptoStream(memoryStream,
            cryptoProvider.CreateEncryptor(bytekey, bytekey), CryptoStreamMode.Write);
            StreamWriter writer = new StreamWriter(cryptoStream);
            writer.Write(originalString);
            writer.Flush();
            cryptoStream.FlushFinalBlock();
            writer.Flush();
            return Convert.ToBase64String(memoryStream.GetBuffer(), 0, (int)memoryStream.Length);
        }

        /// <summary>
        /// Decrypt a crypted string.
        /// </summary>
        /// <param name="cryptedString">The crypted string.</param>
        /// <returns>The decrypted string.</returns>
        /// <exception cref="ArgumentNullException">This exception will be thrown 
        /// when the crypted string is null or empty.</exception>
        public static string Decrypt(string cryptedString)
        {
            if (String.IsNullOrEmpty(cryptedString))
            {
                throw new ArgumentNullException
                   ("The string which needs to be decrypted can not be null.");
            }
            DESCryptoServiceProvider cryptoProvider = new DESCryptoServiceProvider();
            MemoryStream memoryStream = new MemoryStream
                    (Convert.FromBase64String(cryptedString));
            CryptoStream cryptoStream = new CryptoStream(memoryStream,
                cryptoProvider.CreateDecryptor(bytekey, bytekey), CryptoStreamMode.Read);
            StreamReader reader = new StreamReader(cryptoStream);
            return reader.ReadToEnd();
        }
    }
}
