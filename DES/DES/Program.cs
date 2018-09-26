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
            Console.Write("string:\t");
            string s = Console.ReadLine();
            Console.WriteLine();

            Console.WriteLine("Original string:\t" + s);
            string se = Encrypt(s);
            Console.WriteLine("DES encrypted:\t\t" + se);
            string su = Decrypt(se);
            Console.WriteLine("DES unencrypted:\t" + su);
            Console.ReadLine();
        }

        // DES implementation from https://www.codeproject.com/Articles/19538/Encrypt-Decrypt-String-using-DES-in-C
        static byte[] bytekey = ASCIIEncoding.ASCII.GetBytes("aIfjUejv");

        /// <span class="code-SummaryComment"><summary></span>
        /// Encrypt a string.
        /// <span class="code-SummaryComment"></summary></span>
        /// <span class="code-SummaryComment"><param name="originalString">The original string.</param></span>
        /// <span class="code-SummaryComment"><returns>The encrypted string.</returns></span>
        /// <span class="code-SummaryComment"><exception cref="ArgumentNullException">This exception will be </span>
        /// thrown when the original string is null or empty.<span class="code-SummaryComment"></exception></span>
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

        /// <span class="code-SummaryComment"><summary></span>
        /// Decrypt a crypted string.
        /// <span class="code-SummaryComment"></summary></span>
        /// <span class="code-SummaryComment"><param name="cryptedString">The crypted string.</param></span>
        /// <span class="code-SummaryComment"><returns>The decrypted string.</returns></span>
        /// <span class="code-SummaryComment"><exception cref="ArgumentNullException">This exception will be thrown </span>
        /// when the crypted string is null or empty.<span class="code-SummaryComment"></exception></span>
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
