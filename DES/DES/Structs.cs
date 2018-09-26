using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace DES
{
    struct Permutation
    {
        public readonly byte[] permutation;
        public readonly int length;

        public Permutation(byte[] p)
        {
            permutation = p;
            length = p.Length;
        }
    }
}
