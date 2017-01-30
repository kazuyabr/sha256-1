using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

using System.IO;

namespace Sha256_Hash_File_IO
{
    class Program
    {
        static void Main(string[] args)
        {
            String Filename = @"D:\teul jung\visualStudioProjects\Sha256_Hash_File_IO\test.txt"; //read file
            FileStream fs = new FileStream(Filename, FileMode.Open, FileAccess.Read); //make filestream
            byte[] getHashValByte = new byte[32];
            HHeader head = new HHeader();
            HHeader.HashFile(fs,ref getHashValByte);
            for(int i=0;i<32;++i)
            {
                Console.Write("{0:x}",getHashValByte[i]);
            }
            Console.WriteLine();
        }
    }
}
