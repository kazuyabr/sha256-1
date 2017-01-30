using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.IO;
using System.Diagnostics;
using System.Collections.ObjectModel;

namespace Sha256_Hash_File_IO
{
    public class HHeader
    {
        public UInt32[] K = new UInt32[64] {
            0x428A2F98, 0x71374491, 0xB5C0FBCF, 0xE9B5DBA5, 0x3956C25B, 0x59F111F1, 0x923F82A4, 0xAB1C5ED5,
            0xD807AA98, 0x12835B01, 0x243185BE, 0x550C7DC3, 0x72BE5D74, 0x80DEB1FE, 0x9BDC06A7, 0xC19BF174,
            0xE49B69C1, 0xEFBE4786, 0x0FC19DC6, 0x240CA1CC, 0x2DE92C6F, 0x4A7484AA, 0x5CB0A9DC, 0x76F988DA,
            0x983E5152, 0xA831C66D, 0xB00327C8, 0xBF597FC7, 0xC6E00BF3, 0xD5A79147, 0x06CA6351, 0x14292967,
            0x27B70A85, 0x2E1B2138, 0x4D2C6DFC, 0x53380D13, 0x650A7354, 0x766A0ABB, 0x81C2C92E, 0x92722C85,
            0xA2BFE8A1, 0xA81A664B, 0xC24B8B70, 0xC76C51A3, 0xD192E819, 0xD6990624, 0xF40E3585, 0x106AA070,
            0x19A4C116, 0x1E376C08, 0x2748774C, 0x34B0BCB5, 0x391C0CB3, 0x4ED8AA4A, 0x5B9CCA4F, 0x682E6FF3,
            0x748F82EE, 0x78A5636F, 0x84C87814, 0x8CC70208, 0x90BEFFFA, 0xA4506CEB, 0xBEF9A3F7, 0xC67178F2
        };
        
        //public UInt32[] hashInit = new UInt32[8] {
        //    0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A, 0x510E527F, 0x9B05688C, 0x1F83D9AB, 0x5BE0CD19
        //};
        private UInt32[] H = new UInt32[8]
        {
            0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A, 0x510E527F, 0x9B05688C, 0x1F83D9AB, 0x5BE0CD19
        };
        public static UInt32 ROTR(UInt32 objt, int n)
        {
            Debug.Assert(n < 32, "ROTR Error : shift over 32");
            return (objt << n | objt >> (32 - n));
        }
        public static UInt32 ROTL(UInt32 objt, int n)
        {
            Debug.Assert(n < 32, "ROTL Error : shift over 32");
            return (objt >> n | objt << (32 - n));
        }
        public static UInt32 Ch(UInt32 x, UInt32 y, UInt32 z)
        {
            return (x&y)^((~x) & z);
        }
        public static UInt32 Maj(UInt32 x,UInt32 y,UInt32 z)
        {
            return (x & y) ^ (x & z) ^ (y & z);
        }
        public static UInt32 Sig0(UInt32 x)
        {
            return ROTR(x, 2) ^ ROTR(x, 13) ^ ROTR(x, 22);
        }
        public static UInt32 Sig1(UInt32 x)
        {
            return ROTR(x, 6) ^ ROTR(x, 11) ^ ROTR(x, 25);
        }
        public static UInt32 sSig0(UInt32 x)
        {
            return ROTR(x, 7) ^ ROTR(x, 18) ^ (x>>3);
        }
        public static UInt32 sSig1(UInt32 x)
        {
            return ROTR(x, 17) ^ ROTR(x, 19) ^ (x>>10);
        }
        public void processBlock(UInt32[] M)
        {
            Debug.Assert(M.Length == 16); //32*16 = 512
            UInt32[] W = new UInt32[64]; //256 bytes of Working Set
            for( int t=0;t<16;++t)
            {
                W[t] = M[t];
            }
            for(int t=16;t<64;++t)
            {
                W[t] = sSig1(W[t - 2]) + W[t - 7] + sSig0(W[t - 15]) + W[t - 16];
            }
            UInt32 a = H[0],
                b = H[1],
                c = H[2],
                d = H[3],
                e = H[4],
                f = H[5],
                g = H[6],
                h = H[7];
            for(int t=0;t<64;++t)
            {
                UInt32 T1 = h + Sig1(e) + Ch(e, f, g) + K[t] + W[t];
                UInt32 T2 = Sig0(a) + Maj(a, b, c);
                h = g;
                g = f;
                f = e;
                e = d + T1;
                d = c;
                c = b;
                b = a;
                a = T1 + T2;
            }
            H[0] = a + H[0];
            H[1] = b + H[1];
            H[2] = c + H[2];
            H[3] = d + H[3];
            H[4] = e + H[4];
            H[5] = f + H[5];
            H[6] = g + H[6];
            H[7] = h + H[7];
        }
        public static string ArrayToString(ReadOnlyCollection<byte> arr)
        {
            StringBuilder s = new StringBuilder(arr.Count * 2);
            for (int i = 0; i < arr.Count; ++i)
            {
                s.AppendFormat("{0:x2}", arr[i]);
            }
            return s.ToString();
        }
        private byte[] pending_block = new byte[64];
        private uint pending_block_off = 0;
        private UInt32[] uint_buffer = new uint[16];

        private UInt64 bits_processed = 0;
        private bool closed = false;

        private void AddData(byte[] data, uint offset, uint len)
        {
            if (closed)
                throw new InvalidOperationException("Adding data to a closed hasher.");
            if (len == 0)
                return;
            bits_processed += len * 8;
            while (len > 0)
            {//cut into 8196 bytes and every 64byte are hashed without padding. now, remaining 261bytes come to this function, and 9bytes are left
                uint amount_to_copy;
                if (len < 64)
                {
                    if (pending_block_off + len > 64)//마지막의 경우 1바이트 0x80이 패딩으로 들어오는데 이게 성립할 경우는 pending_block_off가 64바이트여야함
                        amount_to_copy = 64 - pending_block_off;
                    else
                        amount_to_copy = len;
                }
                else
                    amount_to_copy = 64 - pending_block_off;
                Array.Copy(data, offset,pending_block, pending_block_off, amount_to_copy); //data 배열에서 offset부터 pending_block(64byte)에 pending_block_off에서 amount_to_copy만큼 복사
                len -= amount_to_copy;
                offset += amount_to_copy;
                pending_block_off += amount_to_copy;//pending_block_off엔 9개만큼 들어갔으니 9, pending_block엔 9bytes 나머지가 입력, 이 둘이 왜 클래스변수로 선언되었는지 알 수 있을듯.

                if(pending_block_off == 64)
                {
                    toUintArray(pending_block, uint_buffer); //pending_block_off array goes to Hash process
                    processBlock(uint_buffer);
                    pending_block_off = 0;
                }
            }
        }
        public ReadOnlyCollection<byte> GetHash()
        {
            return toByteArray(GetHashUInt32());
        }
        public ReadOnlyCollection<UInt32> GetHashUInt32()
        {
            if(!closed)
            {
                UInt64 size_temp = bits_processed;
                AddData(new byte[1] { 0x80 }, 0, 1); //마지막 9바이트를 남겨둔 상태 //만약 딱 64바이트로 나누어 떨어지면 어떻게 될지도 확인할것
                uint available_space = 64 - pending_block_off;
                if (available_space < 8)//길이 정보를 위한
                    available_space += 64;
                byte[] padding = new byte[available_space]; //여기서 나머지 00000.... 바이트 생성해서 
                for (uint i = 1; i <= 8; ++i)
                {
                    padding[padding.Length - i] = (byte)size_temp;
                    size_temp >>= 8;
                }//쩐다... 바이트씩 넣고 >>8 해주는 거기에 MSB, LSB 같은 order도 해결할 수 있음 다른 암호화 알고리즘이나 File system에서도 쓸 수 있을거같다.
                AddData(padding, 0u, (uint)padding.Length);
                Debug.Assert(pending_block_off == 0);//64바이트로 해쉬가 되어야 이 값을 가질 수 있음
                closed = true;
            }
            return Array.AsReadOnly(H);
        }
        private static ReadOnlyCollection<byte> toByteArray(ReadOnlyCollection<UInt32> src)//byte 배열로 바꿔주는
        {
            byte[] dest = new byte[src.Count * 4];
            int pos = 0;
            for(int i=0;i<src.Count;++i)
            {
                dest[pos++] = (byte)(src[i] >> 24);
                dest[pos++] = (byte)(src[i] >> 16);
                dest[pos++] = (byte)(src[i] >> 8);
                dest[pos++] = (byte)(src[i]);
            }
            return Array.AsReadOnly(dest);
        }
        private static void toUintArray(byte[] src,UInt32[] dest)//직접 가르켜서 하는 건 call by reference와 같지만
        {
            for(uint i = 0,j=0; i< dest.Length; ++i,j+=4)
            {
                dest[i] = ((UInt32)src[j + 0] << 24) | ((UInt32)src[j + 1] << 16) | ((UInt32)src[j + 2] << 8) | ((UInt32)src[j + 3]);
            }
        }
        //private static ReadOnlyCollection<byte> HashFile(Stream fs)
        public static void HashFile(Stream fs,ref byte[] dest)//ref 예약어 사용한 것.
        {
            HHeader sha = new HHeader();
            byte[] buf= new byte[8196];

            uint bytes_read;
            do
            {
                bytes_read = (uint)fs.Read(buf, 0, buf.Length);
                if (bytes_read == 0)
                    break;
                sha.AddData(buf, 0, bytes_read); //얘는 패딩하는애가 아니라 64바이트만큼 입력된것들을 우선 해쉬해놓는다. //정확히 말하면 pending_block에 원하는 데이터를 붙이면서 패딩조건을 업데이트하고 만약 64바이트가 되면 해쉬를 한다.
            }
            while (bytes_read > 0);
            //여기까지 64바이트씩 해쉬. 마지막 패딩과 나머지 값들은 아래 GetHash를 통해 마무리 한다.
            //sha클래스에 현재까지 해쉬한정보 그리고 pending_block에 나머지 해쉬할 것들이 들어있다.
            dest=(sha.GetHash()).ToArray<byte>(); //새로 할당한 메모리를 넣는건 call by value로 된다.
        }
     }
}