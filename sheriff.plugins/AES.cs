using System.Security.Cryptography;
using System.Text;

namespace sheriff.plugins.aes
{
    class AES
    {
        public static string IV = null;
        public static string KEY = null;

        public static byte[] Decrypt(byte[] bytes)
        {
            AesCryptoServiceProvider keydecrypt = new AesCryptoServiceProvider();
            keydecrypt.BlockSize = 128;
            keydecrypt.KeySize = 128;
            keydecrypt.Key = Encoding.UTF8.GetBytes(AES.KEY);
            keydecrypt.IV = Encoding.UTF8.GetBytes(AES.IV);
            keydecrypt.Padding = PaddingMode.PKCS7;
            keydecrypt.Mode = CipherMode.CBC;
            ICryptoTransform crypto1 = keydecrypt.CreateDecryptor(keydecrypt.Key, keydecrypt.IV);

            byte[] returnbytearray = crypto1.TransformFinalBlock(bytes, 0, bytes.Length);
            crypto1.Dispose();
            return returnbytearray;
        }
    }
}
