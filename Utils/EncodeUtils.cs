using System.IO.Compression;
using System.Text;

namespace Programatica.Auth.SAML.ServiceProviderUtils.Utils
{
    public static class EncodeUtils
    {
        /// <summary>
        /// DecodeAndInflate
        /// </summary>
        /// <param name="str"></param>
        /// <returns></returns>
        public static string DecodeAndInflate(string str)
        {
            var utf8 = Encoding.UTF8;
            var bytes = Convert.FromBase64String(str);
            using (var output = new MemoryStream())
            {
                using (var input = new MemoryStream(bytes))
                {
                    using (var unzip = new DeflateStream(input, CompressionMode.Decompress))
                    {
                        unzip.CopyTo(output, bytes.Length);
                        unzip.Close();
                    }
                    return utf8.GetString(output.ToArray());
                }
            }
        }

        /// <summary>
        /// DeflateAndEncode
        /// </summary>
        /// <param name="str"></param>
        /// <returns></returns>
        public static string DeflateAndEncode(string str)
        {
            var bytes = Encoding.UTF8.GetBytes(str);
            using (var output = new MemoryStream())
            {
                using (var zip = new DeflateStream(output, CompressionMode.Compress))
                {
                    zip.Write(bytes, 0, bytes.Length);
                }
                var base64 = Convert.ToBase64String(output.ToArray());

                return base64;
            }
        }

        /// <summary>
        /// StringToByteArray
        /// </summary>
        /// <param name="st"></param>
        /// <returns></returns>
        public static byte[] StringToByteArray(string st)
        {
            byte[] bytes = new byte[st.Length];
            for (int i = 0; i < st.Length; i++)
            {
                bytes[i] = (byte)st[i];
            }
            return bytes;
        }

        /// <summary>
        /// Base64Encode
        /// </summary>
        /// <param name="input"></param>
        /// <returns></returns>
        public static string Base64Encode(string input)
        {
            var memoryStream = new MemoryStream();
            var writer = new StreamWriter(new DeflateStream(memoryStream, CompressionMode.Compress, true), new UTF8Encoding(false));
            writer.Write(input);
            writer.Close();
            return Convert.ToBase64String(memoryStream.GetBuffer(), 0, (int)memoryStream.Length, Base64FormattingOptions.None);
        }

    }
}
