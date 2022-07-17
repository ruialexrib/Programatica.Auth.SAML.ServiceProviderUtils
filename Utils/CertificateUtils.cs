using System.Security.Cryptography.X509Certificates;

namespace Programatica.Auth.SAML.ServiceProviderUtils.Utils
{
    public static class CertificateUtils
    {
        /// <summary>
        /// LoadCertificateFile
        /// </summary>
        /// <param name="certificateFilePath"></param>
        /// <param name="password"></param>
        /// <returns></returns>
        public static X509Certificate2 LoadCertificateFile(string certificateFilePath, string password = null)
        {
            return new X509Certificate2(certificateFilePath, password, X509KeyStorageFlags.MachineKeySet | X509KeyStorageFlags.PersistKeySet | X509KeyStorageFlags.Exportable);
        }

        /// <summary>
        /// LoadCertificate
        /// </summary>
        /// <param name="certificate"></param>
        /// <returns></returns>
        public static X509Certificate2 LoadCertificate(string certificate)
        {
            return LoadCertificate(StringToByteArray(certificate));
        }

        /// <summary>
        /// LoadCertificate
        /// </summary>
        /// <param name="certificate"></param>
        /// <param name="password"></param>
        /// <returns></returns>
        public static X509Certificate2 LoadCertificate(byte[] certificate, string password = null)
        {
            return new X509Certificate2(certificate, password, X509KeyStorageFlags.MachineKeySet | X509KeyStorageFlags.PersistKeySet | X509KeyStorageFlags.Exportable);
        }

        /// <summary>
        /// StringToByteArray
        /// </summary>
        /// <param name="st"></param>
        /// <returns></returns>
        private static byte[] StringToByteArray(string st)
        {
            var bytes = new byte[st.Length];
            for (int i = 0; i < st.Length; i++)
            {
                bytes[i] = (byte)st[i];
            }
            return bytes;
        }
    }
}
