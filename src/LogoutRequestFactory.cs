using Programatica.Auth.SAML.ServiceProviderUtils.Interfaces;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Xml;

namespace Programatica.Auth.SAML.ServiceProviderUtils
{
    public class LogoutRequestFactory /*ILogoutRequestFactory*/
    {
        private readonly string _issuer;
        private readonly string _id;
        private readonly string _requestDestination;
        private readonly string _nameId;
        private readonly string _sessionIndex;
        private readonly X509Certificate2? _cert;

        /// <summary>
        /// LogoutRequestFactory
        /// </summary>
        /// <param name="requestDestination"></param>
        /// <param name="issuer"></param>
        public LogoutRequestFactory(string requestDestination, string issuer, string nameId, string sessionIndex, X509Certificate2? cert = null)
        {
            _requestDestination = requestDestination;
            _issuer = issuer;
            _id = $"_{Guid.NewGuid()}";
            _cert = cert;
            _nameId = nameId;
            _sessionIndex = sessionIndex;
        }

        /// <summary>
        /// GetRedirectUrl
        /// </summary>
        /// <param name="samlEndpoint"></param>
        /// <returns></returns>
        public string GetRedirectUrl(string samlEndpoint, bool sign)
        {
            var xml = GetUnSignedRequest();
            var urlParams = $"SAMLRequest={Uri.EscapeDataString(xml)}";

            if (sign)
            {
                if (_cert == null)
                {
                    throw new ArgumentNullException("Missing certificate");
                }

                urlParams = $"{urlParams}&SigAlg={Uri.EscapeDataString("http://www.w3.org/2001/04/xmldsig-more#rsa-sha256")}";

                using (var rsa = _cert.GetRSAPrivateKey())
                {
                    if (rsa != null)
                    {
                        var signature = rsa.SignData(Encoding.UTF8.GetBytes(urlParams), HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
                        urlParams = $"{urlParams}&Signature={Uri.EscapeDataString(Convert.ToBase64String(signature))}";
                    }
                    else
                    {
                        throw new Exception("The certificate does not have an RSA private key.");
                    }
                }

            }

            var queryStringSeparator = samlEndpoint.Contains("?") ? "&" : "?";
            return $"{samlEndpoint}{queryStringSeparator}{urlParams}";
        }

        /// <summary>
        /// GetUnSignedRequest
        /// </summary>
        /// <returns></returns>
        private string GetUnSignedRequest()
        {
            var docString = BuildRequestXml();
            var b64 = Utils.EncodeUtils.Base64Encode(docString);
            return b64;
        }

        /// <summary>
        /// BuildRequestXml
        /// </summary>
        /// <returns></returns>
        private string BuildRequestXml()
        {
            var xmlWriterSettings = new XmlWriterSettings
            {
                OmitXmlDeclaration = true
            };

            using (var stringWriter = new StringWriter())
            {
                using (var xmlWriter = XmlWriter.Create(stringWriter, xmlWriterSettings))
                {
                    xmlWriter.WriteStartElement("samlp", "LogoutRequest", "urn:oasis:names:tc:SAML:2.0:protocol");
                    xmlWriter.WriteAttributeString("ID", _id);
                    xmlWriter.WriteAttributeString("Version", "2.0");
                    xmlWriter.WriteAttributeString("IssueInstant", DateTime.Now.ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ", System.Globalization.CultureInfo.InvariantCulture));
                    xmlWriter.WriteAttributeString("Destination", _requestDestination);

                    xmlWriter.WriteStartElement("saml", "Issuer", "urn:oasis:names:tc:SAML:2.0:assertion");
                    xmlWriter.WriteString(_issuer);
                    xmlWriter.WriteEndElement();

                    xmlWriter.WriteStartElement("saml", "NameID", "urn:oasis:names:tc:SAML:2.0:assertion");
                    xmlWriter.WriteAttributeString("SPNameQualifier", _issuer);
                    xmlWriter.WriteAttributeString("Format", "urn:oasis:names:tc:SAML:2.0:nameid-format:transient");
                    xmlWriter.WriteString($"{_nameId}");
                    xmlWriter.WriteEndElement();

                    xmlWriter.WriteStartElement("samlp", "SessionIndex", "urn:oasis:names:tc:SAML:2.0:protocol");
                    xmlWriter.WriteString($"{_sessionIndex}");
                    xmlWriter.WriteEndElement();

                    // close first element
                    xmlWriter.WriteEndElement();
                }
                return stringWriter.ToString();
            }
        }

    }
}
