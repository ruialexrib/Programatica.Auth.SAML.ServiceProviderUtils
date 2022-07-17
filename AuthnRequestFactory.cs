using Programatica.Auth.SAML.ServiceProviderUtils.Interfaces;
using System.IO.Compression;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Xml;

namespace Programatica.Auth.SAML.ServiceProviderUtils
{
    public class AuthnRequestFactory : IAuthnRequestFactory
    {
        private readonly string _issuer;
        private readonly string _assertionConsumerServiceUrl;
        private readonly string _requestDestination;
        private readonly bool _forceAuthn;
        private readonly X509Certificate2? _cert;

        private readonly string _id;

        /// <summary>
        /// AuthnRequestFactory
        /// </summary>
        /// <param name="issuer">http://www.datypic.com/sc/saml2/e-saml_Issuer.html</param>
        /// <param name="assertionConsumerServiceUrl">http://www.datypic.com/sc/saml2/e-md_AssertionConsumerService.html</param>
        /// <param name="requestDestination"></param>
        /// <param name="forceAuthn"></param>
        /// <param name="cert"></param>
        public AuthnRequestFactory(
                            string issuer,
                            string assertionConsumerServiceUrl,
                            string requestDestination,
                            bool forceAuthn,
                            X509Certificate2? cert = null
                        )
        {
            _issuer = issuer;
            _assertionConsumerServiceUrl = assertionConsumerServiceUrl;
            _requestDestination = requestDestination;
            _forceAuthn = forceAuthn;
            _cert = cert;

            _id = $"_{Guid.NewGuid()}";
        }

        /// <summary>
        /// GetRedirectUrl
        /// returns the URL you should redirect your users to (i.e. your SAML-provider login URL with the Base64-ed request in the querystring
        /// </summary>
        /// <param name="samlEndpoint"></param>
        /// <param name="relayState"></param>
        /// <param name="sign"></param>
        /// <returns></returns>
        /// <exception cref="ArgumentNullException"></exception>
        public string GetRedirectUrl(string samlEndpoint, string relayState, bool sign)
        {

            var request = GetUnSignedRequest();

            //http://docs.oasis-open.org/security/saml/v2.0/saml-core-2.0-os.pdf
            //this exact format matters per 3.4.4.1 of https://docs.oasis-open.org/security/saml/v2.0/saml-bindings-2.0-os.pdf
            var urlParams = $"SAMLRequest={Uri.EscapeDataString(request)}";

            //RelayState param must not be present if empty
            if (!string.IsNullOrEmpty(relayState))
            {
                urlParams = $"{urlParams}&RelayState={Uri.EscapeDataString(relayState)}";
            }

            if (sign)
            {
                if (_cert == null)
                {
                    throw new ArgumentNullException("Missing certificate");
                }

                urlParams = $"{urlParams}&SigAlg={Uri.EscapeDataString("http://www.w3.org/2001/04/xmldsig-more#rsa-sha256")}";

                using (var rsa = _cert.GetRSAPrivateKey())
                {
                    var signature = rsa.SignData(Encoding.UTF8.GetBytes(urlParams), HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
                    urlParams = $"{urlParams}&Signature={Uri.EscapeDataString(Convert.ToBase64String(signature))}";
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
                    xmlWriter.WriteStartElement("samlp", "AuthnRequest", "urn:oasis:names:tc:SAML:2.0:protocol");
                    xmlWriter.WriteAttributeString("ID", _id);
                    xmlWriter.WriteAttributeString("Version", "2.0");
                    xmlWriter.WriteAttributeString("ForceAuthn", _forceAuthn.ToString());
                    xmlWriter.WriteAttributeString("IssueInstant", DateTime.Now.ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ", System.Globalization.CultureInfo.InvariantCulture));
                    xmlWriter.WriteAttributeString("ProtocolBinding", "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST");
                    xmlWriter.WriteAttributeString("AssertionConsumerServiceURL", _assertionConsumerServiceUrl);
                    xmlWriter.WriteAttributeString("Destination", _requestDestination);

                    xmlWriter.WriteStartElement("saml", "Issuer", "urn:oasis:names:tc:SAML:2.0:assertion");
                    xmlWriter.WriteString(_issuer);
                    xmlWriter.WriteEndElement();

                    xmlWriter.WriteStartElement("samlp", "NameIDPolicy", "urn:oasis:names:tc:SAML:2.0:protocol");
                    xmlWriter.WriteAttributeString("Format", "urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified");
                    xmlWriter.WriteAttributeString("AllowCreate", "true");
                    xmlWriter.WriteEndElement();

                    xmlWriter.WriteStartElement("samlp", "RequestedAuthnContext", "urn:oasis:names:tc:SAML:2.0:protocol");
                    xmlWriter.WriteAttributeString("Comparison", "exact");
                    xmlWriter.WriteStartElement("samlp", "AuthnContextClassRef", "urn:oasis:names:tc:SAML:2.0:protocol");
                    xmlWriter.WriteString("urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport");
                    xmlWriter.WriteEndElement();
                    xmlWriter.WriteEndElement();

                    xmlWriter.WriteEndElement();
                }
                return stringWriter.ToString();
            }

        }

    }
}
