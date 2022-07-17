using Programatica.Auth.SAML.ServiceProviderUtils.Interfaces;
using System.Xml;

namespace Programatica.Auth.SAML.ServiceProviderUtils
{
    public class LogoutResponseFactory : ILogoutResponseFactory
    {
        private readonly string _issuer;
        private readonly string _id;
        private readonly string _requestDestination;
        private readonly string _relayState;

        /// <summary>
        /// LogoutResponseFactory
        /// </summary>
        /// <param name="requestDestination"></param>
        /// <param name="issuer"></param>
        /// <param name="relayState"></param>
        public LogoutResponseFactory(string requestDestination, string issuer, string relayState)
        {
            _requestDestination = requestDestination;
            _issuer = issuer;
            _relayState = relayState;
            _id = $"_{Guid.NewGuid()}";
        }

        /// <summary>
        /// GetRedirectUrl
        /// </summary>
        /// <param name="samlEndpoint"></param>
        /// <returns></returns>
        public string GetRedirectUrl(string samlEndpoint)
        {
            var xml = GetUnSignedRequest();
            var urlParams = $"SAMLRequest={Uri.EscapeDataString(xml)}&RelayState={_relayState}";
            return $"{samlEndpoint}?{urlParams}";
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
                    xmlWriter.WriteStartElement("samlp", "LogoutResponse", "urn:oasis:names:tc:SAML:2.0:protocol");
                    xmlWriter.WriteAttributeString("ID", _id);
                    xmlWriter.WriteAttributeString("Version", "2.0");
                    xmlWriter.WriteAttributeString("IssueInstant", DateTime.Now.ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ", System.Globalization.CultureInfo.InvariantCulture));
                    xmlWriter.WriteAttributeString("Destination", _requestDestination);

                    xmlWriter.WriteStartElement("saml", "Issuer", "urn:oasis:names:tc:SAML:2.0:assertion");
                    xmlWriter.WriteString(_issuer);
                    xmlWriter.WriteEndElement();

                    xmlWriter.WriteStartElement("samlp", "Status", "urn:oasis:names:tc:SAML:2.0:protocol");
                    xmlWriter.WriteStartElement("samlp", "StatusCode", "urn:oasis:names:tc:SAML:2.0:protocol");
                    xmlWriter.WriteString("urn:oasis:names:tc:SAML:2.0:status:Success");
                    xmlWriter.WriteEndElement();
                    xmlWriter.WriteEndElement();

                    // close first element
                    xmlWriter.WriteEndElement();
                }
                return stringWriter.ToString();
            }
        }

    }
}
