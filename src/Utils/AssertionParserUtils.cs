using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Security.Cryptography.Xml;
using System.Text;
using System.Threading.Tasks;
using System.Xml;

namespace Programatica.Auth.SAML.ServiceProviderUtils.Utils
{
    public class AssertionParserUtils
    {
        #region public methods

        /// <summary>
        /// LoadXmlFromBase64
        /// </summary>
        /// <param name="response"></param>
        public void LoadXmlFromBase64(string response)
        {
            var enc = new UTF8Encoding();
            var decoded = enc.GetString(Convert.FromBase64String(response));
            LoadXml(decoded);
        }

        /// <summary>
        /// LoadXml
        /// </summary>
        /// <param name="xml"></param>
        public void LoadXml(string xml)
        {
            _xmlDoc = new XmlDocument
            {
                PreserveWhitespace = true,
                XmlResolver = null
            };
            _xmlDoc.LoadXml(xml);

            //returns namespace manager, we need one b/c MS says so... Otherwise XPath doesnt work in an XML doc with namespaces
            //see https://stackoverflow.com/questions/7178111/why-is-xmlnamespacemanager-necessary

            var namespaceManager = new XmlNamespaceManager(_xmlDoc.NameTable);
            namespaceManager.AddNamespace("ds", SignedXml.XmlDsigNamespaceUrl);
            namespaceManager.AddNamespace("saml", "urn:oasis:names:tc:SAML:2.0:assertion");
            namespaceManager.AddNamespace("samlp", "urn:oasis:names:tc:SAML:2.0:protocol");
            namespaceManager.AddNamespace("e", EncryptedXml.XmlEncNamespaceUrl);
            namespaceManager.AddNamespace("xenc", EncryptedXml.XmlEncNamespaceUrl);

            _xmlNameSpaceManager = namespaceManager;
        }

        /// <summary>
        /// DecryptIfNeeded
        /// </summary>
        /// <param name="spCert"></param>
        public void DecryptIfNeeded(X509Certificate2 spCert)
        {
            if (spCert == null)
            {
                throw new ArgumentNullException(nameof(spCert));
            }

            var responseNode = SelectSingleNode("/samlp:Response");
            var encryptedAssertionNode = SelectSingleNode("/samlp:Response/saml:EncryptedAssertion");

            if (encryptedAssertionNode != null)
            {
                var encryptedDataNode = SelectSingleNode("/samlp:Response/saml:EncryptedAssertion/xenc:EncryptedData");
                var encryptionMethodAlgorithm = SelectSingleNode("/samlp:Response/saml:EncryptedAssertion/xenc:EncryptedData/xenc:EncryptionMethod")?.Attributes["Algorithm"]?.Value;
                var encryptionMethodKeyAlgorithm = SelectSingleNode("/samlp:Response/saml:EncryptedAssertion/xenc:EncryptedData/ds:KeyInfo/e:EncryptedKey/e:EncryptionMethod")?.Attributes["Algorithm"]?.Value;
                var cypherText = SelectSingleNode("/samlp:Response/saml:EncryptedAssertion/xenc:EncryptedData/ds:KeyInfo/e:EncryptedKey/e:CipherData/e:CipherValue")?.InnerText;

                var key = Rijndael.Create(encryptionMethodAlgorithm);
                key.Key = EncryptedXml.DecryptKey(
                                                Convert.FromBase64String(cypherText),
                                                (RSA)spCert.PrivateKey,
                                                useOAEP: encryptionMethodKeyAlgorithm == EncryptedXml.XmlEncRSAOAEPUrl
                                            );

                var encryptedXml = new EncryptedXml();
                var encryptedData = new EncryptedData();
                encryptedData.LoadXml((XmlElement)encryptedDataNode);

                var plaintext = encryptedXml.DecryptData(encryptedData, key);
                var xmlString = Encoding.UTF8.GetString(plaintext);

                var tempDoc = new XmlDocument();
                tempDoc.LoadXml(xmlString);

                var importNode = responseNode.OwnerDocument.ImportNode(tempDoc.DocumentElement, true);
                responseNode.ReplaceChild(importNode, encryptedAssertionNode);
            }
        }

        /// <summary>
        /// IsValid
        /// </summary>
        /// <param name="expectedAudience"></param>
        /// <returns></returns>
        public bool IsValid()
        {
            var nodeList = SelectNodes("//ds:Signature");

            if (nodeList.Count == 0)
            {
                return false;
            }

            var signedXml = new SignedXml(_xmlDoc);
            signedXml.LoadXml((XmlElement)nodeList[0]);


            return ValidateSignatureReference(signedXml)
                    && signedXml.CheckSignature()
                    && !IsExpired();

        }

        /// <summary>
        /// GetResponseIssuer
        /// </summary>
        /// <returns></returns>
        public string GetResponseIssuer()
        {
            var node = SelectSingleNode("/samlp:Response/saml:Issuer");
            return node?.InnerText;
        }

        public string GetResponseNameId()
        {
            var node = SelectSingleNode($"{XPathsUtils.FirstAssertionSubject}/saml:NameID");
            return node?.InnerText;
        }

        public string GetResponseSessionIndex()
        {
            var node = SelectSingleNode($"{XPathsUtils.FirstAssertionAuthnStatement}");
            return node?.Attributes["SessionIndex"].InnerText;
        }

        /// <summary>
        /// GetAttributeByName
        /// </summary>
        /// <param name="name"></param>
        /// <returns></returns>
        public string GetAttributeByName(string name, int position)
        {
            var node = SelectNodes($"{XPathsUtils.FirstAssertionsAttributeStatement}/saml:Attribute[@Name='{name}']/saml:AttributeValue")[position];
            return node?.InnerText;
        }

        /// <summary>
        /// Xml
        /// </summary>
        public string Xml => _xmlDoc.OuterXml;

        /// <summary>
        /// SelectSingleNode
        /// </summary>
        /// <param name="xPath"></param>
        /// <returns></returns>
        public XmlNode SelectSingleNode(string xPath) => _xmlDoc.SelectSingleNode(xPath, _xmlNameSpaceManager);

        /// <summary>
        /// SelectNodes
        /// </summary>
        /// <param name="xPath"></param>
        /// <returns></returns>
        public XmlNodeList SelectNodes(string xPath) => _xmlDoc.SelectNodes(xPath, _xmlNameSpaceManager);

        /// <summary>
        /// SelectNodeValues
        /// </summary>
        /// <param name="xPath"></param>
        /// <returns></returns>
        public string[] SelectNodeValues(string xPath)
        {
            return SelectNodes(xPath)
                   ?.Cast<XmlNode>()
                   .Select(x => x?.InnerText)
                   .Where(x => x != null)
                   .ToArray()
                   ?? Array.Empty<string>();
        }

        #endregion

        private XmlDocument _xmlDoc;
        private XmlNamespaceManager _xmlNameSpaceManager; //we need this one to run our XPath queries on the SAML XML

        //an XML signature can "cover" not the whole document, but only a part of it
        //.NET's built in "CheckSignature" does not cover this case, it will validate to true.
        //We should check the signature reference, so it "references" the id of the root document element! If not - it's a hack
        /// <summary>
        /// ValidateSignatureReference
        /// </summary>
        /// <param name="signedXml"></param>
        /// <returns></returns>
        private bool ValidateSignatureReference(SignedXml signedXml)
        {
            if (signedXml.SignedInfo.References.Count != 1) //no ref at all
            {
                return false;
            }

            var reference = (Reference)signedXml.SignedInfo.References[0];
            var id = reference.Uri.Substring(1);

            var idElement = signedXml.GetIdElement(_xmlDoc, id);

            if (idElement == _xmlDoc.DocumentElement)
            {
                return true;
            }
            else //sometimes its not the "root" doc-element that is being signed, but the "assertion" element
            {
                var assertionNode = SelectSingleNode("/samlp:Response/saml:Assertion") as XmlElement;
                if (assertionNode == idElement)
                {
                    return true;
                }
            }

            return false;
        }

        /// <summary>
        /// IsExpired
        /// </summary>
        /// <returns></returns>
        private bool IsExpired()
        {
            var expirationDate = DateTime.MaxValue;
            var node = SelectSingleNode($"{XPathsUtils.FirstAssertion}/saml:Subject/saml:SubjectConfirmation/saml:SubjectConfirmationData");
            if (node?.Attributes["NotOnOrAfter"] != null)
            {
                DateTime.TryParse(node.Attributes["NotOnOrAfter"].Value, out expirationDate);
            }

            if (DateTime.UtcNow > expirationDate.ToUniversalTime())
            {
                // Subject.SubjectConfirmation has expired
                return true;
            }

            node = SelectSingleNode($"{XPathsUtils.FirstAssertion}/saml:Conditions");
            if (node != null)
            {
                if (node?.Attributes["NotOnOrAfter"] != null)
                {
                    DateTime.TryParse(node.Attributes["NotOnOrAfter"].Value, out expirationDate);
                }

                if (DateTime.UtcNow > expirationDate.ToUniversalTime())
                {
                    // Assertion has expired
                    return true;
                }
            }

            return false;
        }

    }
}
