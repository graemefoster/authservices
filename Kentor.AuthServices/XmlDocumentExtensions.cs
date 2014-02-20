using System;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Security.Cryptography.Xml;
using System.Xml;

namespace Kentor.AuthServices
{
    /// <summary>
    /// Extension methods for XmlDocument
    /// </summary>
    public static class XmlDocumentExtensions
    {
        /// <summary>
        /// Sign an xml document with the supplied cert.
        /// </summary>
        /// <param name="xmlDocument">XmlDocument to be signed. The signature is
        /// added as a node in the document.</param>
        /// <param name="cert">Certificate to use when signing.</param>
        /// <param name="uri"></param>
        [System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Design", "CA1054:UriParametersShouldNotBeStrings", MessageId = "2#"), System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Design", "CA1059:MembersShouldNotExposeCertainConcreteTypes", MessageId = "System.Xml.XmlNode")]
        public static void Sign(this XmlDocument xmlDocument, X509Certificate2 cert, string uri)
        {
            if (xmlDocument == null)
            {
                throw new ArgumentNullException("xmlDocument");
            }

            if (cert == null)
            {
                throw new ArgumentNullException("cert");
            }

            var signedXml = new SignedXml(xmlDocument);

            signedXml.SigningKey = (RSACryptoServiceProvider)cert.PrivateKey;
            signedXml.KeyInfo = new KeyInfo();
            signedXml.KeyInfo.AddClause(new KeyInfoX509Data(cert));

            var reference = new Reference();
            reference.Id = "";
            reference.Uri = "#" + uri;
            reference.AddTransform(new XmlDsigEnvelopedSignatureTransform());

            signedXml.AddReference(reference);
            signedXml.ComputeSignature();

            var docElem = xmlDocument.DocumentElement;
            docElem.InsertAfter(xmlDocument.ImportNode(signedXml.GetXml(), true), docElem.FirstChild);
        }
    }
}
