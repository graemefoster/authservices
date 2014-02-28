using System.Security.Cryptography.X509Certificates;
using System.Xml;
using System.Xml.Linq;

namespace Kentor.AuthServices
{
    /// <summary>
    ///     An authentication request corresponding to section 3.4.1 in SAML Core specification.
    /// </summary>
    public class Saml2LogOffRequest : Saml2RequestBase
    {
        private readonly X509Certificate2 _signingCertificate;
        private readonly string _sessionIndex;

        /// <summary>
        /// 
        /// </summary>
        /// <param name="signingCertificate"></param>
        /// <param name="sessionIndex"></param>
        public Saml2LogOffRequest(X509Certificate2 signingCertificate, string sessionIndex)
        {
            _signingCertificate = signingCertificate;
            _sessionIndex = sessionIndex;
        }

        /// <summary>
        /// 
        /// </summary>
        public string ProviderName { get; set; }

        /// <summary>
        /// 
        /// </summary>
        public Saml2BindingType Binding { get; set; }

        public string QId { get; set; }

        /// <summary>
        ///     Serializes the request to a Xml message.
        /// </summary>
        /// <returns>XElement</returns>
        public XElement ToXElement()
        {
            var x = new XElement(Saml2Namespaces.Saml2P + "LogoutRequest");

            x.Add(base.ToXNodes());
            x.AddAttributeIfNotNullOrEmpty("ProviderName", ProviderName);

            if (Binding == Saml2BindingType.HttpPost)
            {
                x.AddAttributeIfNotNullOrEmpty("ProtocolBinding", "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST");
            }

            x.Add(new XElement(Saml2Namespaces.Saml2P + "SessionIndex", _sessionIndex));
            x.Add(new XElement(Saml2Namespaces.Saml2P + "NameQualifier", QId));
            x.Add(new XElement(Saml2Namespaces.Saml2P + "NameIdPolicy", "urn:oasis:names:tc:SAML:1.1:nameidformat:unspecified"));

            return x;
        }

        /// <summary>
        ///     Serializes the message into wellformed Xml.
        /// </summary>
        /// <returns>string containing the Xml data.</returns>
        public override string ToXml()
        {
            var doc = new XmlDocument();
            doc.LoadXml(ToXElement().ToString());

            if (_signingCertificate != null)
                doc.Sign(_signingCertificate, Id);

            return doc.OuterXml;
        }
    }
}