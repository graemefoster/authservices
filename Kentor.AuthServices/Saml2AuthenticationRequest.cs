using System;
using System.Security.Cryptography.X509Certificates;
using System.Xml;
using System.Xml.Linq;

namespace Kentor.AuthServices
{
    /// <summary>
    ///     An authentication request corresponding to section 3.4.1 in SAML Core specification.
    /// </summary>
    public class Saml2AuthenticationRequest : Saml2RequestBase
    {
        private readonly X509Certificate2 _signingCertificate;

        /// <summary>
        /// 
        /// </summary>
        /// <param name="signingCertificate"></param>
        public Saml2AuthenticationRequest(X509Certificate2 signingCertificate)
        {
            _signingCertificate = signingCertificate;
        }

        /// <summary>
        ///     The assertion consumer url that the idp should send its response back to.
        /// </summary>
        public Uri AssertionConsumerServiceUrl { get; set; }

        /// <summary>
        /// 
        /// </summary>
        public string ProviderName { get; set; }

        /// <summary>
        /// 
        /// </summary>
        public Saml2BindingType Binding { get; set; }

        /// <summary>
        ///     Serializes the request to a Xml message.
        /// </summary>
        /// <returns>XElement</returns>
        public XElement ToXElement()
        {
            var x = new XElement(Saml2Namespaces.Saml2P + "AuthnRequest");

            x.Add(base.ToXNodes());
            x.AddAttributeIfNotNullOrEmpty("AssertionConsumerServiceURL", AssertionConsumerServiceUrl);
            x.AddAttributeIfNotNullOrEmpty("ProviderName", ProviderName);

            if (Binding == Saml2BindingType.HttpPost)
            {
                x.AddAttributeIfNotNullOrEmpty("ProtocolBinding", "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST");
            }

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