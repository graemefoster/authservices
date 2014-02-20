﻿using System;
using System.Configuration;
using System.Diagnostics.CodeAnalysis;
using System.Globalization;
using System.Linq;
using System.Security.Cryptography.X509Certificates;
using System.Web;

namespace Kentor.AuthServices.Configuration
{
    /// <summary>
    /// Config element for the signing certificate.
    /// </summary>
    public class CertificateElement : ConfigurationElement
    {
        /// <summary>
        /// File name of cert stored in file.
        /// </summary>
        [ConfigurationProperty("fileName")]
        public string FileName
        {
            get
            {
                return (string)this["fileName"];
            }
        }

        /// <summary>
        /// Password for private key of a certificate used for signing.
        /// </summary>
        [ConfigurationProperty("password")]
        public string Password
        {
            get
            {
                return (string)this["password"];
            }
        }

        /// <summary>
        /// Store name to search.
        /// </summary>
        [ConfigurationProperty("storeName")]
        [ExcludeFromCodeCoverage]
        public StoreName StoreName
        {
            get
            {
                return (StoreName)this["storeName"];
            }
        }

        /// <summary>
        /// Store location to search.
        /// </summary>
        [ConfigurationProperty("storeLocation")]
        [ExcludeFromCodeCoverage]
        public StoreLocation StoreLocation
        {
            get
            {
                return (StoreLocation)this["storeLocation"];
            }
        }

        /// <summary>
        /// The search term used for searching the certificate store.
        /// </summary>
        [ConfigurationProperty("findValue")]
        [ExcludeFromCodeCoverage]
        public string FindValue
        {
            get
            {
                return (string)this["findValue"];
            }
        }

        /// <summary>
        /// Find type, what field to search.
        /// </summary>
        [ConfigurationProperty("x509FindType")]
        [ExcludeFromCodeCoverage]
        public X509FindType X509FindType
        {
            get
            {
                return (X509FindType)this["x509FindType"];
            }
        }

        /// <summary>
        /// Load the certificate pointed to by this configuration.
        /// </summary>
        /// <returns>Certificate</returns>
        [ExcludeFromCodeCoverage]
        public X509Certificate2 LoadCertificate()
        {
            if (!string.IsNullOrEmpty(FileName))
            {
                string fileName = FileName;
                if (HttpContext.Current != null)
                {
                    fileName = HttpContext.Current.Server.MapPath(fileName);
                }

                if (string.IsNullOrEmpty(Password))
                {
                    return new X509Certificate2(fileName);
                }
                return new X509Certificate2(fileName, Password);
            }
            else
            {
                var store = new X509Store(StoreName, StoreLocation);
                store.Open(OpenFlags.ReadOnly);
                try
                {
                    var certs = store.Certificates.Find(X509FindType, FindValue, false);

                    if (certs.Count != 1)
                    {
                        throw new InvalidOperationException(
                            string.Format(CultureInfo.InvariantCulture,
                            "Finding cert through {0} in {1}:{2} with value {3} matched {4} certificates. A unique match is required.",
                            X509FindType, StoreLocation, StoreName, FindValue, certs.Count));
                    }

                    return certs[0];
                }
                finally
                {
                    store.Close();
                }
            }
        }
    }
}
