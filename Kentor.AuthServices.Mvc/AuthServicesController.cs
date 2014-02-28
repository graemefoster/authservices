﻿using System;
using System.Net;
using System.Web.Mvc;
using System.IdentityModel.Services;

namespace Kentor.AuthServices.Mvc
{
    /// <summary>
    /// Mvc Controller that provides the authentication functionality.
    /// </summary>
    [AllowAnonymous]
    public class AuthServicesController : Controller
    {
        /// <summary>
        /// SignIn action that sends the AuthnRequest to the Idp.
        /// </summary>
        /// <returns>Redirect with sign in request</returns>
        public ActionResult SignIn()
        {
            return CommandFactory.GetCommand("SignIn").Run(Request).ToActionResult();
        }

        /// <summary>
        /// Assertion consumer Url that accepts the incoming Saml response.
        /// </summary>
        /// <returns>Redirect to start page on success.</returns>
        /// <remarks>The action effectively accepts the SAMLResponse, but
        /// due to using common infrastructure it is read for the current
        /// http request.</remarks>
        public ActionResult Acs()
        {
            var result = CommandFactory.GetCommand("Acs").Run(Request);
            result.ApplyPrincipal();
            return result.ToActionResult();
        }

        /// <summary>
        /// SignOut action that signs out the current user.
        /// </summary>
        /// <returns>Redirect to base url / </returns>
        public ActionResult FederatedSignOut()
        {
            return CommandFactory.GetCommand("SignOut").Run(Request).ToActionResult();
        }

        /// <summary>
        /// SignOut action that signs out the current user.
        /// </summary>
        /// <returns>Redirect to base url / </returns>
        [System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Design", "CA1054:UriParametersShouldNotBeStrings", MessageId = "0#")]
        public ActionResult SignOut(string redirectUrl)
        {
            FederatedAuthentication.SessionAuthenticationModule.SignOut();
            return Redirect(Url.Content(redirectUrl));
        }
    }
}
