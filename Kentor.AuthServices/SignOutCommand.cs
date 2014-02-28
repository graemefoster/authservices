using System.Linq;
using System.Security.Claims;
using System.Web;

namespace Kentor.AuthServices
{
    class SignOutCommand : ICommand
    {
        public CommandResult Run(HttpRequestBase request)
        {
            var idp = IdentityProvider.ConfiguredIdentityProviders.First().Value;

            var sessionIndex = ClaimsPrincipal.Current.FindFirst(c => c.Type == "SessionIndex").Value;
            var qid = ClaimsPrincipal.Current.FindFirst(c => c.Type == "qid").Value;
            var signoutRequest = idp.CreateSignoutRequest(sessionIndex, qid);

            return idp.Bind(signoutRequest);
        }
    }
}