using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Programatica.Auth.SAML.ServiceProviderUtils.Interfaces
{
    public interface ILogoutResponseFactory
    {
        string GetRedirectUrl(string samlEndpoint);
    }
}
