namespace Programatica.Auth.SAML.ServiceProviderUtils.Interfaces
{
    public interface IAuthnRequestFactory
    {
        string GetRedirectUrl(string samlEndpoint, string relayState, bool sign);
    }
}
