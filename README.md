# Programatica.Auth.SAML.ServiceProviderUtils

The main purpose of this project is provide a set of utilities to implement SAML authentication in .net core projects.

## Factories
- AuthnRequestFactory.cs - builds a SAMLRequest (AuthnRequest) and create an encoded url to start the Single Sign On (SSO) process
- LogoutRequestFactory - builds a SAMLRequest (LogoutRequest) and create an encoded url to start the Single Log Out (SLO) process
- LogoutResponseFactory.cs - builds a LogoutResponse (LogoutRequest) and create an encoded url to end the Single Log Out (SLO) process

## Utilities
- AssertionParserUtils.cs - utility with functions to handle teh assertion (decryption, signature validation, get attributes by name)
- CertificateUtils.cs - utility with functions to load X509Certificates 
- EncodeUtils.cs - utility with functions to handle the DecodeAndInflate and DeflateAndEncode
- XPathsUtils.cs - utility to help parse the assertion xml 

### How to use (Service Provider in asp.net core 6)
To this demonstration we will create an asp.net mvc projet targeting .net core 6. 

Start adding a reference to this project (Programatica.Auth.SAML.ServiceProviderUtils)

#### Home Controller

```
public IActionResult Login()
{
    var authnRequestFactory = new AuthnRequestFactory(issuer: "https://localhost:44396/",
                                                      assertionConsumerServiceUrl: "https://localhost:44396/home/acs",
                                                      requestDestination: "http://localhost:8080/simplesaml/saml2/idp/SSOService.php",
                                                      forceAuthn: true,
                                                      cert: CertificateUtils.LoadCertificateFile("idp_sp.pfx"));

    var redirectUrl = authnRequestFactory.GetRedirectUrl(samlEndpoint: "http://localhost:8080/simplesaml/saml2/idp/SSOService.php",
                                                         relayState: "https://localhost:44396/home/relay",
                                                         sign: true);

    return Redirect(redirectUrl);
}
```
