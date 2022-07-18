[![.NET](https://github.com/ruialexrib/Programatica.Auth.SAML.ServiceProviderUtils/actions/workflows/dotnet.yml/badge.svg)](https://github.com/ruialexrib/Programatica.Auth.SAML.ServiceProviderUtils/actions/workflows/dotnet.yml)

# Programatica.Auth.SAML.ServiceProviderUtils

The main purpose of this project is provide a set of utilities to implement SAML authentication in .net core projects.

## Factories

| File |  Description |
| ------------------- | ------------------- |
|  AuthnRequestFactory.cs |  builds a SAMLRequest (AuthnRequest) and create an encoded url to start the Single Sign On (SSO) process |
|  LogoutRequestFactory.cs |  builds a SAMLRequest (LogoutRequest) and create an encoded url to start the Single Log Out (SLO) process |
|  LogoutResponseFactory.cs |  builds a LogoutResponse (LogoutRequest) and create an encoded url to end the Single Log Out (SLO) process |

## Utilities

| File |  Description |
| ------------------- | ------------------- |
|  AssertionParserUtils.cs |  utility with functions to handle the assertion (decryption, signature validation, get attributes by name) |
|  CertificateUtils.cs |  utility with functions to load X509Certificates  |
|  EncodeUtils.cs |  utility with functions to handle the DecodeAndInflate and DeflateAndEncode |
|  XPathsUtils.cs |  utility to help parse the assertion xml  |


## How to use (Service Provider in asp.net core 6)
To this demonstration we will create an asp.net mvc projet targeting .net core 6. 

Start adding a reference to this project (Programatica.Auth.SAML.ServiceProviderUtils)

### Step 1 - Create the AuthRequest and redirect to url
```csharp
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

### Step 2 - Create an endpoint to handle the assertion... 
This endpoint is the Assertion Consumer Service... the url where the IDP will delivery (post) the authenticated user attributes 
```csharp
[HttpPost]
public async Task<ActionResult> Acs()
{
    var assertionParser = new AssertionParserUtils();
    var sAMLResponse = Request.Form["SAMLResponse"];
    var relayState = Request.Form["RelayState"];
    assertionParser.LoadXmlFromBase64(sAMLResponse);

    // verifica assinatura
    bool isValid = assertionParser.IsValid();

    if (isValid)
    {
        // desencripta
        var cert = CertificateUtils.LoadCertificateFile("idp_sp.pfx");
        assertionParser.DecryptIfNeeded(cert);

        var user = assertionParser.GetAttributeByName("http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name", 0);
        var sessionindex = assertionParser.GetResponseSessionIndex();
        var nameid = assertionParser.GetResponseNameId();
        await Auth(username: user);

        return RedirectToAction("Index");
    }
    else
    {
        throw new Exception("XML signature not valid.");
    }
}
```

### Step 3 - Create the LogoutRequest and redirect to url
```csharp
public IActionResult Logout()
{
    HttpContext.SignOutAsync();

    var logoutRequestFactory = new LogoutRequestFactory(requestDestination: "http://localhost:8080/simplesaml/saml2/idp/SingleLogoutService.php",
                                                        issuer: "https://localhost:44396/",
                                                        cert: CertificateUtils.LoadCertificateFile("idp_sp.pfx"));

    var redirectUrl = logoutRequestFactory.GetRedirectUrl(samlEndpoint: "http://localhost:8080/simplesaml/saml2/idp/SingleLogoutService.php",
                                                          sign: true);

    return Redirect(redirectUrl);
}
```

### Step 4 - Create an endpoint to handle the the LogoutResponse/LogoutRequest
```csharp
public IActionResult Slo()
{
    // valida se temos uma SAMLResponse ou SAMLRequest
    if (HttpContext.Request.Query["SAMLResponse"].ToString() == null && HttpContext.Request.Query["SAMLRequest"].ToString() == null)
    {
        throw new Exception("SAMLRequest or SAMLResponse not found.");
    }
    else
    {
        // trata-se da resposta ao pedido de SLO iniciado pelo SP
        if (HttpContext.Request.Query["SAMLResponse"].ToString() != null)
        {
            // trata-se da resposta ao pedido de SLO iniciado pelo SP
            // tratar SAMLResponse
            var SAMLResponse = EncodeUtils.DecodeAndInflate(HttpContext.Request.Query["SAMLResponse"].ToString());
            return RedirectToAction("Index");
        }
        else
        {
            // trata-se de um pedido inicido pelo IDP para SLO   
            var sAMLRequest = EncodeUtils.DecodeAndInflate(HttpContext.Request.Query["SAMLRequest"].ToString());
            var relaystate = HttpContext.Request.Query["RelayState"].ToString();

            // TODO: validar samlrequest
            // para efeitos de demo, o SP vai apenas terminar a sessão

            // logout
            HttpContext.SignOutAsync();

            // build response
            var request = new LogoutResponseFactory(
                                requestDestination: "http://localhost:8080/simplesaml/saml2/idp/SingleLogoutService.php",
                                issuer: "https://localhost:44396/",
                                relaystate);

            var redirectUrl = request.GetRedirectUrl(samlEndpoint: "http://localhost:8080/simplesaml/saml2/idp/SingleLogoutService.php");

            return Redirect(redirectUrl);
        }
    }
}
```
