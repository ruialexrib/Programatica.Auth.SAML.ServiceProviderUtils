using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Mvc;
using Programatica.Auth.Saml.SpDemo.Models;
using Programatica.Auth.SAML.ServiceProviderUtils;
using Programatica.Auth.SAML.ServiceProviderUtils.Utils;
using System.Diagnostics;
using System.Security.Claims;
using System.Text;

namespace Programatica.Auth.Saml.SpDemo.Controllers
{
    public class HomeController : Controller
    {
        private readonly ILogger<HomeController> _logger;

        public HomeController(ILogger<HomeController> logger)
        {
            _logger = logger;
        }

        public IActionResult Index()
        {
            return View();
        }

        public IActionResult Privacy()
        {
            return View();
        }

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



        [ResponseCache(Duration = 0, Location = ResponseCacheLocation.None, NoStore = true)]
        public IActionResult Error()
        {
            return View(new ErrorViewModel { RequestId = Activity.Current?.Id ?? HttpContext.TraceIdentifier });
        }

        private async Task Auth(string username)
        {
            List<Claim> claims = new List<Claim>();

            claims.Add(new Claim("Username", username));

            ClaimsIdentity identity = new ClaimsIdentity(claims, CookieAuthenticationDefaults.AuthenticationScheme);
            ClaimsPrincipal principal = new ClaimsPrincipal(identity);
            await HttpContext.SignInAsync(CookieAuthenticationDefaults.AuthenticationScheme, principal);
        }
    }
}