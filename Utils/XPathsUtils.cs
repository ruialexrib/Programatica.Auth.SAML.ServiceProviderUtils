namespace Programatica.Auth.SAML.ServiceProviderUtils.Utils
{
    public static class XPathsUtils
    {
        public static string FirstAssertion = "/samlp:Response/saml:Assertion[1]";
        public static string FirstAssertionsAttributeStatement => $"{FirstAssertion}/saml:AttributeStatement";
        public static string FirstAssertionSubject => $"{FirstAssertion}/saml:Subject";

        public static string FirstAssertionAuthnStatement => $"{FirstAssertion}/saml:AuthnStatement";
    }
}
