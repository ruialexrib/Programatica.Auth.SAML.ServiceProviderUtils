# Programatica.Auth.SAML.ServiceProviderUtils

The main purpose of this project is to provide a set of utilities to implement SAML authentication in .net core projects.

## Factories
- AuthnRequestFactory.cs - builds a SAMLRequest (AuthnRequest) and create an encoded url to start the Single Sign On (SSO) process
- LogoutRequestFactory - builds a SAMLRequest (LogoutRequest) and create an encoded url to start the Single Log Out (SLO) process
- LogoutResponseFactory.cs - builds a LogoutResponse (LogoutRequest) and create an encoded url to end the Single Log Out (SLO) process
