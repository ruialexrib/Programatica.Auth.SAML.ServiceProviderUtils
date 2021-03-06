<?php
$metadata['https://localhost:44396/'] = [
    'entityid' => 'https://localhost:44396/',
    'contacts' => [],
    'metadata-set' => 'saml20-sp-remote',
    'expire' => 1689554295,
    'AssertionConsumerService' => [
        [
            'Binding' => 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST',
            'Location' => 'https://localhost:44396/home/acs',
            'index' => 1,
        ],
    ],
    'SingleLogoutService' => [
        [
            'Binding' => 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect',
            'Location' => 'https://localhost:44396/home/slo',
        ],
    ],
    'NameIDFormat' => 'urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified',
    'keys' => [
        [
            'encryption' => false,
            'signing' => true,
            'type' => 'X509Certificate',
            'X509Certificate' => 'MIIEgDCCAuigAwIBAgITcaGmBEmxZxowuyKB0v7ZFwmO8TANBgkqhkiG9w0BAQsFADBQMQswCQYDVQQGEwJQVDEOMAwGA1UECAwFUG9ydG8xDjAMBgNVBAcMBVBvcnRvMSEwHwYDVQQKDBhJbnRlcm5ldCBXaWRnaXRzIFB0eSBMdGQwHhcNMjEwOTA4MDkyMjA5WhcNMzEwOTA4MDkyMjA5WjBQMQswCQYDVQQGEwJQVDEOMAwGA1UECAwFUG9ydG8xDjAMBgNVBAcMBVBvcnRvMSEwHwYDVQQKDBhJbnRlcm5ldCBXaWRnaXRzIFB0eSBMdGQwggGiMA0GCSqGSIb3DQEBAQUAA4IBjwAwggGKAoIBgQC2t8/52rLavw+c1qPhVqPZfDLesFE/0HNPSdog59QE2awUhGUXS+OaRhugmH/2SincJnY00nMlu8T6iw6dqUg5MQXPabAuidVexJiGPojypv+Rdc5Dxt81YHmjtVNjmQpJAHqAm5F9ARnerLg5yEP7/cRXbAADcyDFWqrLNfM/jUBxREl9Nz6GWQv7gPSXZFXpCOJZI/YXsEbcuWJ0HkHrtVDFnF3Mo87tehEhRYG/zByr4OMyKo5hTrs4mKaMWm4bnc9zuabk9/TMTD2A47OMOJEZgYK6HVWm/2bxNs0k1ajKRhuWEWvn94AMfOkvSM/Idvba5eG2vb8FaGF1YyMo29WWeF2qX55LU81AW4bM+1JTXHK4Nz+APiRTvGUQp6bl3NGZmo2jyIqAayJRuUEOiSTqwuMpJU5yP+dHjieVcYF0v/o1lK3m+ZV+DrN+J29azJVqb8yJMWHRuomciEEmuXcRrBCCqgE2H9m4lXStbb3H6SxQFZcJV8Yn0MJBdwMCAwEAAaNTMFEwHQYDVR0OBBYEFLqX6L0J9pRK+Uio34DavmaQ9dp2MB8GA1UdIwQYMBaAFLqX6L0J9pRK+Uio34DavmaQ9dp2MA8GA1UdEwEB/wQFMAMBAf8wDQYJKoZIhvcNAQELBQADggGBAG68S0erfP1GOJs1ssP7PCm2erjmVIEY4SY3l+s8KtNT3q4x78DkIQpWyoOd4KuBPbLEQqRkTModlZGGRasJIASyUkG9IjFyBapEQAiSg30cTXlb5L+a7erlcysTosXNGdsJxu9K02esXu9we3iPcfNWy+a7MVi7DAdz6hZENue6FyvkLgaQ6C5DQOA78GoSbNg65ESDXMOVu7dGGwOMMx3pDuodPYonFOAmi/A4yHC6dyErVfuw7aBrqPv8CkBGYwdz/f4HB33249GqPFQRfgYA4A3I+4BpWKgXiTM+mmawWdkLW4d1Qg/tlCsYuiLY4peeL3NgS/kFBZiXJn8xM1o4GlqFpD8ujiYYvZHSMT1LzxQQJC9zeDwjq93XOzB/MXIo0wzSRupoqb9z/B86A3oe8s1qqOlF4OuLryEBRQmzWjwdJ9ZA5KDNt79wkQLCFj4n8tebNYHC9oPnoFN8P25samin5P72PKBHjR195x0HNzojbAsY2cfoccPnMbvR+Q==',
        ],
        [
            'encryption' => true,
            'signing' => false,
            'type' => 'X509Certificate',
            'X509Certificate' => 'MIIEgDCCAuigAwIBAgITcaGmBEmxZxowuyKB0v7ZFwmO8TANBgkqhkiG9w0BAQsFADBQMQswCQYDVQQGEwJQVDEOMAwGA1UECAwFUG9ydG8xDjAMBgNVBAcMBVBvcnRvMSEwHwYDVQQKDBhJbnRlcm5ldCBXaWRnaXRzIFB0eSBMdGQwHhcNMjEwOTA4MDkyMjA5WhcNMzEwOTA4MDkyMjA5WjBQMQswCQYDVQQGEwJQVDEOMAwGA1UECAwFUG9ydG8xDjAMBgNVBAcMBVBvcnRvMSEwHwYDVQQKDBhJbnRlcm5ldCBXaWRnaXRzIFB0eSBMdGQwggGiMA0GCSqGSIb3DQEBAQUAA4IBjwAwggGKAoIBgQC2t8/52rLavw+c1qPhVqPZfDLesFE/0HNPSdog59QE2awUhGUXS+OaRhugmH/2SincJnY00nMlu8T6iw6dqUg5MQXPabAuidVexJiGPojypv+Rdc5Dxt81YHmjtVNjmQpJAHqAm5F9ARnerLg5yEP7/cRXbAADcyDFWqrLNfM/jUBxREl9Nz6GWQv7gPSXZFXpCOJZI/YXsEbcuWJ0HkHrtVDFnF3Mo87tehEhRYG/zByr4OMyKo5hTrs4mKaMWm4bnc9zuabk9/TMTD2A47OMOJEZgYK6HVWm/2bxNs0k1ajKRhuWEWvn94AMfOkvSM/Idvba5eG2vb8FaGF1YyMo29WWeF2qX55LU81AW4bM+1JTXHK4Nz+APiRTvGUQp6bl3NGZmo2jyIqAayJRuUEOiSTqwuMpJU5yP+dHjieVcYF0v/o1lK3m+ZV+DrN+J29azJVqb8yJMWHRuomciEEmuXcRrBCCqgE2H9m4lXStbb3H6SxQFZcJV8Yn0MJBdwMCAwEAAaNTMFEwHQYDVR0OBBYEFLqX6L0J9pRK+Uio34DavmaQ9dp2MB8GA1UdIwQYMBaAFLqX6L0J9pRK+Uio34DavmaQ9dp2MA8GA1UdEwEB/wQFMAMBAf8wDQYJKoZIhvcNAQELBQADggGBAG68S0erfP1GOJs1ssP7PCm2erjmVIEY4SY3l+s8KtNT3q4x78DkIQpWyoOd4KuBPbLEQqRkTModlZGGRasJIASyUkG9IjFyBapEQAiSg30cTXlb5L+a7erlcysTosXNGdsJxu9K02esXu9we3iPcfNWy+a7MVi7DAdz6hZENue6FyvkLgaQ6C5DQOA78GoSbNg65ESDXMOVu7dGGwOMMx3pDuodPYonFOAmi/A4yHC6dyErVfuw7aBrqPv8CkBGYwdz/f4HB33249GqPFQRfgYA4A3I+4BpWKgXiTM+mmawWdkLW4d1Qg/tlCsYuiLY4peeL3NgS/kFBZiXJn8xM1o4GlqFpD8ujiYYvZHSMT1LzxQQJC9zeDwjq93XOzB/MXIo0wzSRupoqb9z/B86A3oe8s1qqOlF4OuLryEBRQmzWjwdJ9ZA5KDNt79wkQLCFj4n8tebNYHC9oPnoFN8P25samin5P72PKBHjR195x0HNzojbAsY2cfoccPnMbvR+Q==',
        ],
    ],
    'validate.authnrequest' => true,
    'saml20.sign.assertion' => false,
];