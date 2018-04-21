# DefaultAuthenticationMethod Class

Default authentication method
for basic hash authentication.

- Valid requests contain a `X-API-Client` HTTP header
  containing the client ID.

- Valid requests contain a `X-API-Token` HTTP header
  containing a SHA256 HMAC hash
  of the request body,
  the HTTP method and URI,
  the `Content-Type` header,
  and the used client ID.  
  The client secret is used as the HMAC key.  

- Valid requests contain a `X-Request-ID` HTTP header
  containing a hexadecimal value (length: 32…100),
  e.g. some random SHA256 value.  
  That value should NOT be calculated from the request data.

- The client secret is used both for signing and for verifying.

- The `authenticate` method will...
   - add a random `X-Request-ID` HTTP header (if there is none),
   - add the `X-API-Client` HTTP header,
   - add the `X-API-Token` HTTP header with the calculated authentication token.

- The `verify` method will...
   - check if the `X-Request-ID` header value is present, has the correct length, and is some hexadecimal value,
   - check if the `X-API-Client` header value is a client ID known in the supplied [KeyRepository],
   - check if the `X-API-Token` authentication token header value matches the request data and the client's secret.

- The `verify` method **will NOT...**
    - check if the `X-Request-ID` header value is actually unique.

[Exceptions]: Exceptions.md
[KeyRepository]: Class_KeyRepository.md
[AuthenticationMethod]: Class_AuthenticationMethod.md
[RequestAuthenticator]: Class_RequestAuthenticator.md
[RequestVerifier]: Class_RequestVerifier.md
[RequestInfo]: Class_RequestInfo.md


## Class Details

* Full class name: <code>mle86\\RequestAuthentication\\AuthenticationMethod\\<b>DefaultAuthenticationMethod</b></code>.
* Class file: [src/AuthenticationMethod/DefaultAuthenticationMethod.php](../src/AuthenticationMethod/DefaultAuthenticationMethod.php)


## Constructor

* <code><b>\_\_construct</b> ()</code>

