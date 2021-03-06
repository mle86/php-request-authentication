# BasicAuthenticationMethod Class

Implements HTTP “Basic” authentication.

 - The Basic username is the `$apiClientId`,
 - the Basic password is the `$apiClientKey`.
 - The Basic password must also be returned unchanged by the [KeyRepository].

If you want to store the Basic password in hashed form instead of plaintext passwords,
use the [BasicHashAuthenticationMethod] class instead.

This is here mostly for testing and completeness purposes;
whatever HTTP/REST/PSR-7 library you're using,
it can probably do this better.

[Exceptions]: Exceptions.md
[KeyRepository]: Class_KeyRepository.md
[AuthenticationMethod]: Class_AuthenticationMethod.md
[BasicHashAuthenticationMethod]: Class_BasicHashAuthenticationMethod.md
[RequestAuthenticator]: Class_RequestAuthenticator.md
[RequestVerifier]: Class_RequestVerifier.md
[RequestInfo]: Class_RequestInfo.md


## Class Details

* Full class name: <code>mle86\\RequestAuthentication\\AuthenticationMethod\\<b>BasicAuthenticationMethod</b></code>
* Class file: [src/AuthenticationMethod/BasicAuthenticationMethod.php](../src/AuthenticationMethod/BasicAuthenticationMethod.php)
* Inheritance:
    * implements [AuthenticationMethod]


## Constructor

* <code><b>\_\_construct</b> ()</code>

