# BasicHashAuthenticationMethod Class

Implements HTTP “Basic” authentication
with hashed password storage.

 - The Basic username is the `$apiClientId`,
 - the Basic password is the `$apiClientKey`.
 - The Basic password must also be returned unchanged by the [KeyRepository].

This class expects the KeyRepository to contain only hashed passwords
(in contrast to the simpler [BasicAuthenticationMethod]
which expects the repository to contain plaintext passwords).
This works well with `htpasswd` files and the [FileRepository].

The following hash formats are recognized:
 - Prefixes `$1$` (MD5),
   `$2$`/`$2a$`/`$2x$`/`$2y$` (bcrypt),
   `$5$` (SHA-256),
   `$6$` (SHA-512),
   and `$argon2i$` (Argon2 -- only on PHP7.2+)
   as returned by [crypt()] and [password_hash()].
 - Prefixes
   `{SHA}` (SHA-1),
   `{SSHA}` (salted SHA-1),
   and `$apr1$` (APR1-MD5)
   as traditionally used in htpasswd files.

[Exceptions]: Exceptions.md
[KeyRepository]: Class_KeyRepository.md
[AuthenticationMethod]: Class_AuthenticationMethod.md
[BasicAuthenticationMethod]: Class_BasicAuthenticationMethod.md
[FileRepository]: Class_FileRepository.md
[RequestAuthenticator]: Class_RequestAuthenticator.md
[RequestVerifier]: Class_RequestVerifier.md
[RequestInfo]: Class_RequestInfo.md
[crypt()]: https://php.net/manual/function.crypt.php
[password_hash()]: https://secure.php.net/manual/en/function.password-hash.php


## Class Details

* Full class name: <code>mle86\\RequestAuthentication\\AuthenticationMethod\\<b>BasicHashAuthenticationMethod</b></code>
* Class file: [src/AuthenticationMethod/BasicHashAuthenticationMethod.php](../src/AuthenticationMethod/BasicHashAuthenticationMethod.php)
* Inheritance:
    * extends [BasicAuthenticationMethod]
    * implements [AuthenticationMethod]


## Constructor

* <code><b>\_\_construct</b> ()</code>

