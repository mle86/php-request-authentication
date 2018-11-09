# Usage Example: htpasswd file

This library can be used
to verify inbound requests'
`Authorization: Basic …` headers
against a htpasswd file.

```php
<?php

use mle86\RequestAuthentication\KeyRepository\FileRepository;
use mle86\RequestAuthentication\AuthenticationMethod\BasicHashAuthenticationMethod;
use mle86\RequestAuthentication\RequestVerifier;

// Reading a local htpasswd-style file takes a FileRepository:
$keyRepository = new FileRepository('./path/htpasswd');

// Verifying HTTP Basic authorization headers can be done with the BasicAuthenticationMethod class
//  (if your htpasswd files contains plaintext passwords)
// or with the BasicHashAuthenticationMethod
//  (if your htpasswd files contains hashed passwords, as it should).
$authenticationMethod = new BasicHashAuthenticationMethod();

// We're good to go, but the RequestVerifer helper class simplifies things a little bit:
$verifier = new RequestVerifier($authenticationMethod, $keyRepository);

// Now for the actual verification:
$clientId = $verifier->verifyGlobals();
// If we had a PSR-7 RequestInterface instance,
// we could do this instead:
#  $clientId = $verifier->verify($request);

// If we got a MissingAuthenticationHeaderException, the request had no `Authorization: Basic` header.
// If we got an InvalidAuthenticationException, the username was not found in the htpasswd file
//  or the password was incorrect.
// If we reach this line without any exceptions,
//  the request contained a valid Basic header!

// We now have the Basic username in $clientId:
print "Welcome, {$clientId}!";
```
