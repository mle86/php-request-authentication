# PublicKeyMethod Class

Authentication method using public/private client keys.

This method is similar to the [DefaultAuthenticationMethod]
in that it will add a random `X-Request-ID` header (if missing)
which will also be checked by the `verify()` method.

It also has the client identification string in the `X-API-Client` header.

It has however no `X-API-Token` header.
It has the `X-API-Signature` header instead
which contains a cryptographic signature
calculated using the client's private key
and verified using the client's public key.

This means that the [KeyRepository] supplied to `verify()`
must return the client's public key.
The client's private key should not be stored on the server side at all.

This method assumes that the
[paragonie/halite](https://github.com/paragonie/halite) cryptographic library
is available in your project.


[Exceptions]: Exceptions.md
[KeyRepository]: Class_KeyRepository.md
[AuthenticationMethod]: Class_AuthenticationMethod.md
[DefaultAuthenticationMethod]: Class_DefaultAuthenticationMethod.md
[RequestAuthenticator]: Class_RequestAuthenticator.md
[RequestVerifier]: Class_RequestVerifier.md


## Requirements

Using this class requires the [paragonie/halite](https://github.com/paragonie/halite) library
and the [libsodium](https://github.com/jedisct1/libsodium-php) extension
(it's a core PHP module starting with PHP 7.2).

```sh
composer require paragonie/halite
```


## Class Details

* Full class name: <code>mle86\\RequestAuthentication\\AuthenticationMethod\\<b>PublicKeyMethod</b></code>.
* Class file: [src/AuthenticationMethod/PublicKeyMethod.php](../src/AuthenticationMethod/PublicKeyMethod.php)


## Constructor

* <code><b>\_\_construct</b> ()</code>


## Using Public and Private Keys

The library includes the
[HaliteSigningPublicKey](../src/Crypto/Halite/HaliteSigningPublicKey.php)
and
[HaliteSigningPrivateKey](../src/Crypto/Halite/HaliteSigningPrivateKey.php)
wrapper classes.
They're used internally
and for key pair generation.

**To generate a new key pair,**
use the `HaliteSigningPrivateKey::generate()` constructor:

```php
<?php
use mle86\RequestAuthentication\Crypto\Halite\HaliteSigningPrivateKey;
use mle86\RequestAuthentication\Crypto\Halite\HaliteSigningPublicKey;

$privateKey = HaliteSigningPrivateKey::generate();                 // instanceof HaliteSigningPrivateKey
$publicKey  = HaliteSigningPublicKey::fromPrivateKey($privateKey); // instanceof HaliteSigningPublicKey

$encodedPrivateKey = $privateKey->getEncodedForm(); // printable string
$encodedPublicKey  = $publicKey->getEncodedForm();  // printable string
```

The encoded private key should be stored on the client side only.
It's needed to authenticate outbound requests.

The encoded public key should be stored on the server side
in the [KeyRepository] that will be used later for request verification.

The encoded form returned by `getEncodedForm()`
is a printable string without whitespace.
It is the only key form that will be used later,
the `HaliteSigningPublicKey`/`HaliteSigningPrivateKey` wrapper classes
won't be used directly.


## Authenticating and Verifying Requests

**To authenticate an outbound request,**
the encoded form of a `HaliteSigningPrivateKey` is needed.
(This is a string that should be sent to the client once after generating a new public/private key pair.
 It should not be stored on the server side, as that would defeat the purpose of public/private cryptography.)

```php
<?php
use mle86\RequestAuthentication\RequestAuthenticator;
use mle86\RequestAuthentication\AuthenticationMethod\PublicKeyMethod;

$clientId          = …;
$encodedPrivateKey = …;
$request           = …;

$authenticator = new RequestAuthenticator(
    new PublicKeyMethod,
    $clientId,
    $encodedPrivateKey);

$authenticated_request = $authenticator->authenticate($request);
```

**To verify an inbound request,**
a [KeyRepository] that returns the client's encoded public key is needed.

```php
<?php
use mle86\RequestAuthentication\RequestVerifier;
use mle86\RequestAuthentication\KeyRepository\ArrayRepository;
use mle86\RequestAuthentication\AuthenticationMethod\PublicKeyMethod;

$clientId         = …;
$encodedPublicKey = …;
$inboundRequest   = …;

$keys = new ArrayRepository([
    $clientId => $encodedPublicKey,
]);

$verifier = new RequestVerifier(
    new PublicKeyMethod,
    $keys);

$verifier->verify($inboundRequest);
```

