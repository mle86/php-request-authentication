# php-request-authentication

[![Build Status](https://travis-ci.org/mle86/php-request-authentication.svg?branch=master)](https://travis-ci.org/mle86/php-request-authentication)
[![Coverage Status](https://coveralls.io/repos/github/mle86/php-request-authentication/badge.svg?branch=master)](https://coveralls.io/github/mle86/php-request-authentication?branch=master)
[![Latest Stable Version](https://poser.pugx.org/mle86/request-authentication/version)](https://packagist.org/packages/mle86/request-authentication)
[![License](https://poser.pugx.org/mle86/request-authentication/license)](https://packagist.org/packages/mle86/request-authentication)

This PHP library provides a generic interface for authenticating outbound API requests
and for verifying inbound API requests' authentication.

It is released under the [MIT License](https://opensource.org/licenses/MIT).


## Installation:

Via Composer:  `$ composer require mle86/request-authentication`

Or insert this into your project's `composer.json` file:

```js
"require": {
    "mle86/request-authentication": "^0"
}
```


## Minimum PHP version:

PHP 7.1


## Workflow:

This library contains several [AuthenticationMethod] classes.

Each of those represents one mechanism for request authentication and verification.
The [BasicAuthenticationMethod] for example adds an `Authorization: Basic …` HTTP header to outbound requests
and verifies that header in inbound requests against a list of known usernames and their passwords.

Usually the [AuthenticationMethod] classes won't be used directly
(apart from instantiating them),
there's the [RequestAuthenticator] and [RequestVerifier] wrapper classes instead
that take an AuthenticationMethod dependency.

To sign/authenticate an outbound request
you'll need an [AuthenticationMethod] instance
wrapped in a [RequestAuthenticator] instance,
a client ID and a client secret,
and the request to sign.
The `authenticate()` method will add the required authentication methods to the request
so that it can be sent.

To verify an inbound request
you'll need an [AuthenticationMethod] instance of the same class
wrapped in a [RequestVerifier] instance
and a [KeyRepository] that will map the request's client ID
to the same client secret used for signing the request.  
(In case of the [PublicKeyMethod] class,
the client will use its private key for signing
and the [KeyRepository] must return the client's public key.)


## Classes and interfaces:

* Main wrapper classes:
    * [RequestAuthenticator] wrapper class,
    * [RequestVerifier] wrapper class.
* [AuthenticationMethod] main interface:
    * [BasicAuthenticationMethod] class,
    * [DefaultAuthenticationMethod] class,
    * [PublicKeyMethod] class,
    * [MethodStack] composite class.
* [RequestInfo] data transfer object.
* [KeyRepository] base class:
    * [ArrayRepository] class.
* [Exceptions] classes.

[RequestAuthenticator]: doc/Class_RequestAuthenticator.md
[RequestVerifier]: doc/Class_RequestVerifier.md
[AuthenticationMethod]: doc/Class_AuthenticationMethod.md
[BasicAuthenticationMethod]: doc/Class_BasicAuthenticationMethod.md
[DefaultAuthenticationMethod]: doc/Class_DefaultAuthenticationMethod.md
[PublicKeyMethod]: doc/Class_PublicKeyMethod.md
[RequestInfo]: doc/Class_RequestInfo.md
[KeyRepository]: doc/Class_KeyRepository.md
[ArrayRepository]: doc/Class_ArrayRepository.md
[Exceptions]: doc/Exceptions.md
[MethodStack]: doc/Class_MethodStack.md

