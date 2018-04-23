# php-request-authentication

This PHP library provides a generic interface for authenticating outbound API requests
and for verifying inbound API requests' authentication.

It is released under the [MIT License](https://opensource.org/licenses/MIT).


# Installation:

Via Composer:  `$ composer require mle86/request-authentication`

Or insert this into your project's `composer.json` file:

```js
"require": {
    "mle86/value": "^1.0"
}
```


# Minimum PHP version:

PHP 7.1


# Classes and interfaces:

* Main wrapper classes:
    * [RequestAuthenticator] wrapper class,
    * [RequestVerifier] wrapper class,
* [AuthenticationMethod] main interface:
    * [BasicAuthenticationMethod] class,
    * [DefaultAuthenticationMethod] class,
    * [PublicKeyMethod] class,
    * [MethodStack] composite class.
* [RequestInfo] data transfer object,
* [KeyRepository] base class:
    * [ArrayRepository] class,
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

