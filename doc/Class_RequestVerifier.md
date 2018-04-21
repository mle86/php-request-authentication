# RequestVerifier Class

Wraps an [AuthenticationMethod] instance to verify inbound request authentication data.

- Can be used to verify authentication data in any [PSR-7](https://www.php-fig.org/psr/psr-7/)
  [`RequestInterface`](https://github.com/php-fig/http-message/blob/master/src/RequestInterface.php)
  with the `verify()` method.
- Can be used to verify authentication data in any [Symfony HttpFoundation](https://symfony.com/doc/current/components/http_foundation.html) `Request`
  with the `verifySymfonyRequest()` method.

[Exceptions]: Exceptions.md
[KeyRepository]: Class_KeyRepository.md
[AuthenticationMethod]: Class_AuthenticationMethod.md
[RequestAuthenticator]: Class_RequestAuthenticator.md
[RequestVerifier]: Class_RequestVerifier.md
[RequestInfo]: Class_RequestInfo.md


## Class Details

* Full class name: <code>mle86\\RequestAuthentication\\<b>RequestVerifier</b></code>.
* Class file: [src/RequestVerifier.php](../src/RequestVerifier.php)


## Methods

* **Constructor:** <code>\_\_construct ([AuthenticationMethod] $method, [KeyRepository] $keys)</code>

* <code><b>verify</b> (Psr\Http\Message\RequestInterface $request): void</code>  
    Takes a PSR-7 RequestInterface instance
    and checks the contained authentication token data.
    _Side Effect:_ This will cause a `StreamInterface::rewind()` call on `RequestInterface::getBody()`.  

* <code><b>verifySymfonyRequest</b> (Symfony\Component\HttpFoundation\Request $request): void</code>  
    Takes a Symfony HttpFounddation Request instance
    and checks the contained authentication token data.

All `verify…()` methods throw a [MissingAuthenticationHeaderException][Exceptions] on missing or empty authentication header(s).  
All `verify…()` methods throw a [InvalidAuthenticationException][Exceptions] on incorrect authentication header(s).  
All `verify…()` methods throw a [CryptoErrorException][Exceptions] if there was a problem with a low-level cryptographic function.

