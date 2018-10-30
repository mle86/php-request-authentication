# RequestAuthenticator Class

Wraps an [AuthenticationMethod] instance to authenticate outbound requests.

- Can be used to add authentication data to any [PSR-7](https://www.php-fig.org/psr/psr-7/)
  [`RequestInterface`](https://github.com/php-fig/http-message/blob/master/src/RequestInterface.php).
  with the `authenticate()` method.
- Can be used to add authentication data to any [Symfony HttpFoundation](https://symfony.com/doc/current/components/http_foundation.html) `Request`
  with the `authenticateSymfonyRequest()` method.
- The instance itself is a valid [Guzzle middleware](http://docs.guzzlephp.org/en/stable/handlers-and-middleware.html).

[Exceptions]: Exceptions.md
[KeyRepository]: Class_KeyRepository.md
[AuthenticationMethod]: Class_AuthenticationMethod.md
[RequestAuthenticator]: Class_RequestAuthenticator.md
[RequestVerifier]: Class_RequestVerifier.md
[RequestInfo]: Class_RequestInfo.md


## Class Details

* Full class name: <code>mle86\\RequestAuthentication\\<b>RequestAuthenticator</b></code>
* Class file: [src/RequestAuthenticator.php](../src/RequestAuthenticator.php)


## Methods

* **Constructor:** <code>\_\_construct ([AuthenticationMethod] $method, string $apiClientId, string $apiSecretKey)</code>

* <code><b>authenticate</b> (Psr\Http\Message\RequestInterface $request): Psr\Http\Message\RequestInterface</code>  
    Takes a PSR-7 RequestInterface instance
    and returns a new RequestInterface instance with added authentication data.  
    _Side Effect:_ This will cause a `StreamInterface::rewind()` call on `RequestInterface::getBody()`.  

* <code><b>authenticateSymfonyRequest</b> (Symfony\Component\HttpFoundation\Request $request): Symfony\Component\HttpFoundation\Request</code>  
    Takes a Symfony HttpFoundation Request instance
    and returns a new Request instance with added authentication data.

* <code><b>\_\_invoke</b> (): \Closure</code>  
    Returns a GuzzleHttp middleware handler
    that will add authentication data to all requests
    according to the constructor settings.  
    `HandlerStack::push()` can be used to add this RequestAuthenticator instance to a middleware handler stack.

All `authenticate…()` methods throw a [CryptoErrorException][Exceptions] if there was a problem with a low-level cryptographic function.

