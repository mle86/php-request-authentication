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
[RequestIdList]: Class_RequestIdList.md


## Class Details

* Full class name: <code>mle86\\RequestAuthentication\\<b>RequestVerifier</b></code>
* Class file: [src/RequestVerifier.php](../src/RequestVerifier.php)


## Methods

* **Constructor:** <code>\_\_construct ([AuthenticationMethod] $method, [KeyRepository] $keys)</code>

* <code><b>withRequestIdList</b> (?[RequestIdList] $requestIdList): self</code>  
    Adds a [RequestIdList] instance to this RequestVerifier
    which will be used to ensure Request ID Uniqueness
    for all valid inbound requests.  

* <code><b>verify</b> (Psr\Http\Message\RequestInterface $request): string</code>  
    Takes a PSR-7 RequestInterface instance
    and checks the contained authentication token data.
    _Side Effect:_ This will cause a `StreamInterface::rewind()` call on `RequestInterface::getBody()`.  

* <code><b>verifySymfonyRequest</b> (Symfony\Component\HttpFoundation\Request $request): string</code>  
    Takes a Symfony HttpFoundation Request instance
    and checks the contained authentication token data.

* <code><b>verifyGlobals</b> (): string</code>  
     Reads the PHP globals (`$_SERVER` and `php://stdin`)
     to read the current request (using <code>[RequestInfo]::fromGlobals()</code>)
     and checks the contained authentication token data.  
     _Side Effect:_ This will open, read, rewind, and close `php://stdin`.

**Return values:**

On success, all verification methods
return the client identification string
as returned by <code>[AuthenticationMethod]::getClientId()</code>.

**Exceptions:**

* All verification methods throw a [MissingAuthenticationHeaderException][Exceptions] on missing or empty authentication header(s).
* All verification methods throw a [InvalidAuthenticationException][Exceptions] on incorrect authentication header(s).
* All verification methods throw a [CryptoErrorException][Exceptions] if there was a problem with a low-level cryptographic function.
* All verification methods throw a [DuplicateRequestIDException][Exceptions] if the request was valid but contained an already-seen Request ID (requires `withRequestIdList()`).

