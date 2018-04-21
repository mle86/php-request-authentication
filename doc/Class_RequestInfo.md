# RequestInfo Data Transfer Object

Encapsulates all relevant information about one HTTP request.

These objects are consumed internally by the [AuthenticationMethod] implementations.
They are built by the [RequestAuthenticator] and [RequestVerifier] wrapper classes.

[Exceptions]: Exceptions.md
[AuthenticationMethod]: Class_AuthenticationMethod.md
[RequestAuthenticator]: Class_RequestAuthenticator.md
[RequestVerifier]: Class_RequestVerifier.md


## Class Details

* Full class name: <code>mle86\\RequestAuthentication\\DTO\\<b>RequestInfo</b></code>.
* Class file: [src/DTO/RequestInfo.php](../src/DTO/RequestInfo.php)


## Constructors

* <code><b>\_\_construct</b> (
        string $http\_method,
        string $http\_scheme,
        string $http\_host,
        string $http\_path = '/',
        string $request\_body = '',
        array  $request\_headers = [])</code>  
    As this is a long and cumbersome invocation,
    use one of the other constructor methods below.
    
* <code><b>fromGlobals</b> ()</code>  
    Builds a new instance from PHP's global variables
    (`$_SERVER` and the `php://input` pseudo-file).

* <code><b>fromSymfonyRequest</b> (Symfony\Component\HttpFoundation\Request $request)</code>  
    Builds a new instance from a [symfony/http-foundation](https://symfony.com/doc/current/components/http_foundation.html) request.

* <code><b>fromPsr7</b> (Psr\Http\Message\RequestInterface $request)</code>  
    Builds a new interface from a [PSR-7](https://www.php-fig.org/psr/psr-7/)
    [`RequestInterface`](https://github.com/php-fig/http-message/blob/master/src/RequestInterface.php).
    (Also supports the [`ServerRequestInterface`](https://github.com/php-fig/http-message/blob/master/src/ServerRequestInterface.php) as it is a subclass.)

## Methods

This class is used internally by the library.
There should be no need to use any of its methods (besides the constructors).

* <code><b>getHttpMethod</b> (): string</code>  
  (GET)
* <code><b>getHttpScheme</b> (): string</code>  
  (https)
* <code><b>getHttpHost</b> (): string</code>  
  (www.domain.test:8080)
* <code><b>getHttpPath</b> (): string</code>  
  (/foo/bar?123)
* <code><b>getUri</b> (): string</code>  
  (https://www.domain.test:8080/foo/bar?123)
* <code><b>getRequestBody</b> (): string</code>  
  (POST request body or empty string)
* <code><b>getRequestHeaders</b> (): array</code>  
  (\[headerName => headerValue, …])
* <code><b>hasHeader</b> (string $header\_name): bool</code>
* <code><b>getHeaderValue</b> (string $header\_name): ?string</code>  
    Returns a header value from the request.
    `$header_name` is case-insensitive.
    * If the header exists but its value is an empty string, `null` is returned instead.
    * If the header exists multiple times, its values will be joined with `\x00` NUL characters.
    * If the header does not exist, a [MissingAuthenticationHeaderException][Exceptions] is thrown.
* <code><b>getNonemptyHeaderValue</b> (string $header\_name): string</code>  
    Like `getHeaderValue()`, but will never return `null` or the empty string –
    it'll throw a [MissingAuthenticationHeaderException][Exceptions] instead.
