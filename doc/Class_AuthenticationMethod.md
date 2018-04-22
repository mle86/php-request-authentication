# AuthenticationMethod Interface

Authentication method used to sign or to verify requests.

All implementation have two use cases:

 - **Authentication:**
   Using the `authenticate()` method,
   outbound requests can be authenticated.
   The method calculates the authentication token string
   and returns it as an additional header to add to the request before sending it.

 - **Verification:**
   Using the `verify()` method,
   an inbound request's authentication token
   can be tested against the rest of the request data (including the client ID)
   and the locally-known list of acceptable client IDs and their API secrets.

There's also a `getClientId()` method that just extracts the API client identification from a request
in case you need it for authorization checking/rate limiting/logging.

[Exceptions]: Exceptions.md
[AuthenticationMethod]: Class_AuthenticationMethod.md
[RequestAuthenticator]: Class_RequestAuthenticator.md
[RequestVerifier]: Class_RequestVerifier.md
[RequestInfo]: Class_RequestInfo.md


## Class Details

* Full interface name: <code>mle86\\RequestAuthentication\\AuthenticationMethod\\<b>AuthenticationMethod</b></code>.
* Class file: [src/AuthenticationMethod/AuthenticationMethod.php](../src/AuthenticationMethod/AuthenticationMethod.php)


## Methods

* <code><b>authenticate</b> ([RequestInfo] $request, string $api\_client\_id, string $api\_secret\_key): array</code>  
    Calculates the authentication data for one request
    based on its headers, http method/host/uri, and request body.  
	Returns an array of HTTP headers that must be added to the request before sending it:
	  `[headerName => headerValue, …]`  
	Throws a [CryptoErrorException][Exceptions] if there was a problem with a low-level cryptographic function.
	* `$api_client_id`: The API client's identification which will be included in the output headers.
	* `$api_secret_key`: The client's secret key used to calculate the authentication token.

* <code><b>verify</b> ([RequestInfo] $request, [KeyRepository] $keys): void</code>  
	Verifies one request's authentication token.  
    This method extracts the client identification string from the request (using `getClientId()`),
    gets that client's key from the [KeyRepository],
    and verifies the request's authentication token
    against that key and the request data.  
	Throws a [MissingAuthenticationHeaderException][Exceptions] on missing or empty authentication header(s).  
	Throws a [InvalidAuthenticationException][Exceptions] on incorrect authentication header(s).  
	Throws a [CryptoErrorException][Exceptions] if there was a problem with a low-level cryptographic function.

* <code><b>getClientId</b> ([RequestInfo] $request): string</code>  
	Extracts the API client identification from an inbound request.  
	NB: This method does NOT `verify()` the request, it simply extracts the client identification.
	(The only validation it does is ensuring that the client identification header exists and is non-empty.)
