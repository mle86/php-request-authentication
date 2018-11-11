# Request IDs

Some authentication methods
always add a random _Request ID_
to their authentication headers.

They also expect to see a Request ID header
in inbound requests.

* The [PublicKeyMethod] uses the `X-Request-ID` header.
* The [DefaultAuthenticationMethod] uses the `X-Request-ID` header.

All [AuthenticationMethod]s using Request IDs
implement the [UsesRequestID] interface
which offers the <code>getRequestId(RequestInfo): string</code> method
so both the client side and the server side
can easily log the used/received request id.

These Request IDs
may be useful for logging
both the client side and the server side.

[Exceptions]: Exceptions.md
[KeyRepository]: Class_KeyRepository.md
[AuthenticationMethod]: Class_AuthenticationMethod.md
[DefaultAuthenticationMethod]: Class_DefaultAuthenticationMethod.md
[PublicKeyMethod]: Class_PublicKeyMethod.md
[RequestAuthenticator]: Class_RequestAuthenticator.md
[RequestVerifier]: Class_RequestVerifier.md
[RequestInfo]: Class_RequestInfo.md
[RequestIdList]: Class_RequestIdList.md
[UsesRequestID]: ../src/AuthenticationMethod/Feature/UsesRequestID.php
[HexRequestIDTrait]: ../src/AuthenticationMethod/Feature/HexRequestIDTrait.php


## Validation and Default Value

The [AuthenticationMethod]s mentioned above
all expect the Request ID header
to contain a hexadecimal string of 32…100 characters.

When authenticating outbound requests,
they'll add a Request ID header of 64 random hex characters.
(If the outbound request already contains that header
it won't be overwritten so it's possible to set the Request ID manually.)

These validation rules and default value generation rules
are defined in the [HexRequestIDTrait] trait.
Implementors of other AuthenticationMethod classes
may choose a different format (e.g. UUIDs)
so there's no library-wide guarantees about Request ID format
except that they're always some non-empty string.


## Request Uniqueness

When implementing an API
it can be important to ensure _Request Uniqueness._

Using the [RequestVerifier] on inbound requests
guarantees that all requests
have valid authentication headers
but it may still be possible for an attacker
to replay previous requests,
causing unwanted repeated effects.

Request IDs can easily prevent this.

To this end,
the [AuthenticationMethod]s mentioned above
always add a random Request ID
to outbound requests
and they always verify that header's existence and format
in inbound requests.
But they do not yet check that the Request IDs
are actually unique.

This is where the [RequestIdList] classes
come into the picture:
A RequestIDList is a
**running append-only list of already-seen Request IDs.**
Re-adding an already-seen Request ID
results in a [DuplicateRequestIDException][Exceptions],
interrupting request verification.


### RequestIdList Usage

The easiest way to use a [RequestIdList]
is to use the [RequestVerifier] helper class,
it has an extra setter to accept a RequestIdList instance:

```php
<?php

use mle86\RequestAuthentication\RequestVerifier;
use mle86\RequestAuthentication\RequestIdList\CacheRequestIdList;

# $authenticationMethod = ...
# $keyRepository = ...
# $myCache = PSR-16...

$requestIdList = new CacheRequestIdList($myCache, 'PREFIX_');

$verifier = (new RequestVerifier($authenticationMethod, $keyRepository))
    ->withRequestIdList($requestIdList);

$clientId = $verifier->verifyGlobals();
// After calling RequestVerifier->withRequestIdList(),
// all verify…() methods check the Request ID.
// Now we can be sure that the global request
// contained a truly unique request ID
// (if the $authenticationMethod is one of the UsesRequestID implementations).
```
