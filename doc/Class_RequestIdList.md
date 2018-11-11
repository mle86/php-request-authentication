# RequestIdList Interface

Interface for Request ID Lists.

A Request ID List
is a running append-only list of already-seen request IDs.

Re-adding an already-seen request ID
results in a [DuplicateRequestIDException][Exceptions],
interrupting request verification.

It can be used to ensure
that no two requests with the same request ID are processed,
e.g. to prevent replay attacks.

**NB:**
 It's not recommended to use the interface methods directly.
 Use the [RequestVerifier] helper class instead,
 it has a `withRequestIdList()` setter.

See “[Request IDs](Request_IDs.md)” for more information
and a usage example.

[Exceptions]: Exceptions.md
[RequestVerifier]: Class_RequestVerifier.md
[CacheRequestIdList]: Class_CacheRequestIdList.md


## Class Details

* Full interface name: <code>mle86\\RequestAuthentication\\RequestIdList\\<b>RequestIdList</b></code>
* Interface file: [src/RequestIdList/RequestIdList.php](../src/RequestIdList/RequestIdList.php)


## Implementations

* [CacheRequestIdList] class (takes a PSR-16 Cache instance)


## Methods

* <code><b>contains</b> (string $requestId): bool</code>  
    Returns true if the Request ID is already contained in the list (`put()` will fail),
    returns false if the Request ID is not yet known.

* <code><b>put</b> (string $requestId): void</code>  
    Stores one Request ID in the list.
    This only works with Request IDs which are _not yet_ contained within the list.  
    Returns if the ID has been added to the list successfully.  
    Throws a [DuplicateRequestIDException][Exceptions] if the Request ID has been seen previously.
