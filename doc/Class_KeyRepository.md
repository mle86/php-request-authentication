# KeyRepository Abstract Base Class

A key repository can look up client API secrets
by their client identification.

They are needed by <code>[AuthenticationMethod]::verify()</code>
to look up the correct client API secret
for the client identification string
contained within the request.

A basic implementation is the [ArrayRepository] which simply wraps a <code>[clientId => clientSecret, …]</code> array.
More complex implementations may look up the client secret in a database or some other external system.

[Exceptions]: Exceptions.md
[AuthenticationMethod]: Class_AuthenticationMethod.md
[RequestAuthenticator]: Class_RequestAuthenticator.md
[RequestVerifier]: Class_RequestVerifier.md


## Class Details

* Full class name: <code>mle86\\RequestAuthentication\\KeyRepository\\<b>KeyRepository</b></code>
* Class file: [src/KeyRepository/KeyRepository.php](../src/KeyRepository/KeyRepository.php)


## Methods

The class implements the native [`ArrayAccess`](http://php.net/manual/class.arrayaccess.php) interface:

* <code>offsetExists ($client\_id): bool</code>
* <code>offsetGet ($client\_id): string</code>
* <code>offsetUnset ($client\_id): void</code> – always throws an [ImmutableDataException][Exceptions].
* <code>offsetSet ($client\_id, $value): void</code> – always throws an [ImmutableDataException][Exceptions].

