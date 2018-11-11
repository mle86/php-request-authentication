# KeyRepository Abstract Base Class

A key repository can look up client API keys/secrets
by their client identification.

They are needed by <code>[AuthenticationMethod]::verify()</code>
to look up the correct client API key/secret
for the client identification string
contained within the request.

A basic implementation is the [ArrayRepository] which simply wraps a <code>[clientId => clientSecret, …]</code> array.
Another is the [FileRepository] which reads a `.htpasswd`-style file.
More complex implementations may look up the client secret in a database or some other external system.

[Exceptions]: Exceptions.md
[AuthenticationMethod]: Class_AuthenticationMethod.md
[RequestAuthenticator]: Class_RequestAuthenticator.md
[RequestVerifier]: Class_RequestVerifier.md
[ArrayRepository]: Class_ArrayRepository.md
[FileRepository]: Class_FileRepository.md
[ArrayAccess]: https://php.net/manual/class.arrayaccess.php


## Class Details

* Full class name: <code>mle86\\RequestAuthentication\\KeyRepository\\<b>KeyRepository</b></code>
* Class file: [src/KeyRepository/KeyRepository.php](../src/KeyRepository/KeyRepository.php)
* Inheritance:
    * implements \\[ArrayAccess]


## Methods

The class implements the native [ArrayAccess] interface:

* <code>offsetExists ($clientId): bool</code>
* <code>offsetGet ($clientId): string</code> – Returns the client key/secret/hash/password that belongs to one client ID.
    (This might be a symmetric key or hash, a public key, or a plaintext password depending on the [AuthenticationMethod] used.)
    Throws an [UnknownClientIdException][Exceptions] if the client ID is unknown in this repository.
* <code>offsetUnset ($clientId): void</code> – always throws an [ImmutableDataException][Exceptions].
* <code>offsetSet ($clientId, $value): void</code> – always throws an [ImmutableDataException][Exceptions].

