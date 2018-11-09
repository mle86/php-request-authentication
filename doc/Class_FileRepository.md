# FileRepository Class

A client key repository based on a `htpasswd`-style file.

See [KeyRepository] interface.

The constructor takes a filename
and ensures it's not a directory's name.

The constructor does however not check the filename for existence, readability, or format.
This is done once on the first actual usage of the repository (`offsetExists`/`offsetGet`).
If you want to force these checks and the file read early, call the `forceRead()` method.

The file will _not_ be re-read on multiple `offsetGet` calls.

The expected file format is that of htpasswd files:
 - One <code><i>clientId</i>:<i>clientKey</i></code> pair per line.
 - clientId must be non-empty and cannot contain colons.
 - clientKey must be non-empty.
 - Leading and trailing whitespace will be removed.
 - Empty lines, whitespace-only lines and lines starting with a "`#`" will be ignored.

Real htpasswd files usually contain password hashes instead of plaintext passwords,
making them useless for our [BasicAuthenticationMethod]
(which works with plaintext client keys only).
Use the [BasicHashAuthenticationMethod] instead,
it understands most hash methods traditionally used in htpasswd files.

You may of course also store public keys in a htpasswd-style key repository files
to use with a class like [PublicKeyMethod].

[Exceptions]: Exceptions.md
[KeyRepository]: Class_KeyRepository.md
[AuthenticationMethod]: Class_AuthenticationMethod.md
[RequestAuthenticator]: Class_RequestAuthenticator.md
[RequestVerifier]: Class_RequestVerifier.md
[RequestInfo]: Class_RequestInfo.md
[PublicKeyMethod]: Class_PublicKeyMethod.md
[BasicAuthenticationMethod]: Class_BasicAuthenticationMethod.md
[BasicHashAuthenticationMethod]: Class_BasicHashAuthenticationMethod.md


## Class Details

* Full class name: <code>mle86\\RequestAuthentication\\KeyRepository\\<b>FileRepository</b></code>
* Class file: [src/KeyRepository/ArrayRepository.php](../src/KeyRepository/FileRepository.php)


## Constructor

* <code><b>\_\_construct</b> (string $filename)</code>


## Other Methods

* <code><b>forceRead</b> (): self</code>  
    Forces the source file to be read immediately.  
    (This only has an effect once and only prior to the first `offsetExists`/`offsetGet` call.)
