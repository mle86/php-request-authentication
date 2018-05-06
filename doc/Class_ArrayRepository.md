# ArrayRepository Class

A client key repository based on a simple PHP array.

See [KeyRepository] interface.

* The constructor's input array must be in the form
  `[clientId => clientKey, …]`.

* Client IDs must be non-zero integers or non-empty strings.
* Client keys must be non-empty strings.

[Exceptions]: Exceptions.md
[KeyRepository]: Class_KeyRepository.md
[AuthenticationMethod]: Class_AuthenticationMethod.md
[RequestAuthenticator]: Class_RequestAuthenticator.md
[RequestVerifier]: Class_RequestVerifier.md
[RequestInfo]: Class_RequestInfo.md


## Class Details

* Full class name: <code>mle86\\RequestAuthentication\\KeyRepository\\<b>ArrayRepository</b></code>
* Class file: [src/KeyRepository/ArrayRepository.php](../src/KeyRepository/ArrayRepository.php)


## Constructor

* <code><b>\_\_construct</b> (array $keys)</code>

