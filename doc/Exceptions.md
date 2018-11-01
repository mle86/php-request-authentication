# Exception Classes

[Exceptions]: Exceptions.md
[KeyRepository]: Class_KeyRepository.md
[RequestIdList]: Class_RequestIdList.md
[AuthenticationMethod]: Class_AuthenticationMethod.md
[RequestAuthenticator]: Class_RequestAuthenticator.md
[RequestVerifier]: Class_RequestVerifier.md
[RequestInfo]: Class_RequestInfo.md

All custom exceptions live in the `mle86\RequestAuthentication\Exception\` namespace.


* **Base interface:** `RequestAuthenticationException`  
    Implemented by all exception classes in this library.

* `CryptoErrorException`  
    Thrown by [AuthenticationMethod] implementations
    if a low-level cryptographic function fails unexpectedly.  
    (If it was a hashing function such as `hash_hmac`,
     the more specific `HashErrorException` is thrown instead.)

* `HashErrorException` (`extends CryptoErrorException`)  
    Thrown by [AuthenticationMethod] implementations
    if a low-level hashing function fails unexpectedly.

* `ImmutableDataException`  
    Thrown in case of a writing data access to an immutable structure,
    e.g. trying to alter the values stored in a [KeyRepository].

* `InvalidArgumentException`  
    Thrown in case of invalid input arguments,
    same as the built-in `\InvalidArgumentException`.

* `InvalidAuthenticationException`  
    Thrown by <code>[AuthenticationMethod]::verify()</code>
    if the input request contains incorrect or malformed request authentication data.

* `MissingAuthenticationHeaderException`  
    Thrown by <code>[AuthenticationMethod]::verify()</code>
    and by [RequestInfo]'s header getters
    in case of a missing or empty header value
    that should be present and non-empty.

* `UnknownClientIdException`  
    Thrown by [KeyRepository] implementations
    in case of an unknown client ID.

* `DuplicateRequestIDException`  
    Thrown by [RequestIdList] implementations
    in case of a repeated request ID.

* `RepositorySourceException`  
    Thrown by [KeyRepository] implementations
    if their key source is faulty --
    for example if the key file is malformed or does not exist.
