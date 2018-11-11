# MethodStack Composite Class

Contains a list of other [AuthenticationMethod] instances
which will be used to verify requests.

This is useful if your API has several acceptable authentication methods
and you want to support them all with a single `verify()` call.

This class itself implements the [AuthenticationMethod] interface,
so it can be used in place of single instances everywhere.

Instances can be used for authentication:
the `authenticate()` call will always be delegated
to the _first instance_ in the stack.

[Exceptions]: Exceptions.md
[KeyRepository]: Class_KeyRepository.md
[AuthenticationMethod]: Class_AuthenticationMethod.md
[RequestAuthenticator]: Class_RequestAuthenticator.md
[RequestVerifier]: Class_RequestVerifier.md
[RequestInfo]: Class_RequestInfo.md


## Class Details

* Full class name: <code>mle86\\RequestAuthentication\\<b>MethodStack</b></code>
* Class file: [src/MethodStack.php](../src/MethodStack.php)


## Constructor

* <code><b>\_\_construct</b> (iterable $methods)</code>  
    Takes a list of [AuthenticationMethod] instances or class names.
    Class names will be instantiated (which requires them to have a
    public constructor without required arguments).  
    The list may _not_ be empty.


## Method Overrides

* <code><b>authenticate</b> ([RequestInfo] $request, string $apiClientId, string $apiClientKey): array</code>  
    Proxy for <code>[AuthenticationMethod]::authenticate()</code>
    of the _first method_ in the stack.

* <code><b>verify</b> ([RequestInfo] $request, [KeyRepository] $keys): void</code>  
    Calls <code>[AuthenticationMethod]::verify()</code>
    on all method instances in the stack (in their original order)
    until one of them verifies the request.  
    All [InvalidAuthenticationException][Exceptions]s/[MissingAuthenticationHeaderException][Exceptions]s/[CryptoErrorException][Exceptions]s
    are ignored.  
    If none of the method instances accept the input,
    an [InvalidAuthenticationException][Exceptions] is thrown.

* <code><b>getClientId</b> ([RequestInfo] $request): string</code>  
    Calls <code>[AuthenticationMethod]::verify()</code>
    on all method instances in the stack (in their original order)
    until one of them returns the client ID.  
    All [InvalidAuthenticationException][Exceptions]s/[MissingAuthenticationHeaderException][Exceptions]s/[CryptoErrorException][Exceptions]s
    are ignored.  
    If none of the method instances accept the input,
    an [InvalidAuthenticationException][Exceptions] is thrown.  
    **⚠ NB:**
    It is only safe to call this method if `verify()` has been called before _and_
    if the last successful `verify()` call had the same request argument.
    Otherwise, the wrong method may be chosen which might return an incorrect client id.
    The [RequestVerifier] helper class does this correctly.

## Extra Methods

* <code><b>getMethods</b> (): array</code>  
    Returns the contained [AuthenticationMethod] instances in their original order.
