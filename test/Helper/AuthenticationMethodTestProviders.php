<?php
namespace mle86\RequestAuthentication\Tests\Helper;


/** @internal This trait is used by {@see AuthenticationMethodTests}. */
trait AuthenticationMethodTestProviders
{

    public function requestsFromDifferentInput(): array { return [
        [$this->buildRequest(['method'  => self::otherMethod()])],
        [$this->buildRequest(['scheme'  => self::otherScheme()])],
        [$this->buildRequest(['host'    => self::otherHost()])],
        [$this->buildRequest(['path'    => self::otherPath()])],
        [$this->buildRequest(['headers' => self::otherHeaders()])],
        [$this->buildRequest(['body'    => self::otherBody()])],
        [$this->buildRequest(['headers' => self::otherHeaders(), 'body' => self::otherBody()])],
        [$this->buildRequest([  // everything is different in this request!
            'method'  => self::otherMethod(),
            'scheme'  => self::otherScheme(),
            'host'    => self::otherHost(),
            'path'    => self::otherPath(),
            'headers' => self::otherHeaders(),
            'body'    => self::otherBody(),
        ])],
    ]; }

    public function differentClientData(): array { return [
        // Changing the client key should lead to a different signature:
        [['key' => self::sampleClientKey() . '1']],
        [['key' => substr(self::sampleClientKey(), 0, -1)]],
        [['key' => self::sampleClientKey() . "\x01"]],
        [['key' => self::otherClientKey()]],

        // We don't know for sure that the AuthenticationMethod includes the client id in the hash data,
        // so we cannot assume that a changed client id (with same client key) will always result in different output.
        // If your method implementation includes the client id in its hash data, add this case to your customDifferentClientData() provider:
#       [['id' => self::otherClientId()]],
        // ...In that case, we can also enable this special case where the client key _and_ id have been changed:
#       [['key' => self::otherClientKey(), 'id' => self::otherClientId()]],
    ]; }

    public function missingAuthenticationHeaderValues(): array { return [
        [''],
        [false],
        [null],
        [new RemoveHeaderMarker],
    ]; }

    public function invalidAuthenticationHeaderValues(): array { return [
        // No matter which AuthenticationMethod, those header values can ALWAYS be considered invalid.
        ['*'],
        ["\x00"],
        ['0'],
        ['1111111111111111111111111111111111111111111111111111111111111111'],  // looks like sha256
    ]; }

}
