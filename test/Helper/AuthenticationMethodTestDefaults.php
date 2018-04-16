<?php
namespace mle86\RequestAuthentication\Tests\Helper;

use GuzzleHttp;


/** @internal This trait is used by {@see AuthenticationMethodTests}. */
trait AuthenticationMethodTestDefaults
{

    protected static function sampleClientId(): string { return 'C1'; }
    protected static function otherClientId(): string  { return 'C11'; }

    protected static function sampleClientKey(): string { return 'h8sLmTPFgQ'; }
    protected static function otherClientKey(): string  { return 'SF8aoIlsBz'; }

    protected static function sampleMethod(): string { return 'POST'; }
    protected static function otherMethod(): string  { return 'PATCH'; }

    protected static function sampleScheme(): string { return 'http'; }
    protected static function otherScheme(): string  { return 'https'; }

    protected static function sampleHost(): string { return 'test.localhost'; }
    protected static function otherHost(): string  { return 'test2.localhost'; }

    protected static function samplePath(): string { return '/info.php?111=222'; }
    protected static function otherPath(): string  { return '/info.php?444=555'; }

    protected static function sampleBody(): string { return http_build_query(['k1' => 'V1', 'k2' => 'V2']); }
    protected static function otherBody(): string  { return GuzzleHttp\json_encode(['k1' => 'V1', 'k2' => 'V2']); }

    protected static function sampleHeaders(): array { return ['Content-Type' => 'application/x-www-form-urlencoded', 'Accept' => '*/*']; }
    protected static function otherHeaders(): array  { return ['Content-Type' => 'application/json',                  'Accept' => 'text/plain']; }

}
