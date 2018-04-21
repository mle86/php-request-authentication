<?php
namespace mle86\RequestAuthentication\Crypto;


/**
 * Common interface for public keys suitable for signature verification by a {@see Verifer} implementation.
 *
 * The "encoded form" accepted by the constructor and returned by {@see getEncodedForm}
 * should consist of printable, non-whitespace characters only,
 * preferrably from a websafe charset.
 */
interface SigningPublicKey
{

    public function __construct (string $encoded_public_key);

    public function getEncodedForm (): string;

}
