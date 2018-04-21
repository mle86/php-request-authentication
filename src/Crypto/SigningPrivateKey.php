<?php
namespace mle86\RequestAuthentication\Crypto;


/**
 * Common interface for private keys suitable for signature creation by a {@see Signer} implementation.
 *
 * The "encoded form" accepted by the constructor and returned by {@see getEncodedForm}
 * should consist of printable, non-whitespace characters only,
 * preferrably from a websafe charset.
 */
interface SigningPrivateKey
{

    public function __construct (string $encoded_private_key);

    public function getEncodedForm (): string;

}
