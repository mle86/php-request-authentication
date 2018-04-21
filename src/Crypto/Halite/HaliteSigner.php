<?php
namespace mle86\RequestAuthentication\Crypto\Halite;

use mle86\RequestAuthentication\Crypto\Signer;
use ParagonIE\Halite\Asymmetric;
use ParagonIE\Halite\Halite;

/**
 * Wraps the `paragonie/halite` package and its {@see Asymmetric\Crypto::sign()} method.
 *
 * @see HaliteVerifier
 */
class HaliteSigner
    implements Signer
{

    const SIGNATURE_ENCODING = Halite::ENCODE_BASE64URLSAFE;

    private $private_key;

    public function __construct(HaliteSigningPrivateKey $private_key)
    {
        $this->private_key = $private_key;
    }

    public function sign(string $message): string
    {
        return Asymmetric\Crypto::sign(
            $message,
            $this->private_key->getInternalKey(),
            self::SIGNATURE_ENCODING);
    }

}
