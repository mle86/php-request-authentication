<?php

namespace mle86\RequestAuthentication\Crypto\Halite;

use mle86\RequestAuthentication\Crypto\Verifier;
use mle86\RequestAuthentication\Exception\CryptoErrorException;
use mle86\RequestAuthentication\Exception\InvalidAuthenticationException;
use ParagonIE\Halite\Alerts\InvalidSignature;
use ParagonIE\Halite\Asymmetric;

/**
 * Wraps the `paragonie/halite` package and its {@see Asymmetric\Crypto::verify()} method.
 *
 * @see HaliteSigner
 */
class HaliteVerifier extends Verifier
{

    const SIGNATURE_ENCODING = HaliteSigner::SIGNATURE_ENCODING;

    private $publicKey;

    public function __construct(HaliteSigningPublicKey $publicKey)
    {
        $this->publicKey = $publicKey;
    }

    public function test(string $message, string $signature): bool
    {
        try {
            return Asymmetric\Crypto::verify(
                $message,
                $this->publicKey->getInternalKey(),
                $signature,
                self::SIGNATURE_ENCODING);

        } catch (InvalidSignature $e) {
            throw new InvalidAuthenticationException('invalid auth signature', 0, $e);
        } catch (\RangeException $e) {
            throw new CryptoErrorException('invalid auth signature', 0, $e);
        }
    }

}
