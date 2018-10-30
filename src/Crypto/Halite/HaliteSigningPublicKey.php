<?php

namespace mle86\RequestAuthentication\Crypto\Halite;

use mle86\RequestAuthentication\Crypto\SigningPublicKey;
use mle86\RequestAuthentication\Exception\CryptoErrorException;
use ParagonIE\Halite\Alerts\InvalidKey;
use ParagonIE\Halite\Asymmetric\SignaturePublicKey;
use ParagonIE\Halite\HiddenString;
use ParagonIE\Halite\SignatureKeyPair;
use Sodium;

/**
 * Wraps the `paragonie/halite` package's {@see SignaturePublicKey} class.
 *
 * This class exists mostly for some convenience methods
 * and to make sure the keys are always stored in a printable string encoding.
 */
class HaliteSigningPublicKey implements SigningPublicKey
{
    use HaliteKeyEncoding;

    private $encoded;
    private $key;

    /**
     * Creates a new instance from an encoded public key.
     *
     * @param string $encoded_public_key The public key.
     * @throws CryptoErrorException  if the public key is invalid.
     */
    public function __construct(string $encoded_public_key)
    {
        $this->encoded = $encoded_public_key;

        $raw_public_key = self::decodeKey($encoded_public_key);

        try {
            $this->key = new SignaturePublicKey(
                new HiddenString($raw_public_key, true, true)
            );
        } catch (InvalidKey $e) {
            throw new CryptoErrorException('invalid public key', 0, $e);
        } finally {
            Sodium\memzero($raw_public_key);
        }
    }

    /**
     * Creates a new instance from a raw, unencoded public key.
     *
     * @param string $raw_public_key The unencoded public key.
     * @return self
     * @throws CryptoErrorException  if the public key is invalid.
     */
    public static function fromRawKey(string $raw_public_key): self
    {
        return new self(self::encodeKey($raw_public_key));
    }

    /**
     * Creates a new instance from a Halite {@see SignatureKeyPair} instance.
     *
     * @param SignatureKeyPair $pair
     * @return self
     */
    public static function fromKeyPair(SignatureKeyPair $pair): self
    {
        return self::fromRawKey($pair->getPublicKey()->getRawKeyMaterial());
    }

    /**
     * Creates a new instance from an existing private key.
     *
     * @param HaliteSigningPrivateKey $private_key The private key to derive the new public key from.
     * @return self
     */
    public static function fromPrivateKey(HaliteSigningPrivateKey $private_key): self
    {
        return self::fromRawKey($private_key->getInternalKey()->derivePublicKey()->getRawKeyMaterial());
    }


    public function getEncodedForm(): string
    {
        return $this->encoded;
    }

    public function getInternalKey(): SignaturePublicKey
    {
        return $this->key;
    }

}
