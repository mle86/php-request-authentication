<?php
namespace mle86\RequestAuthentication\Crypto\Halite;

use mle86\RequestAuthentication\Crypto\SigningPrivateKey;
use mle86\RequestAuthentication\Exception\CryptoErrorException;
use ParagonIE\Halite\Alerts\InvalidKey;
use ParagonIE\Halite\Asymmetric\SignatureSecretKey;
use ParagonIE\Halite\HiddenString;
use ParagonIE\Halite\KeyFactory;
use ParagonIE\Halite\SignatureKeyPair;
use ParagonIE\Halite\Util;
use Sodium;

/**
 * Wraps the `paragonie/halite` package's {@see SignaturePrivateKey} class.
 *
 * This class exists mostly for some convenience methods
 * and to make sure the keys are always stored in a printable string encoding.
 *
 * @see HaliteSigner  to use these key instances for calculating cryptographic signatures which can later be verified by {@see HaliteVerifier}.
 */
class HaliteSigningPrivateKey
    implements SigningPrivateKey
{

    use HaliteKeyEncoding;

    private $encoded;
    private $key;

    /**
     * Creates a new instance from an encoded private key.
     *
     * @param string $encoded_private_key The private key.
     * @throws CryptoErrorException  if the private key is invalid.
     */
    public function __construct(string $encoded_private_key)
    {
        $this->encoded = new HiddenString($encoded_private_key);

        $raw_private_key = self::decodeKey($encoded_private_key);

        try {
            $this->key = new SignatureSecretKey(
                new HiddenString($raw_private_key, true, true)
            );
        } catch (InvalidKey $e) {
            throw new CryptoErrorException('invalid private key', 0, $e);
        } finally {
            Sodium\memzero($raw_private_key);
        }
    }

    /**
     * Creates a new instance from a raw, unencoded private key.
     *
     * @param string $raw_private_key The unencoded private key.
     * @return self
     * @throws CryptoErrorException  if the private key is invalid.
     */
    public static function fromRawKey(string $raw_private_key): self
    {
        return new self (self::encodeKey($raw_private_key));
    }

    /**
     * Creates a new instance from a Halite {@see SignatureKeyPair} instance.
     *
     * @param SignatureKeyPair $pair
     * @return self
     */
    public static function fromKeyPair(SignatureKeyPair $pair): self
    {
        return self::fromRawKey($pair->getSecretKey()->getRawKeyMaterial());
    }

    /**
     * Generates a new random key pair.
     *
     * @see HaliteSigningPublicKey::fromPrivateKey()  to obtain the corresponding public key.
     *
     * @return self
     */
    public static function generate(): self
    {
        $keyPair = KeyFactory::generateSignatureKeyPair();
        try {
            return self::fromKeyPair($keyPair);
        } finally {
            Sodium\memzero($keyPair);
        }
    }

    public function getEncodedForm(): string
    {
        return Util::safeStrcpy($this->encoded->getString());
    }

    public function getInternalKey(): SignatureSecretKey
    {
        return $this->key;
    }

}
