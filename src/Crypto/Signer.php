<?php
namespace mle86\RequestAuthentication\Crypto;


/**
 * Can be used to sign messages cryptographically.
 *
 * Implementations will usually have some more dependencies
 * such as a {@see SigningPrivateKey} key used for signing.
 *
 * @see Verifier implementations to verify the signatures this class generates.
 */
interface Signer
{

    /**
     * @param string $message  The raw message to sign.
     * @return string  The detached signature for the message
     *                 in a printable, whitespace-free encoding
     *                 accepted by {@see Verifier::test()}.
     */
    public function sign (string $message): string;

}
