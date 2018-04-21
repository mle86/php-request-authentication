<?php
namespace mle86\RequestAuthentication\Crypto;

use mle86\RequestAuthentication\Exception\InvalidAuthenticationException;

/**
 * Can be used to verify cryptographic message signatures
 * generated by {@see Signer} classes.
 *
 * Implementations will usually have some more dependencies
 * such as a public key.
 */
abstract class Verifier
{

    /**
     * Tests whether a signature matches a message.
     *
     * @param string $message  The raw message to be tested against the signature.
     * @param string $signature  The detached signature for the message
     *                           in its original printable encoding as returned by {@see Signer::sign()}.
     * @return bool
     *   True if the signature matches the message (and the instance's other settings, such as the signer's public key),
     *   False if not.
     * @throws InvalidAuthenticationException  if the signature is invalid.
     */
    abstract public function test (string $message, string $signature): bool;

    /**
     * Like {@see test()}, but has no return value.
     * Instead of returning `false`, it will throw an {@see InvalidAuthenticationException} in case of signature mismatch.
     *
     * @param string $message  The raw message to be tested against the signature.
     * @param string $signature  The detached signature for the message.
     * @return void
     *   Returns if the signature matches.
     * @throws InvalidAuthenticationException  if the signature does not match.
     */
    final public function verify (string $message, string $signature): void {
        if (!$this->test($message, $signature)) {
            throw new InvalidAuthenticationException('signature mismatch');
        }
    }

}
