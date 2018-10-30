<?php
namespace mle86\RequestAuthentication\Tests\Helper;

use PHPUnit\Framework\AssertionFailedError;

trait AssertException
{

    /**
     * Executes the callback (without any arguments)
     * and expects it to throw an exception whose type is $exceptionClass or a subclass of that.
     *
     * @param string|string[] $exceptionClass The expected exception FQCN. Can be an array in case more than one exception class is possible.
     * @param callable $callback              The callback to invoke.
     * @param string $message                 The assertion error message.
     */
    protected function assertException($exceptionClass, callable $callback, string $message = ''): void
    {
        $ex = null;

        try {
            $callback();
        } catch (\Throwable $ex) {
            // continue
        }

        $joinedFqcn = implode('|', (array)$exceptionClass);
        $message = "Callback should have thrown a {$joinedFqcn}!" .
            (($message !== '') ? "\n" . $message : '');

        $this->assertNotNull($ex, $message);

        foreach ((array)$exceptionClass as $fqcn) {
            if (is_a($ex, $fqcn)) {
                // ok!
                return;
            }
        }

        throw new AssertionFailedError($message, 0, $ex);
    }

}