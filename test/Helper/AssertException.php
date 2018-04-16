<?php
namespace mle86\RequestAuthentication\Tests\Helper;

use PHPUnit\Framework\AssertionFailedError;

trait AssertException
{

    /**
     * Executes the callback (without any arguments)
     * and expects it to throw an exception whose type is $exception_class or a subclass of that.
     *
     * @param string|string[] $exception_class  The expected exception FQCN. Can be an array in case more than one exception class is possible.
     * @param callable $callback  The callback to invoke.
     * @param string $message  The assertion error message.
     */
    protected function assertException($exception_class, callable $callback, string $message = ''): void
    {
        $ex = null;

        try {
            $callback();
        } catch (\Throwable $ex) {
            // continue
        }

        $joined_fqcn = implode('|', (array)$exception_class);
        $message = "Callback should have thrown a {$joined_fqcn}!" .
            (($message !== '') ? "\n" . $message : '');

        $this->assertNotNull($ex, $message);

        foreach ((array)$exception_class as $fqcn) {
            if (is_a($ex, $fqcn)) {
                // ok!
                return;
            }
        }

        throw new AssertionFailedError($message, 0, $ex);
    }

}