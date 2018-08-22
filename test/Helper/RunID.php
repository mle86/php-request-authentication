<?php

namespace mle86\RequestAuthentication\Tests\Helper;

/**
 * Adds the {@see runId()} method.
 * It returns a random hex ID which is different for every test class and for every test run.
 */
trait RunID
{

    private static $runId;

    protected static function runId(): string
    {
        return (static::$runId ?? (static::$runId =
                hash('sha256', random_bytes(6))
            ));
    }


}
