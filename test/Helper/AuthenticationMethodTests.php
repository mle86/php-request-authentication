<?php
namespace mle86\RequestAuthentication\Tests\Helper;

use mle86\RequestAuthentication\AuthenticationMethod\AuthenticationMethod;

trait AuthenticationMethodTests
{

    abstract public function testGetInstance(): AuthenticationMethod;

    # TODO

}
