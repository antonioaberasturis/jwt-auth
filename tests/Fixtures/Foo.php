<?php

/*
 * This file is part of jwt-auth.
 *
 * (c) Sean Anton <tymon148@gmail.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Anton\JWTAuth\Test\Fixtures;

use Anton\JWTAuth\Claims\Claim;

class Foo extends Claim
{
    /**
     * {@inheritdoc}
     */
    protected $name = 'foo';
}
