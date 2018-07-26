<?php

/*
 * This file is part of jwt-auth.
 *
 * (c) Sean Anton <Anton148@gmail.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Anton\JWTAuth\Claims;

class Issuer extends Claim
{
    /**
     * The claim name.
     *
     * @var string
     */
    protected $name = 'iss';
}
