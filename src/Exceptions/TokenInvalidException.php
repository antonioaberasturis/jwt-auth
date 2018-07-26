<?php

/*
 * This file is part of jwt-auth.
 *
 * (c) Sean Anton <Anton148@gmail.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Anton\JWTAuth\Exceptions;

class TokenInvalidException extends JWTException
{
    /**
     * @var int
     */
    protected $statusCode = 400;
}
