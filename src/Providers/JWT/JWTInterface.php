<?php

/*
 * This file is part of jwt-auth.
 *
 * (c) Sean Anton <Anton148@gmail.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Anton\JWTAuth\Providers\JWT;

interface JWTInterface
{
    /**
     * @param array $payload
     *
     * @return string
     */
    public function encode(array $payload);

    /**
     * @param string $token
     *
     * @return array
     */
    public function decode($token);
}
