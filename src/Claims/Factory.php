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

class Factory
{
    /**
     * @var array
     */
    private static $classMap = [
        'aud' => 'Anton\JWTAuth\Claims\Audience',
        'exp' => 'Anton\JWTAuth\Claims\Expiration',
        'iat' => 'Anton\JWTAuth\Claims\IssuedAt',
        'iss' => 'Anton\JWTAuth\Claims\Issuer',
        'jti' => 'Anton\JWTAuth\Claims\JwtId',
        'nbf' => 'Anton\JWTAuth\Claims\NotBefore',
        'sub' => 'Anton\JWTAuth\Claims\Subject',
    ];

    /**
     * Get the instance of the claim when passing the name and value.
     *
     * @param string $name
     * @param mixed  $value
     *
     * @return \Anton\JWTAuth\Claims\Claim
     */
    public function get($name, $value)
    {
        if ($this->has($name)) {
            return new self::$classMap[$name]($value);
        }

        return new Custom($name, $value);
    }

    /**
     * Check whether the claim exists.
     *
     * @param string $name
     *
     * @return bool
     */
    public function has($name)
    {
        return array_key_exists($name, self::$classMap);
    }
}
