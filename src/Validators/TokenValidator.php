<?php

/*
 * This file is part of jwt-auth.
 *
 * (c) Sean Anton <Anton148@gmail.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Anton\JWTAuth\Validators;

use Anton\JWTAuth\Exceptions\TokenInvalidException;

class TokenValidator extends AbstractValidator
{
    /**
     * Check the structure of the token.
     *
     * @param string $value
     */
    public function check($value)
    {
        $this->validateStructure($value);
    }

    /**
     * @param string $token
     *
     * @throws \Anton\JWTAuth\Exceptions\TokenInvalidException
     *
     * @return bool
     */
    protected function validateStructure($token)
    {
        if (count(explode('.', $token)) !== 3) {
            throw new TokenInvalidException('Wrong number of segments');
        }

        return true;
    }
}
