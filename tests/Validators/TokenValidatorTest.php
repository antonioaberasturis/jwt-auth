<?php

/*
 * This file is part of jwt-auth.
 *
 * (c) Sean Anton <tymon148@gmail.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Anton\JWTAuth\Test\Validators;

use Anton\JWTAuth\Test\AbstractTestCase;
use Anton\JWTAuth\Validators\TokenValidator;

class TokenValidatorTest extends AbstractTestCase
{
    /**
     * @var \Anton\JWTAuth\Validators\TokenValidator
     */
    protected $validator;

    public function setUp()
    {
        parent::setUp();

        $this->validator = new TokenValidator();
    }

    /** @test */
    public function it_should_return_true_when_providing_a_well_formed_token()
    {
        $this->assertTrue($this->validator->isValid('one.two.three'));
    }

    public function dataProviderMalformedTokens()
    {
        return [
            ['one.two.'],
            ['.two.'],
            ['.two.three'],
            ['one..three'],
            ['..'],
            [' . . '],
            [' one . two . three '],
        ];
    }

    /**
     * @test
     * @dataProvider \Anton\JWTAuth\Test\Validators\TokenValidatorTest::dataProviderMalformedTokens
     *
     * @param string $token
     */
    public function it_should_return_false_when_providing_a_malformed_token($token)
    {
        $this->assertFalse($this->validator->isValid($token));
    }

    /**
     * @test
     * @dataProvider \Anton\JWTAuth\Test\Validators\TokenValidatorTest::dataProviderMalformedTokens
     *
     * @param string $token
     * @expectedException \Anton\JWTAuth\Exceptions\TokenInvalidException
     * @expectedExceptionMessage Malformed token
     */
    public function it_should_throw_an_exception_when_providing_a_malformed_token($token)
    {
        $this->validator->check($token);
    }

    public function dataProviderTokensWithWrongSegmentsNumber()
    {
        return [
            ['one.two'],
            ['one.two.three.four'],
            ['one.two.three.four.five'],
        ];
    }

    /**
     * @test
     * @dataProvider \Anton\JWTAuth\Test\Validators\TokenValidatorTest::dataProviderTokensWithWrongSegmentsNumber
     *
     * @param string $token
     */
    public function it_should_return_false_when_providing_a_token_with_wrong_segments_number($token)
    {
        $this->assertFalse($this->validator->isValid($token));
    }

    /**
     * @test
     * @dataProvider \Anton\JWTAuth\Test\Validators\TokenValidatorTest::dataProviderTokensWithWrongSegmentsNumber
     *
     * @param string $token
     * @expectedException \Anton\JWTAuth\Exceptions\TokenInvalidException
     * @expectedExceptionMessage Wrong number of segments
     */
    public function it_should_throw_an_exception_when_providing_a_malformed_token_with_wrong_segments_number($token)
    {
        $this->validator->check($token);
    }
}
