<?php

namespace Tests\Unit\GoogleAuthenticator;

use MadeSimple\TwoFactor\GoogleAuthenticator\GoogleAuthenticator;
use PHPUnit\Framework\TestCase;

class GoogleAuthenticatorTest extends TestCase
{
    /**
     * Test GoogleAuthenticator::secret throws InvalidArgumentException if length is invalid.
     *
     * @dataProvider invalidLengthDataProvider
     * @param int $length
     *
     * @expectedException \InvalidArgumentException
     * @expectedExceptionMessage Secret length must be 16 <= length <= 128
     */
    public function testSecretThrowsInvalidArgumentException($length)
    {
        GoogleAuthenticator::secret($length);
    }

    /**
     * Test GoogleAuthenticator::secret generates secrets of the given $length.
     *
     * @dataProvider validLengthDataProvider
     * @param int $length
     */
    public function testSecret($length)
    {
        $secret = GoogleAuthenticator::secret($length);

        $this->assertEquals($length, strlen($secret));
    }

    /**
     * Test GoogleAuthenticator::code generates the proper code.
     *
     * @dataProvider validSecretTimeCodeDataProvider
     * @param string $secret
     * @param int    $time
     * @param string $code
     */
    public function testCode($secret, $time, $code)
    {
        $this->assertEquals($code, GoogleAuthenticator::code($secret, 6, $time));
    }

    /**
     * Test GoogleAuthenticator::verify verifies code with no discrepancy.
     *
     * @dataProvider validSecretTimeCodeDataProvider
     * @param string $secret
     * @param int    $time
     * @param string $code
     */
    public function testVerifyNoDiscrepancy($secret, $time, $code)
    {
        $auth = new GoogleAuthenticator($secret, 6);

        $this->assertTrue($auth->verify($code, 0, $time));
    }

    /**
     * Test GoogleAuthenticator::otpAuthString throws an exception if an invalid argument is provided.
     *
     * @dataProvider invalidAccountNameDataProvider
     * @param $accountName
     * @param $secret
     * @param $issuer
     * @expectedException \InvalidArgumentException
     */
    public function testOtpAuthStringInvalidArgumentException($accountName, $secret, $issuer = null)
    {
        GoogleAuthenticator::otpAuthString($accountName, $secret, $issuer);
    }


    /**
     * Test GoogleAuthenticator::otpAuthString generates valid string.
     *
     * @dataProvider validAccountNameDataProvider
     * @param $otpAuthString
     * @param $accountName
     * @param $secret
     * @param $issuer
     */
    public function testOtpAuthString($otpAuthString, $accountName, $secret, $issuer = null)
    {
        $generated = GoogleAuthenticator::otpAuthString($accountName, $secret, $issuer);

        $this->assertEquals($otpAuthString, $generated);
    }



    public function invalidLengthDataProvider()
    {
        return [[15], [129]];
    }
    public function validLengthDataProvider()
    {
        return [[16], [37], [64], [128]];
    }
    public function validSecretTimeCodeDataProvider()
    {
        return [
            ['SECRETKEYSECRETKEY', 49637965, 744102],
            ['SECRETKEYSECRETKEY', 49637966, '716156'],
            ['ANOTHERSECRETKEYVALUE', 49637973, 936461],
            ['ANOTHERSECRETKEYVALUE', 49637974, '852137'],
        ];
    }
    public function invalidAccountNameDataProvider()
    {
        return [
            ['invalid:accountName', 'secret'],
            ['', 'secret'],
            ['example', ''],
            ['example', 'secret', 'invalid:issuer'],
            ['example', 'secret', ''],
        ];
    }
    public function validAccountNameDataProvider()
    {
        return [
            ['otpauth://totp/accountName?secret=SECRET', 'accountName', 'SECRET'],
            ['otpauth://totp/ISSUER:accountName?secret=SECRET&issuer=ISSUER', 'accountName', 'SECRET', 'ISSUER'],
        ];
    }
}