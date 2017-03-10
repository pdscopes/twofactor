<?php

namespace Tests\Unit\GoogleAuthenticator;

use MadeSimple\TwoFactor\GoogleAuthenticator\Base32;
use PHPUnit\Framework\TestCase;

class Base32Test extends TestCase
{
    /**
     * Test encoding/decoding string.
     */
    public function testEncodeDecode()
    {
        $original = 'This is a test string to be encoded';

        $this->assertEquals($original, Base32::decode(Base32::encode($original)));
    }

    /**
     * @expectedException \InvalidArgumentException
     * @expectedExceptionMessage Encoded string is invalid. Contains unknown char #
     */
    public function testDecodeThrowsInvalidArgumentException()
    {
        Base32::decode('InvalidEncoded0987');
    }
}