<?php

namespace MadeSimple\TwoFactor\GoogleAuthenticator;

/**
 * Class Base32
 *
 * Adapted from bbars bbars/utils library for GoogleAuthenticator.
 *
 * @package MadeSimple\TwoFactor\GoogleAuthenticator
 * @link    https://github.com/bbars/utils
 */
class Base32
{
    /**
     * @var string Valid
     */
    protected static $CHARS = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567=';

    /**
     * Base32 encode $data.
     *
     * @param string $data
     *
     * @return string
     */
    public static function encode($data)
    {
        $length        = strlen($data);
        $encoded       = '';
        $remainder     = 0;
        $remainderSize = 0;

        for ($i = 0; $i < $length; $i++) {
            $byte      = ord($data[$i]);
            $remainder = ($remainder << 8) | $byte;
            $remainderSize += 8;
            while ($remainderSize > 4) {
                $remainderSize -= 5;
                $char = $remainder & (31 << $remainderSize);
                $char >>= $remainderSize;
                $encoded .= self::$CHARS[$char];
            }
        }
        if ($remainderSize > 0) {
            $remainder <<= (5 - $remainderSize);
            $char = $remainder & 31;
            $encoded .= self::$CHARS[$char];
        }

        return $encoded;
    }

    /**
     * Base32 decode $encoded.
     *
     * @param string $encoded
     *
     * @return string
     * @throws \InvalidArgumentException If $encoded contains invalid characters
     */
    public static function decode($encoded)
    {
        $encoded    = strtoupper($encoded);
        $length     = strlen($encoded);
        $buffer     = 0;
        $bufferSize = 0;
        $decoded    = '';

        for ($i = 0; $i < $length; $i++) {
            $char = $encoded[$i];
            $byte = strpos(self::$CHARS, $char);
            if ($byte === false) {
                throw new \InvalidArgumentException('Encoded string is invalid. Contains unknown char #' . ord($char));
            }
            $buffer = ($buffer << 5) | $byte;
            $bufferSize += 5;
            if ($bufferSize > 7) {
                $bufferSize -= 8;
                $byte = ($buffer & (0xff << $bufferSize)) >> $bufferSize;
                $decoded .= chr($byte);
            }
        }

        return $decoded;
    }
}