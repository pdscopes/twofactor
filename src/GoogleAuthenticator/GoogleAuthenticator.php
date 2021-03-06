<?php

namespace MadeSimple\TwoFactor\GoogleAuthenticator;

/**
 * @link https://developers.google.com/chart/infographics/docs/qr_codes
 */
class GoogleAuthenticator
{
    /**
     * @var string
     */
    private $secret;

    /**
     * @var int
     */
    private $length;

    /**
     * Return the current slice of time.
     *
     * @return int
     */
    protected static function sliceTime()
    {
        return floor(time() / 30);
    }

    /**
     * GoogleAuthenticator constructor.
     *
     * @param string $secret
     * @param int    $length
     */
    public function __construct($secret, $length = 6)
    {
        $this->secret = $secret;
        $this->length = $length;
    }

    /**
     * Generates $length bytes of randomness and base32 encode.
     *
     * @param int $length
     *
     * @return string
     * @throws \Exception
     */
    public static function secret($length = 16)
    {
        // Validate secret length
        if ($length < 16 || $length > 128) {
            throw new \InvalidArgumentException('Secret length must be 16 <= length <= 128');
        }

        $seed   = false;
        $strong = true;
        if (function_exists('random_bytes')) {
            $seed = random_bytes($length);
        } else if (function_exists('mcrypt_create_iv')) {
            $seed = mcrypt_create_iv($length, MCRYPT_DEV_URANDOM);
        } else if (function_exists('openssl_random_pseudo_bytes')) {
            $seed = openssl_random_pseudo_bytes($length, $strong);
        }
        if ($seed === false || $strong === false) {
            throw new \Exception('No source of secure randomness');
        }

        return substr(Base32::encode($seed), 0, $length);
    }

    /**
     * Generates the code of $length length from $secret and $timeSlice.
     *
     * @param string   $secret base32 encode
     * @param int      $length
     * @param int|null $timeSlice
     *
     * @return string
     * @see Base32
     */
    public static function code($secret, $length = 6, $timeSlice = null)
    {
        $timeSlice = $timeSlice ? : static::sliceTime();

        // Pack time into binary string
        $time = str_pad(pack('N*', $timeSlice), 8, chr(0), STR_PAD_LEFT);
        // Hash binary time string with binary secret
        $hash = hash_hmac('sha1', $time, Base32::decode($secret), true);
        // Use the last octet of the hash as the offset
        $offset = ord(substr($hash, -1)) & 0xF;
        // Grab 4 bytes of the result
        $bytes = substr($hash, $offset, 4);
        // Unpack the binary value and only 32 bits
        $value = unpack('N', $bytes)[1] & 0x7FFFFFFF;

        return str_pad($value % pow(10, $length), $length, '0', STR_PAD_LEFT);
    }

    /**
     * Verify the given $code. Accept codes that are 30 seconds x $discrepancy either side of the $timeSlice.
     *
     * @param string $code
     * @param int    $discrepancy Number of time slices either side to check
     * @param int    $timeSlice   Current slice of time
     *
     * @return bool
     */
    public function verify($code, $discrepancy = 1, $timeSlice = null)
    {
        // Force code into a string
        $code = (string) $code;

        // Check code length
        if (strlen($code) != $this->length) {
            return false;
        }

        $timeSlice = $timeSlice ? : static::sliceTime();

        for ($i = -$discrepancy; $i <= $discrepancy; $i++) {
            $calculatedCode = static::code($this->secret, $this->length, $timeSlice + $i);
            if (hash_equals($calculatedCode, $code)) {
                return true;
            }
        }

        return false;
    }

    /**
     * Generates a OTP Auth string which should be used as the data to generate a QR code.
     *
     * The Account name may not contain a double colon (:). Valid account name examples:
     *  - "John.Doe@gmail.com"
     *  - "John Doe"
     *  - "John_Doe_789"
     *
     * The Issuer may not contain a double colon (:). The issuer is recommended to pass along. If used, it will also
     * be appended before the account name.
     *
     * The previous examples of account names with an issue "Foo ltd" would result in the label:
     *  - "Foo ltd:John.Doe@gmail.com"
     *  - "Foo ltd:John Doe"
     *  - "Foo ltd:John_Doe_789"
     *
     * The contents of the label, issuer, and secret are used to generate the OTP auth string.
     *
     * @param string      $accountName
     * @param string      $secret
     * @param string|null $issuer
     * @return string
     */
    public static function otpAuthString($accountName, $secret, $issuer = null)
    {
        if ('' === $accountName || false !== strpos($accountName, ':')) {
            throw new \InvalidArgumentException(sprintf(
                'The account name may not contain a double colon (:) and may not be an empty string. Given "%s".',
                $accountName
            ));
        }
        if ('' === $secret) {
            throw new \InvalidArgumentException('The secret may not be an empty string.');
        }

        $label = $accountName;
        $otpAuthString = 'otpauth://totp/%s?secret=%s';

        if (null !== $issuer) {
            if ('' === $issuer || false !== strpos($issuer, ':')) {
                throw new \InvalidArgumentException(sprintf(
                    'The issuer may not contain a double colon (:) and may not be an empty string. Given "%s".',
                    $issuer
                ));
            }
            // use both the issuer parameter and label prefix as recommended by Google for BC reasons
            $label = $issuer.':'.$label;
            $otpAuthString .= '&issuer=%s';
        }

        return sprintf($otpAuthString, $label, $secret, $issuer);
    }
}
