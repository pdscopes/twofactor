# madesimple/twofactor
[![PHPUnit](https://github.com/pdscopes/twofactor/actions/workflows/phpunit.yml/badge.svg)](https://github.com/pdscopes/twofactor/actions/workflows/phpunit.yml)

Library for two factor authentication.

## Google Authenticator
How to use:
```php
use MadeSimple\TwoFactor\GoogleAuthenticator\GoogleAuthenticator;

$auth = new GoogleAuthenticator($secret);
if (!$auth->$verfiy($code)) {
    // Block access
}

// Sign them in
```