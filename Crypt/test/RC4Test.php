<?php

require __DIR__ . '/../vendor/autoload.php';

use Crypt\RC4;

class RC4Test extends PHPUnit_Framework_TestCase {

    private $rc4;

    public function setUp() {
        $this->rc4 = new RC4( 'this is a secret key' );
    }

    public function tearDown() {
        $this->rc4 = null;
    }

    public function testSimpleString() {

        $text = 'This is a test ... ';

        $encrypted = $this->rc4->encrypt( $text );
        $decrypted = $this->rc4->decrypt( $encrypted );

        $this->assertEquals( $text, $decrypted, 'The decrypted text should be the same as the input plain text');

    }

    /**
     * Testing multibyte characters. Using Unicode (as this file is saved as unicode)
     */
    public function testUnicodeString() {

        $text = 'this € is a ↈ  test';

        $encrypted = $this->rc4->encrypt( $text );
        $decrypted = $this->rc4->decrypt( $encrypted );

        $this->assertEquals( $text, $decrypted, 'The decrypted text should be the same as the input plain text');

    }
} 