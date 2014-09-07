<?php

namespace Crypt;

interface RC4Interface {

    /**
     * Constructor
     * 
     * @var string The secret key to be used for encryption/decryption
     */
    public function __construct( $key );

    /**
     * Function to encrypt the plaintext
     *
     * @var string $plainText Text to be encrypted
     */
    public function encrypt( $plainText );

    /**
     * Function to decrypt the encrypted text
     * 
     * @var string $plainText Encrypted text to be decrypted
     */
    public function decrypt( $encryptedText );

}