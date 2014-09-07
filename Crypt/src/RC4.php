<?php

namespace Crypt;

class RC4 {

    /**
     * @var string
     */
    private $key;

    /**
     * @var array
     */
    private $state;

    /**
     * @var array
     */
    private $keyStream;

    /**
     * @var string The secret key to be used for encryption/decryption
     */
    public function __construct( $key ) {
        if ( empty( $key ) || !is_string( $key ) ) {
            throw new Exception( 'Invalid Key' );
        }
        $this->key = $key;
    }

    /**
     * Initialize the S array using the Key-Scheduling Algorithm
     * (KSA). Sets $this->state.
     *
     * @return void
     */
    private function initializeState() {
        $state = array();

        for ( $i = 0; $i < 256; $i++ ) {
            $state[ $i ] = $i;
        }
        
        $j = 0;
        $keyLength = strlen( $this->key );
        for ( $i = 0; $i < 256; $i++ ) {
            $j = ( $j + $state[ $i ] + ( $this->key[ $i % $keyLength ] ) ) % 256;
            // swap values
            list( $state[ $j ], $state[ $i ] ) = array( $state[ $i ], $state[ $j ] );
        }

        $this->state = $state;
    }

    /**
     * Generate the stream of bits (which are XOred with the plain
     * text) using the Pseudo-Random Generation Algorithm
     *
     * @param Integer $length The length of the key stream to be generated
     * @return void
     */
    private function generateKeyStream( $length ) {
        $keyStream = '';
        $i = 0;
        $j = 0;
        for ( $k = 0; $k < $length; $k++ ) {
            $i = ( $i + 1 ) % 256;
            $j = ( $j + $this->state[ $i ]  ) % 256;
            // swap values
            list( $this->state[ $j ], $this->state[ $i ] ) = array( $this->state[ $i ], $this->state[ $j ] );
            $keyStream .= $this->state[ ( $this->state[ $i ] + $this->state[ $j ] ) % 256 ];
        }

        $this->keyStream = $keyStream;
    }

    /**
     * The encryption/decryption function which XORs the plaintext
     * with the keystream
     *
     * @param String $content String to be encrypted/decrypted
     * @return String A string that is encrypted/decrypted
     */
    private function crypt( $content ) {
        $contentLen = strlen( $content ); // strlen isn't good for
                                          // multibyte strings but
                                          // does the job here since
                                          // we only care about bytes
                                          // and not characers

        $this->initializeState();
        $this->generateKeyStream( $contentLen );

        $response = '';
        for ( $i = 0; $i < $contentLen; $i++ ) {
            $response .= $content[ $i ] ^ $this->keyStream[ $i ];
        }
        return $response;
    }
    
    public function encrypt( $content ) {
        return $this->crypt( $content );
    }

    public function decrypt( $content ) {
        return $this->crypt( $content );
    }
}