<?
    class PublicKeys {

    /*
        NOTE:
        The openssl_public_encrypt and openssl_private_decrypt functions don't work with strings 
        longer than about 112 characters. So I break the clearText into 100 character blocks and 
        encrypt each block separately. Each block creates 256 bytes of (binHexed) encrypted text.
        When decrypting, I separate the (binHexed) encrypted text into blocks of 256 characters
        and decrypt each block separately.
    
        EXAMPLE CODE:
        $key = new PublicKeys();
        $key->SetPublicKey('/path/to/public.key');
        $encryptedText = $key->Encrypt('some plain text, any length');
        
        $key->SetPrivateKey('/path/to/private.key');
        $plainText = $key->Decrypt($encryptedText);
        
    */

        private $publicKey;
        private $privateKey;

        function __construct() {
        
        }

        function SetPublicKey($key) {
            if ( substr($key, 0, 5) == '-----' ) {
                // passed in an actual key
                $this->publicKey = $key;
            } else {
                // assume this is a path and read in the key
                $this->publicKey = file_get_contents($key);
            }
        }

        function SetPrivateKey($key) {
            if ( substr($key, 0, 5) == '-----' ) {
                // passed in an actual key
                $this->privateKey = $key;
            } else {
                // assume this is a path and read in the key
                $this->privateKey = file_get_contents($key);
            }
        }

        function encrypt($clearText) {
            if ( $this->publicKey == '' ) return 'error - missing public key';
            $cryptText = '';
            while ( $clearText != '' ) {
                $clear     = substr($clearText, 0, 100);
                $clearText = substr($clearText, 100);
                openssl_public_encrypt($clear, $crypt, $this->publicKey);
                $cryptText .= bin2hex($crypt);
            }
            return $cryptText;
        }
        
        function decrypt($cryptText) {
            if ( $this->privateKey == '' ) return 'error - missing private key';
            $clearText = '';
            while ( $cryptText != '' ) {
                $crypt     = $this->hex2bin(substr($cryptText, 0, 256));
                $cryptText = substr($cryptText, 256);
                openssl_private_decrypt($crypt, $clear, $this->privateKey);
                $clearText .= $clear;
            }
            return $clearText;
        }
        
        // Pass full paths to the filenames to store the keys
        function generateKeyPair($publicKeyFile, $privateKeyFile) {
            // generate a 1024 bit rsa private key, returns a php resource, save to file
            $privateKey = openssl_pkey_new(array(
            	'private_key_bits' => 1024,
            	'private_key_type' => OPENSSL_KEYTYPE_RSA,
            ));
            openssl_pkey_export_to_file($privateKey, $privateKeyFile, $passphrase);
             
            // get the public key $keyDetails['key'] from the private key;
            $keyDetails = openssl_pkey_get_details($privateKey);
            file_put_contents($publicKeyFile, $keyDetails['key']);
        }
        
        // decrypt using a symetric key
        function symDecrypt($cryptText, $key) {
            $cryptText = $this->hex2bin($cryptText);
            $iv_size    = mcrypt_get_iv_size(MCRYPT_RIJNDAEL_256, MCRYPT_MODE_ECB);
            $iv         = mcrypt_create_iv($iv_size, MCRYPT_RAND);
            $plainText  = mcrypt_decrypt(MCRYPT_RIJNDAEL_256, $key, $cryptText, MCRYPT_MODE_ECB, $iv);
            
            return $plainText;
        }
        
        function symEncrypt($plainText, $key) {
            $iv_size = mcrypt_get_iv_size(MCRYPT_RIJNDAEL_256, MCRYPT_MODE_ECB);
            $iv = mcrypt_create_iv($iv_size, MCRYPT_RAND);
            $cryptText = mcrypt_encrypt(MCRYPT_RIJNDAEL_256, $key, $plainText, MCRYPT_MODE_ECB, $iv);
            $cryptText = bin2hex($cryptText);
            
            return $cryptText;
        }
        
        function hex2bin($h) {
            if (!is_string($h)) return null;
            $r='';
            for ($a=0; $a<strlen($h); $a+=2) { $r.=chr(hexdec($h{$a}.$h{($a+1)})); }
            return $r;
        }

    }
    
