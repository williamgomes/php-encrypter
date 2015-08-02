<?php

/*
  Autor: William Francis Gomes
  Version: 0.5
  Release Date: 01/09/2013
  License: The MIT License (MIT)
 */

class PHPHash {

    //an unique salt key constant which will be using through this class for encryption
    const uniSaltKey = "AbCdEfG125678";
    //salt variable
    private $_salt;
    //blowfish
    private static $algo = '$2a';
    //cost parameter
    private static $cost = '$10';

    /**
     * generateSaltKey function is used to generate random salt key
     * key length is by default set to 15 but it can be specified using $intLength
     * 
     * @param int $intLength (Specify length of the key)
     * @return string
     */
    public function generateSaltKey($intLength = 15) {
        //string that will be used to generate salt key
        $string = '0 1 2 3 4 5 6 7 8 9 a b c d e f g h i j k l m n o p q r s t u v x y z A B C D E F G H I J K L M N O P Q R S T U V X Y W Z';
        //making array from string of characters
        $array = explode(' ', $string);
        //picking random keys from the array and storing them
        $rand_keys = array_rand($array, $intLength);
        //using random keys generating the salt key
        for ($i = 0; $i < $intLength; $i++) {
            $this->_salt .= $array[$rand_keys[$i]];
        }
        return $this->_salt;
    }

    /**
     * This function will be used to encrypt a given string.
     * This encryption is irreversible. You have to encrypt a string in order to compare with another encrypted string.
     * Return value will be same always for a particular string.
     * 
     * @param string $strPassword
     * @return string
     */
    public function hashWithoutSalt($strPassword = "") {

        //created md5 hash
        $strPassword = md5($strPassword);
        //calculating the lengh of the value
        $length = strlen($strPassword);
        //checking set $strPasswordword_code or not
        $strPasswordword_code = self::uniSaltKey;
        if ($strPasswordword_code != '') {
            $security_code = trim($strPasswordword_code);
        } else {
            $security_code = '';
        }
        //dividing the lenght
        $start = floor($length / 2);
        //$search = which part will replace
        $search = substr($strPassword, 1, $start);
        //$search.$security_code replacing a part this password_code
        $securePass = str_replace($search, $search . $security_code, $strPassword);

        return $securePass;
    }

    /**
     * This function used to do encryption Blowfish Algorithm.
     * This function only takes a string and returns encrypted string.
     * 
     * @param string $strPassword
     * @return string
     */
    public function hashUsingBlowfish($strPassword = "") {
        $securePass = crypt($strPassword, self::$algo . self::$cost . '$' . $this->generateSaltKey());
        return $securePass;
    }

    /**
     * This function used to check a given string with a given encrypted string.
     * Takes two parameters, first parameter is the encrypted string and second parameter is the string that needs to checked.
     * This function will check two parameter and will return true if matched and false if not matched.
     * 
     * @param string $strHashed
     * @param string $strPassword
     * @return boolean
     */
    public static function checkHashUsingBlowfish($strHashed = "", $strPassword = "") {

        $strSaltKey = substr($strHashed, 0, 29);
        $strNewHash = crypt($strPassword, $strSaltKey);
        return ($strHashed == $strNewHash);
    }

}
