<?php
/**
 * This file contains the client code for Vanilla jsConnect single sign on.
 *
 * @author Todd Burry <todd@vanillaforums.com>
 * @author Ton Sharp <Forma-PRO@66ton99.org.ua>
 * @version 1.2
 * @copyright Copyright 2008-2012 Vanilla Forums Inc.
 * @license http://www.opensource.org/licenses/gpl-2.0.php GPLv2
 */

class JsConnect
{

   const TIMEOUT = 1440; #24 * 60

   protected $ClientID;

   protected $Secret;

   /**
    * Constructor
    *
    * @param string $ClientID The string client ID that you set up in the jsConnect settings page.
    * @param string $Secret The string secred that you set up in the jsConnect settings page.
    *
    * @return void
    */
   public function __construct($ClientID, $Secret)
   {
     $this->ClientID = $ClientID;
     $this->Secret = $Secret;
   }

   /**
    * Generate the jsConnect array for single sign on.
    *
    * @since 1.1b Added the ability to provide a hash algorithm to $Secure.
    *
    * @param array $User An array containing information about the currently signed on user.
    *                    If no user is signed in then this should be an empty array.
    * @param array $Request An array of the $_GET request.
    * @param string|bool $Secure Whether or not to check for security. This is one of these values.
    *  - true: Check for security and sign the response with an md5 hash.
    *  - false: Don't check for security, but sign the response with an md5 hash.
    *  - string: Check for security and sign the response with the given hash algorithm.
    *            See hash_algos() for what your server can support.
    *  - null: Don't check for security and don't sign the response.
    *
    * @return array
    */
   public function Generate($User, $Request, $Secure = TRUE) {
      $User = array_change_key_case($User);

      // Error checking.
      if ($Secure) {
         // Check the client.
         if (!isset($Request['client_id'])) {
            $Error = array('error' => 'invalid_request', 'message' => 'The client_id parameter is missing.');
         } elseif ($Request['client_id'] != $this->ClientID) {
            $Error = array('error' => 'invalid_client', 'message' => "Unknown client {$Request['client_id']}.");
         } elseif (!isset($Request['timestamp']) && !isset($Request['signature'])) {
            if (is_array($User) && count($User) > 0) {
               // This isn't really an error, but we are just going to return public information when no signature is sent.
               $Error = array('name' => $User['name'], 'photourl' => @$User['photourl']);
            } else {
               $Error = array('name' => '', 'photourl' => '');
            }
         } elseif (!isset($Request['timestamp']) || !is_numeric($Request['timestamp'])) {
            $Error = array('error' => 'invalid_request', 'message' => 'The timestamp parameter is missing or invalid.');
         } elseif (!isset($Request['signature'])) {
            $Error = array('error' => 'invalid_request', 'message' => 'Missing  signature parameter.');
         } elseif (($Diff = abs($Request['timestamp'] - $this->Timestamp())) > self::TIMEOUT) {
            $Error = array('error' => 'invalid_request', 'message' => 'The timestamp is invalid.');
         } else {
            // Make sure the timestamp hasn't timed out.
            $Signature = $this->Hash($Request['timestamp'].$this->Secret, $Secure);
            if ($Signature != $Request['signature']) {
               $Error = array('error' => 'access_denied', 'message' => 'Signature invalid.');
            }
         }
      }

      if (isset($Error)) {
         $Result = $Error;
      } elseif (is_array($User) && count($User) > 0) {
         if ($Secure === NULL) {
            $Result = $User;
         } else {
            $Result = $this->Sign($User, $this->ClientID, $this->Secret, $Secure, TRUE);
         }
      } else {
         $Result = array('name' => '', 'photourl' => '');
      }

      return $Result;
   }

   /**
    * Generate the jsConnect Json string for single sign on.
    *
    * @see self::Generate()
    *
    * @return string
    */
   public function GenerateJson($User, $Request, $Secure = TRUE)
   {
     $Json = json_encode($this->Generate($User, $Request, $Secure));
     if (isset($Request['callback'])) {
       return "{$Request['callback']}($Json)";
     }
     return $Json;
   }

   /**
    * Sign
    *
    * @param array $Data
    * @param bool|string $HashType
    * @param bool $ReturnData
    *
    * @return mixed
    */
   public function Sign($Data, $HashType, $ReturnData = FALSE) {
      $Data = array_change_key_case($Data);
      ksort($Data);

      foreach ($Data as $Key => $Value) {
         if ($Value === NULL) $Data[$Key] = '';
      }

      $String = http_build_query($Data, NULL, '&');
   //   echo "$String\n";
      $Signature = $this->Hash($String.$this->Secret, $HashType);
      if ($ReturnData) {
         $Data['client_id'] = $this->ClientID;
         $Data['signature'] = $Signature;
   //      $Data['string'] = $String;
         return $Data;
      } else {
         return $Signature;
      }
   }

   /**
    * Return the hash of a string.
    *
    * @since 1.1b
    *
    * @param string $String The string to hash.
    * @param string|bool $Secure The hash algorithm to use. TRUE means md5.
    *
    * @return string
    */
   protected function Hash($String, $Secure = TRUE) {
      switch ($Secure) {
         case 'md5':
         case TRUE:
         case FALSE:
            return md5($String);

         case 'sha1':
            return sha1($String);

         default:
            return hash($Secure, $String).$Secure;
      }
   }

   /**
    * Returns current timestamp
    *
    * @return int
    */
   protected function Timestamp() {
      return time();
   }
}
