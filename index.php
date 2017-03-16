<?php
require_once dirname(__FILE__).'/functions.jsconnect.php';

// 1. Get your client ID and secret here. These must match those in your jsConnect settings.
$clientID = "1234";
$secret = "1234";

// 2. Grab the current user from your session management system or database here.
$signedIn = true; // this is just a placeholder

// YOUR CODE HERE.

// 3. Fill in the user information in a way that Vanilla can understand.
$user = array();

if ($signedIn) {
   // CHANGE THESE FOUR LINES.
   $user['uniqueid'] = '123';
   $user['name'] = 'John PHP';
   $user['email'] = 'john.php@anonymous.com';
   $user['photourl'] = '';
}

// 4. Generate the jsConnect string.

// This should be true unless you are testing. 
// You can also use a hash name like md5, sha1 etc which must be the name as the connection settings in Vanilla.
$secure = true; 
WriteJsConnect($user, $_GET, $clientID, $secret, $secure);
