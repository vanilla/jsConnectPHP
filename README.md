# Vanilla jsConnect Client Library for PHP #

_**Note:** Vanilla has recently updated it's jsConnect protocol to a different architecture that will work with current browsers that block third party cookies. Make sure you update your libraries to use the protocol. Once you've done this you will need to configure Vanilla to use the protocol in your dashboard under jsConnect settings._

## About jsConnect

The jsConnect protocol is a simple single sign on (SSO) framework that allows you to easily use your own site to sign on to a Vanilla site. It is intended to require as little programming as possible. You will need to do the following:

1. Program one page that responds with information about the currently signed in user.
2. Your main sign in page should be capable of redirecting to a URL that is supplied in the querystring.
3. You can optionally provide a registration page too, but it must also be capable of redirecting via a query string parameter.

## Installation

There are two ways to install jsConnect.

1. You can install this library via composer. You want to require `vanilla/js-connect-php`.
2. You can use the supplied [functions.jsconnect.php](./dist/functions.jsconnect.php). This is the old way of installing Vanilla. It still works, but we recommend transitioning to the composer install.

## Usage

There are two ways to use this jsConnect library. There is an object oriented way and a functional way.

### Object Oriented Usage

If you are new to jsConnect then we recommend the object oriented usage. Here is an example of what your page might look like.

```php
$jsConnect = new \Vanilla\JsConnect\JsConnect();

// 1. Add your client ID and secret. These values are defined in your dashboard.
$jsConnect->setSigningCredentials($clientID, $secret);

// 2. Grab the current user from your session management system or database here.
$signedIn = true; // this is just a placeholder

// YOUR CODE HERE.

// 3. Fill in the user information in a way that Vanilla can understand.
if ($signedIn) {
    // CHANGE THESE FOUR LINES.
  	$jsConnect
        ->setUniqueID('123')
      	->setName('Username')
      	->setEmail('user@example.com')
      	->setPhotoUrl('https://example.com/avatar.jpg');
} else {
  $jsConnect->setGuest(true);
}

// 4. Generate the jsConnect response and redirect.
$jsConnect->handleRequest($_GET);

```

## Functional Usage

The functional usage is mainly for backwards compatibility. If you are currently using this method then you can continue to do so. However, you may want to port your code to the object oriented method when you have time.

Here is an example of the functional usage:

```php
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
    $user['email'] = 'john.php@example.com';
    $user['photourl'] = '';
}

// 4. Generate the jsConnect string.

// This should be true unless you are testing.
// You can also use a hash name like md5, sha1 etc which must be the name as the connection settings in Vanilla.
$secure = true;
writeJsConnect($user, $_GET, $clientID, $secret, $secure);
```
