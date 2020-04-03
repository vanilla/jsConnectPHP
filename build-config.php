<?php
/**
 * @author Todd Burry <todd@vanillaforums.com>
 * @copyright 2009-2020 Vanilla Forums Inc.
 * @license MIT
 */

require __DIR__.'/vendor/autoload.php';

use ClassPreloader\ClassLoader;
use Vanilla\JsConnect\JsConnect;
use Vanilla\JsConnect\JsConnectJSONP;

$config = ClassLoader::getIncludes(function (ClassLoader $loader) {
    $loader->register();
    $loader->loadClass(JsConnectJSONP::class);
    $loader->loadClass(JsConnect::class);
    $loader->loadClass(\Vanilla\JsConnect\Exceptions\JsConnectException::class);
    $loader->loadClass(\Vanilla\JsConnect\Exceptions\FieldNotFoundException::class);
    $loader->loadClass(\Vanilla\JsConnect\Exceptions\InvalidValueException::class);
    $loader->loadClass(\Firebase\JWT\BeforeValidException::class);
    $loader->loadClass(\Firebase\JWT\ExpiredException::class);
    $loader->loadClass(\Firebase\JWT\JWT::class);
    $loader->loadClass(\Firebase\JWT\SignatureInvalidException::class);
});

return $config;
