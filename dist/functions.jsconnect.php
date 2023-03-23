<?php
namespace Vanilla\JsConnect {
/**
 * This class contains backwards compatible methods for the v2.x jsConnect protocol.
 */
final class JsConnectJSONP
{
    const VERSION = '2';
    const TIMEOUT = 24 * 60;
    const FIELD_MAP = ['uniqueid' => JsConnect::FIELD_UNIQUE_ID, 'photourl' => JsConnect::FIELD_PHOTO];
    /**
     * Write the jsConnect string for single sign on.
     *
     * @param array $user An array containing information about the currently signed on user. If no user is signed in, this should be empty.
     * @param array $request An array of the $_GET request.
     * @param string $clientID The string client ID that you set up in the jsConnect settings page.
     * @param string $secret The string secret that you set up in the jsConnect settings page.
     * @param string|bool $secure Whether or not to check for security. This is one of these values.
     *  - true: Check for security and sign the response with an md5 hash.
     *  - false: Don't check for security, but sign the response with an md5 hash.
     *  - string: Check for security and sign the response with the given hash algorithm. See hash_algos() for what your server can support.
     *  - null: Don't check for security and don't sign the response.
     * @since 1.1b Added the ability to provide a hash algorithm to $secure.
     */
    public static function writeJsConnect($user, $request, $clientID, $secret, $secure = true) : void
    {
        if (isset($request['jwt'])) {
            self::writeJWT($user, $request, $clientID, $secret);
        } else {
            self::writeJSONP($user, $request, $clientID, $secret, $secure);
        }
    }
    /**
     * This is a backwards compatible method to help migrate jsConnect to the KWT protocol.
     *
     * @param array $user
     * @param array $query
     * @param string $clientID
     * @param string $secret
     */
    protected static function writeJWT(array $user, array $query, string $clientID, string $secret) : void
    {
        $jsc = new JsConnect();
        $jsc->setSigningCredentials($clientID, $secret);
        foreach ($user as $key => $value) {
            $lkey = strtolower($key);
            if (isset(self::FIELD_MAP[$lkey])) {
                $key = self::FIELD_MAP[$lkey];
            }
            $jsc->setUserField($key, $value);
        }
        $jsc->handleRequest($query);
    }
    /**
     * Write the JSONP (v2) protocol response.
     *
     * @param array $user
     * @param array $request
     * @param string $clientID
     * @param string $secret
     * @param bool|string|null $secure
     */
    protected static function writeJSONP(array $user, array $request, string $clientID, string $secret, $secure) : void
    {
        $user = array_change_key_case($user);
        // Error checking.
        if ($secure) {
            // Check the client.
            if (!isset($request['v'])) {
                $error = array('error' => 'invalid_request', 'message' => 'Missing the v parameter.');
            } elseif ($request['v'] !== self::VERSION) {
                $error = array('error' => 'invalid_request', 'message' => "Unsupported version {$request['v']}.");
            } elseif (!isset($request['client_id'])) {
                $error = array('error' => 'invalid_request', 'message' => 'Missing the client_id parameter.');
            } elseif ($request['client_id'] != $clientID) {
                $error = array('error' => 'invalid_client', 'message' => "Unknown client {$request['client_id']}.");
            } elseif (!isset($request['timestamp']) && !isset($request['sig'])) {
                if (count($user) > 0) {
                    // This isn't really an error, but we are just going to return public information when no signature is sent.
                    $error = array('name' => (string) @$user['name'], 'photourl' => @$user['photourl'], 'signedin' => true);
                } else {
                    $error = array('name' => '', 'photourl' => '');
                }
            } elseif (!isset($request['timestamp']) || !ctype_digit($request['timestamp'])) {
                $error = array('error' => 'invalid_request', 'message' => 'The timestamp parameter is missing or invalid.');
            } elseif (!isset($request['sig'])) {
                $error = array('error' => 'invalid_request', 'message' => 'Missing the sig parameter.');
            } elseif (abs($request['timestamp'] - self::timestamp()) > self::TIMEOUT) {
                // Make sure the timestamp hasn't timeout
                $error = array('error' => 'invalid_request', 'message' => 'The timestamp is invalid.');
            } elseif (!isset($request['nonce'])) {
                $error = array('error' => 'invalid_request', 'message' => 'Missing the nonce parameter.');
            } elseif (!isset($request['ip'])) {
                $error = array('error' => 'invalid_request', 'message' => 'Missing the ip parameter.');
            } else {
                $signature = self::hash($request['ip'] . $request['nonce'] . $request['timestamp'] . $secret, $secure);
                if ($signature != $request['sig']) {
                    $error = array('error' => 'access_denied', 'message' => 'Signature invalid.');
                }
            }
        }
        if (isset($error)) {
            $result = $error;
        } elseif (count($user) > 0) {
            if ($secure === null) {
                $result = $user;
            } else {
                $user['ip'] = $request['ip'];
                $user['nonce'] = $request['nonce'];
                $result = self::signJsConnect($user, $clientID, $secret, $secure, true);
                /**
                 * @psalm-suppress PossiblyInvalidArrayOffset
                 */
                $result['v'] = self::VERSION;
            }
        } else {
            $result = ['name' => '', 'photourl' => ''];
        }
        $content = json_encode($result);
        if (isset($request['callback'])) {
            $content = "{$request['callback']}({$content})";
        }
        if (!headers_sent()) {
            $contentType = self::contentType($request);
            header($contentType, true);
        }
        echo $content;
    }
    /**
     * Get the current timestamp.
     *
     * @return int
     */
    public static function timestamp()
    {
        return time();
    }
    /**
     * Return the hash of a string.
     *
     * @param string $string The string to hash.
     * @param string|bool $secure The hash algorithm to use. true means md5.
     * @return string
     */
    public static function hash($string, $secure = true)
    {
        if ($secure === true) {
            $secure = 'md5';
        }
        switch ($secure) {
            case 'sha1':
                return sha1($string);
                break;
            case 'md5':
            case false:
                return md5($string);
            default:
                return hash($secure, $string);
        }
    }
    /**
     * Sign a jsConnect array.
     *
     * @param array $data
     * @param string $clientID
     * @param string $secret
     * @param string|bool $hashType
     * @param bool $returnData
     *
     * @return array|string
     */
    public static function signJsConnect(array $data, string $clientID, string $secret, $hashType, bool $returnData = false)
    {
        $normalizedData = array_change_key_case($data);
        ksort($normalizedData);
        foreach ($normalizedData as $key => $value) {
            if ($value === null) {
                $normalizedData[$key] = '';
            }
        }
        // RFC1738 state that spaces are encoded as '+'.
        $stringifiedData = http_build_query($normalizedData, '', '&', PHP_QUERY_RFC1738);
        $signature = self::hash($stringifiedData . $secret, $hashType);
        if ($returnData) {
            $normalizedData['client_id'] = $clientID;
            $normalizedData['sig'] = $signature;
            return $normalizedData;
        } else {
            return $signature;
        }
    }
    /**
     * Based on a jsConnect request, determine the proper response content type.
     *
     * @param array $request
     * @return string
     */
    public static function contentType(array $request) : string
    {
        $isJsonp = isset($request["callback"]);
        $contentType = $isJsonp ? "Content-Type: application/javascript; charset=utf-8" : "Content-Type: application/json; charset=utf-8";
        return $contentType;
    }
    /**
     * Generate an SSO string suitable for passing in the url for embedded SSO.
     *
     * @param array $user The user to sso.
     * @param string $clientID Your client ID.
     * @param string $secret Your secret.
     * @return string
     */
    public static function ssoString($user, $clientID, $secret)
    {
        if (!isset($user['client_id'])) {
            $user['client_id'] = $clientID;
        }
        $string = base64_encode(json_encode($user));
        $timestamp = time();
        $hash = hash_hmac('sha1', "{$string} {$timestamp}", $secret);
        $result = "{$string} {$hash} {$timestamp} hmacsha1";
        return $result;
    }
}
}

namespace Vanilla\JsConnect {
use Exception;
use Firebase\JWT\JWT;
use Firebase\JWT\Key;
use UnexpectedValueException;
use Vanilla\JsConnect\Exceptions\FieldNotFoundException;
use Vanilla\JsConnect\Exceptions\InvalidValueException;
/**
 * Handles the jsConnect protocol v3.x.
 */
class JsConnect
{
    const VERSION = 'php:3';
    const FIELD_UNIQUE_ID = 'id';
    const FIELD_PHOTO = 'photo';
    const FIELD_NAME = 'name';
    const FIELD_EMAIL = 'email';
    const FIELD_ROLES = 'roles';
    const FIELD_JWT = 'jwt';
    const TIMEOUT = 10 * 60;
    const ALLOWED_ALGORITHMS = ['ES256', 'HS256', 'HS384', 'HS512', 'RS256', 'RS384', 'RS512'];
    const FIELD_STATE = 'st';
    const FIELD_USER = 'u';
    const FIELD_REDIRECT_URL = 'rurl';
    const FIELD_CLIENT_ID = 'kid';
    const FIELD_TARGET = 't';
    /**
     * @var \ArrayAccess
     */
    protected $keys;
    /**
     * @var string string
     */
    protected $signingClientID = '';
    /**
     * @var array
     */
    protected $user = [];
    /**
     * @var bool
     */
    protected $guest = false;
    /**
     * @var string
     */
    protected $signingAlgorithm;
    /**
     * @var int
     */
    protected $timeout = self::TIMEOUT;
    /**
     * JsConnect constructor.
     */
    public function __construct()
    {
        $this->keys = new \ArrayObject();
        $this->setSigningAlgorithm('HS256');
    }
    /**
     * Validate a value that cannot be empty.
     *
     * @param mixed $value The value to test.
     * @param string $valueName The name of the value for the exception message.
     * @throws InvalidValueException Throws an exception when the value is empty.
     */
    protected static function validateNotEmpty($value, string $valueName) : void
    {
        if ($value === null) {
            throw new InvalidValueException("{$valueName} is required.");
        }
        if (empty($value)) {
            throw new InvalidValueException("{$valueName} cannot be empty.");
        }
    }
    /**
     * Set the current user's email address.
     *
     * @param string $email
     * @return $this
     */
    public function setEmail(string $email)
    {
        return $this->setUserField(self::FIELD_EMAIL, $email);
    }
    /**
     * Set a field on the current user.
     *
     * @param string $key The key on the user.
     * @param string|int|bool|array|null $value The value to set. This must be a basic type that can be JSON encoded.
     * @return $this
     */
    public function setUserField(string $key, $value)
    {
        $this->user[$key] = $value;
        return $this;
    }
    /**
     * Set the current user's username.
     *
     * @param string $name
     * @return $this
     */
    public function setName(string $name)
    {
        return $this->setUserField(self::FIELD_NAME, $name);
    }
    /**
     * Set the current user's avatar.
     *
     * @param string $photo
     * @return $this
     */
    public function setPhotoURL(string $photo)
    {
        return $this->setUserField(self::FIELD_PHOTO, $photo);
    }
    /**
     * Set the current user's unique ID.
     *
     * @param string $id
     * @return $this
     */
    public function setUniqueID(string $id)
    {
        return $this->setUserField(self::FIELD_UNIQUE_ID, $id);
    }
    /**
     * Handle the authentication request and redirect back to Vanilla.
     *
     * @param array $query
     */
    public function handleRequest(array $query) : void
    {
        try {
            $jwt = static::validateFieldExists(self::FIELD_JWT, $query, 'querystring');
            $location = $this->generateResponseLocation($jwt);
            $this->redirect($location);
        } catch (Exception $ex) {
            echo htmlspecialchars($ex->getMessage());
        }
    }
    /**
     * Validate that a field exists in a collection.
     *
     * @param string $field The name of the field to validate.
     * @param mixed $collection The collection to look at.
     * @param string $collectionName The name of the collection.
     * @param bool $validateEmpty If true, make sure the value is also not empty.
     * @return mixed Returns the field value if there are no errors.
     * @throws FieldNotFoundException Throws an exception when the field is not in the array.
     * @throws InvalidValueException Throws an exception when the collection isn't an array or the value is empty.
     */
    protected static function validateFieldExists(string $field, $collection, string $collectionName = 'payload', bool $validateEmpty = true)
    {
        if (!(is_array($collection) || $collection instanceof \ArrayAccess)) {
            throw new InvalidValueException("Invalid array: {$collectionName}");
        }
        if (!isset($collection[$field])) {
            throw new FieldNotFoundException($field, $collectionName);
        }
        if ($validateEmpty && empty($collection[$field])) {
            throw new InvalidValueException("Field cannot be empty: {$collectionName}[{$field}]");
        }
        return $collection[$field];
    }
    /**
     * Generate the location for an SSO redirect.
     *
     * @param string $requestJWT
     * @return string
     */
    public function generateResponseLocation(string $requestJWT) : string
    {
        // Validate the request token.
        $request = $this->jwtDecode($requestJWT);
        if ($this->isGuest()) {
            $data = [self::FIELD_USER => new \stdClass(), self::FIELD_STATE => $request[self::FIELD_STATE] ?? []];
        } else {
            // Generate the response token.
            $data = [self::FIELD_USER => $this->user, self::FIELD_STATE => $request[self::FIELD_STATE] ?? []];
        }
        $response = $this->jwtEncode($data);
        $location = $request[self::FIELD_REDIRECT_URL] . '#' . http_build_query(['jwt' => $response]);
        return $location;
    }
    /**
     * Decode a JWT with the connection's settings.
     *
     * @param string $jwt
     * @return array
     */
    public function jwtDecode(string $jwt) : array
    {
        /**
         * @psalm-suppress InvalidArgument
         */
        $keys = [];
        foreach ($this->keys as $id => $key) {
            $keys[$id] = new Key($key, $this->getSigningAlgorithm());
        }
        $payload = JWT::decode($jwt, $keys);
        $payload = $this->stdClassToArray($payload);
        return $payload;
    }
    /**
     * Convert an object to an array, recursively.
     *
     * @param array|object $o
     * @return array
     */
    protected function stdClassToArray($o) : array
    {
        if (!is_array($o) && !$o instanceof \stdClass) {
            throw new UnexpectedValueException("JsConnect::stdClassToArray() expects an object or array, scalar given.", 400);
        }
        $o = (array) $o;
        $r = [];
        foreach ($o as $key => $value) {
            if (is_array($value) || is_object($value)) {
                $r[$key] = $this->stdClassToArray($value);
            } else {
                $r[$key] = $value;
            }
        }
        return $r;
    }
    /**
     * Whether or not the user is signed in.
     *
     * @return bool
     */
    public function isGuest() : bool
    {
        return $this->guest;
    }
    /**
     * Set whether or not the user is signed in.
     *
     * @param bool $isGuest
     * @return $this
     */
    public function setGuest(bool $isGuest)
    {
        $this->guest = $isGuest;
        return $this;
    }
    /**
     * Wrap a payload in a JWT.
     *
     * @param array $payload
     * @return string
     */
    public function jwtEncode(array $payload) : string
    {
        $payload += ['v' => $this->getVersion(), 'iat' => $this->getTimestamp(), 'exp' => $this->getTimestamp() + $this->getTimeout()];
        $jwt = JWT::encode($payload, $this->getSigningSecret(), $this->getSigningAlgorithm(), null, [self::FIELD_CLIENT_ID => $this->getSigningClientID()]);
        return $jwt;
    }
    /**
     * Get the current timestamp.
     *
     * This time is used for signing and verifying tokens.
     *
     * @return int
     */
    protected function getTimestamp() : int
    {
        $r = JWT::$timestamp ?: time();
        return $r;
    }
    /**
     * Get the secret that is used to sign JWTs.
     *
     * @return string
     */
    public function getSigningSecret() : string
    {
        return $this->keys[$this->signingClientID];
    }
    /**
     * Get the algorithm used to sign tokens.
     *
     * @return string
     */
    public function getSigningAlgorithm() : string
    {
        return $this->signingAlgorithm;
    }
    /**
     * Set the algorithm used to sign tokens.
     *
     * @param string $signingAlgorithm
     * @return $this
     */
    public function setSigningAlgorithm(string $signingAlgorithm)
    {
        if (!in_array($signingAlgorithm, static::ALLOWED_ALGORITHMS)) {
            throw new UnexpectedValueException('Algorithm not allowed');
        }
        $this->signingAlgorithm = $signingAlgorithm;
        return $this;
    }
    /**
     * Get the client ID that is used to sign JWTs.
     *
     * @return string
     */
    public function getSigningClientID() : string
    {
        return $this->signingClientID;
    }
    /**
     * Redirect to a new location.
     *
     * @param string $location
     */
    protected function redirect(string $location) : void
    {
        header("Location: {$location}", true, 302);
        die;
    }
    /**
     * Set the credentials that will be used to sign requests.
     *
     * @param string $clientID
     * @param string $secret
     * @return $this
     */
    public function setSigningCredentials(string $clientID, string $secret)
    {
        $this->keys[$clientID] = $secret;
        $this->signingClientID = $clientID;
        return $this;
    }
    public function getUser() : array
    {
        return $this->user;
    }
    /**
     * Set the roles on the user.
     *
     * @param array $roles
     * @return $this
     */
    public function setRoles(array $roles)
    {
        $this->setUserField(self::FIELD_ROLES, $roles);
        return $this;
    }
    /**
     * Returns a JWT header.
     *
     * @param string $jwt
     *
     * @return array|null
     */
    public static final function decodeJWTHeader(string $jwt) : ?array
    {
        $tks = explode('.', $jwt);
        if (count($tks) != 3) {
            throw new UnexpectedValueException('Wrong number of segments');
        }
        list($headb64) = $tks;
        if (null === ($header = JWT::jsonDecode(JWT::urlsafeB64Decode($headb64)))) {
            throw new UnexpectedValueException('Invalid header encoding');
        }
        return json_decode(json_encode($header), true);
    }
    /**
     * Get the version used to sign requests.
     *
     * @return string
     */
    public function getVersion() : string
    {
        return self::VERSION;
    }
    /**
     * Get the JWT expiry timeout.
     *
     * @return int
     */
    public function getTimeout() : int
    {
        return $this->timeout;
    }
    /**
     * Set the JWT expiry timeout.
     *
     * @param int $timeout
     * @return $this
     */
    public function setTimeout(int $timeout)
    {
        $this->timeout = $timeout;
        return $this;
    }
}
}

namespace Vanilla\JsConnect\Exceptions {
/**
 * The base class for all JsConnect exceptions.
 */
class JsConnectException extends \Exception
{
}
}

namespace Vanilla\JsConnect\Exceptions {
/**
 * An exception that represents a missing field in a request or response.
 */
class FieldNotFoundException extends JsConnectException
{
    /**
     * FieldNotFoundException constructor.
     *
     * @param string $field
     * @param string $collection
     */
    public function __construct(string $field, string $collection = 'payload')
    {
        parent::__construct("Missing field: {$collection}[{$field}]", 404);
    }
}
}

namespace Vanilla\JsConnect\Exceptions {
/**
 * An exception that represents a value that is not the correct type or expected value.
 */
class InvalidValueException extends JsConnectException
{
    /**
     * InvalidValueException constructor.
     *
     * @param string $message
     */
    public function __construct(string $message = "")
    {
        parent::__construct($message, 400);
    }
}
}

namespace Firebase\JWT {
class BeforeValidException extends \UnexpectedValueException
{
}
}

namespace Firebase\JWT {
class ExpiredException extends \UnexpectedValueException
{
}
}

namespace Firebase\JWT {
use ArrayAccess;
use DateTime;
use DomainException;
use Exception;
use InvalidArgumentException;
use OpenSSLAsymmetricKey;
use OpenSSLCertificate;
use stdClass;
use UnexpectedValueException;
/**
 * JSON Web Token implementation, based on this spec:
 * https://tools.ietf.org/html/rfc7519
 *
 * PHP version 5
 *
 * @category Authentication
 * @package  Authentication_JWT
 * @author   Neuman Vong <neuman@twilio.com>
 * @author   Anant Narayanan <anant@php.net>
 * @license  http://opensource.org/licenses/BSD-3-Clause 3-clause BSD
 * @link     https://github.com/firebase/php-jwt
 */
class JWT
{
    private const ASN1_INTEGER = 0x2;
    private const ASN1_SEQUENCE = 0x10;
    private const ASN1_BIT_STRING = 0x3;
    /**
     * When checking nbf, iat or expiration times,
     * we want to provide some extra leeway time to
     * account for clock skew.
     *
     * @var int
     */
    public static $leeway = 0;
    /**
     * Allow the current timestamp to be specified.
     * Useful for fixing a value within unit testing.
     * Will default to PHP time() value if null.
     *
     * @var ?int
     */
    public static $timestamp = null;
    /**
     * @var array<string, string[]>
     */
    public static $supported_algs = ['ES384' => ['openssl', 'SHA384'], 'ES256' => ['openssl', 'SHA256'], 'ES256K' => ['openssl', 'SHA256'], 'HS256' => ['hash_hmac', 'SHA256'], 'HS384' => ['hash_hmac', 'SHA384'], 'HS512' => ['hash_hmac', 'SHA512'], 'RS256' => ['openssl', 'SHA256'], 'RS384' => ['openssl', 'SHA384'], 'RS512' => ['openssl', 'SHA512'], 'EdDSA' => ['sodium_crypto', 'EdDSA']];
    /**
     * Decodes a JWT string into a PHP object.
     *
     * @param string                 $jwt            The JWT
     * @param Key|array<string,Key> $keyOrKeyArray  The Key or associative array of key IDs (kid) to Key objects.
     *                                               If the algorithm used is asymmetric, this is the public key
     *                                               Each Key object contains an algorithm and matching key.
     *                                               Supported algorithms are 'ES384','ES256', 'HS256', 'HS384',
     *                                               'HS512', 'RS256', 'RS384', and 'RS512'
     *
     * @return stdClass The JWT's payload as a PHP object
     *
     * @throws InvalidArgumentException     Provided key/key-array was empty or malformed
     * @throws DomainException              Provided JWT is malformed
     * @throws UnexpectedValueException     Provided JWT was invalid
     * @throws SignatureInvalidException    Provided JWT was invalid because the signature verification failed
     * @throws BeforeValidException         Provided JWT is trying to be used before it's eligible as defined by 'nbf'
     * @throws BeforeValidException         Provided JWT is trying to be used before it's been created as defined by 'iat'
     * @throws ExpiredException             Provided JWT has since expired, as defined by the 'exp' claim
     *
     * @uses jsonDecode
     * @uses urlsafeB64Decode
     */
    public static function decode(string $jwt, $keyOrKeyArray) : stdClass
    {
        // Validate JWT
        $timestamp = \is_null(static::$timestamp) ? \time() : static::$timestamp;
        if (empty($keyOrKeyArray)) {
            throw new InvalidArgumentException('Key may not be empty');
        }
        $tks = \explode('.', $jwt);
        if (\count($tks) !== 3) {
            throw new UnexpectedValueException('Wrong number of segments');
        }
        list($headb64, $bodyb64, $cryptob64) = $tks;
        $headerRaw = static::urlsafeB64Decode($headb64);
        if (null === ($header = static::jsonDecode($headerRaw))) {
            throw new UnexpectedValueException('Invalid header encoding');
        }
        $payloadRaw = static::urlsafeB64Decode($bodyb64);
        if (null === ($payload = static::jsonDecode($payloadRaw))) {
            throw new UnexpectedValueException('Invalid claims encoding');
        }
        if (\is_array($payload)) {
            // prevent PHP Fatal Error in edge-cases when payload is empty array
            $payload = (object) $payload;
        }
        if (!$payload instanceof stdClass) {
            throw new UnexpectedValueException('Payload must be a JSON object');
        }
        $sig = static::urlsafeB64Decode($cryptob64);
        if (empty($header->alg)) {
            throw new UnexpectedValueException('Empty algorithm');
        }
        if (empty(static::$supported_algs[$header->alg])) {
            throw new UnexpectedValueException('Algorithm not supported');
        }
        $key = self::getKey($keyOrKeyArray, property_exists($header, 'kid') ? $header->kid : null);
        // Check the algorithm
        if (!self::constantTimeEquals($key->getAlgorithm(), $header->alg)) {
            // See issue #351
            throw new UnexpectedValueException('Incorrect key for this algorithm');
        }
        if (\in_array($header->alg, ['ES256', 'ES256K', 'ES384'], true)) {
            // OpenSSL expects an ASN.1 DER sequence for ES256/ES256K/ES384 signatures
            $sig = self::signatureToDER($sig);
        }
        if (!self::verify("{$headb64}.{$bodyb64}", $sig, $key->getKeyMaterial(), $header->alg)) {
            throw new SignatureInvalidException('Signature verification failed');
        }
        // Check the nbf if it is defined. This is the time that the
        // token can actually be used. If it's not yet that time, abort.
        if (isset($payload->nbf) && $payload->nbf > $timestamp + static::$leeway) {
            throw new BeforeValidException('Cannot handle token prior to ' . \date(DateTime::ISO8601, $payload->nbf));
        }
        // Check that this token has been created before 'now'. This prevents
        // using tokens that have been created for later use (and haven't
        // correctly used the nbf claim).
        if (isset($payload->iat) && $payload->iat > $timestamp + static::$leeway) {
            throw new BeforeValidException('Cannot handle token prior to ' . \date(DateTime::ISO8601, $payload->iat));
        }
        // Check if this token has expired.
        if (isset($payload->exp) && $timestamp - static::$leeway >= $payload->exp) {
            throw new ExpiredException('Expired token');
        }
        return $payload;
    }
    /**
     * Converts and signs a PHP array into a JWT string.
     *
     * @param array<mixed>          $payload PHP array
     * @param string|resource|OpenSSLAsymmetricKey|OpenSSLCertificate $key The secret key.
     * @param string                $alg     Supported algorithms are 'ES384','ES256', 'ES256K', 'HS256',
     *                                       'HS384', 'HS512', 'RS256', 'RS384', and 'RS512'
     * @param string                $keyId
     * @param array<string, string> $head    An array with header elements to attach
     *
     * @return string A signed JWT
     *
     * @uses jsonEncode
     * @uses urlsafeB64Encode
     */
    public static function encode(array $payload, $key, string $alg, string $keyId = null, array $head = null) : string
    {
        $header = ['typ' => 'JWT', 'alg' => $alg];
        if ($keyId !== null) {
            $header['kid'] = $keyId;
        }
        if (isset($head) && \is_array($head)) {
            $header = \array_merge($head, $header);
        }
        $segments = [];
        $segments[] = static::urlsafeB64Encode((string) static::jsonEncode($header));
        $segments[] = static::urlsafeB64Encode((string) static::jsonEncode($payload));
        $signing_input = \implode('.', $segments);
        $signature = static::sign($signing_input, $key, $alg);
        $segments[] = static::urlsafeB64Encode($signature);
        return \implode('.', $segments);
    }
    /**
     * Sign a string with a given key and algorithm.
     *
     * @param string $msg  The message to sign
     * @param string|resource|OpenSSLAsymmetricKey|OpenSSLCertificate  $key  The secret key.
     * @param string $alg  Supported algorithms are 'ES384','ES256', 'ES256K', 'HS256',
     *                    'HS384', 'HS512', 'RS256', 'RS384', and 'RS512'
     *
     * @return string An encrypted message
     *
     * @throws DomainException Unsupported algorithm or bad key was specified
     */
    public static function sign(string $msg, $key, string $alg) : string
    {
        if (empty(static::$supported_algs[$alg])) {
            throw new DomainException('Algorithm not supported');
        }
        list($function, $algorithm) = static::$supported_algs[$alg];
        switch ($function) {
            case 'hash_hmac':
                if (!\is_string($key)) {
                    throw new InvalidArgumentException('key must be a string when using hmac');
                }
                return \hash_hmac($algorithm, $msg, $key, true);
            case 'openssl':
                $signature = '';
                $success = \openssl_sign($msg, $signature, $key, $algorithm);
                // @phpstan-ignore-line
                if (!$success) {
                    throw new DomainException('OpenSSL unable to sign data');
                }
                if ($alg === 'ES256' || $alg === 'ES256K') {
                    $signature = self::signatureFromDER($signature, 256);
                } elseif ($alg === 'ES384') {
                    $signature = self::signatureFromDER($signature, 384);
                }
                return $signature;
            case 'sodium_crypto':
                if (!\function_exists('sodium_crypto_sign_detached')) {
                    throw new DomainException('libsodium is not available');
                }
                if (!\is_string($key)) {
                    throw new InvalidArgumentException('key must be a string when using EdDSA');
                }
                try {
                    // The last non-empty line is used as the key.
                    $lines = array_filter(explode("\n", $key));
                    $key = base64_decode((string) end($lines));
                    if (\strlen($key) === 0) {
                        throw new DomainException('Key cannot be empty string');
                    }
                    return sodium_crypto_sign_detached($msg, $key);
                } catch (Exception $e) {
                    throw new DomainException($e->getMessage(), 0, $e);
                }
        }
        throw new DomainException('Algorithm not supported');
    }
    /**
     * Verify a signature with the message, key and method. Not all methods
     * are symmetric, so we must have a separate verify and sign method.
     *
     * @param string $msg         The original message (header and body)
     * @param string $signature   The original signature
     * @param string|resource|OpenSSLAsymmetricKey|OpenSSLCertificate  $keyMaterial For HS*, a string key works. for RS*, must be an instance of OpenSSLAsymmetricKey
     * @param string $alg         The algorithm
     *
     * @return bool
     *
     * @throws DomainException Invalid Algorithm, bad key, or OpenSSL failure
     */
    private static function verify(string $msg, string $signature, $keyMaterial, string $alg) : bool
    {
        if (empty(static::$supported_algs[$alg])) {
            throw new DomainException('Algorithm not supported');
        }
        list($function, $algorithm) = static::$supported_algs[$alg];
        switch ($function) {
            case 'openssl':
                $success = \openssl_verify($msg, $signature, $keyMaterial, $algorithm);
                // @phpstan-ignore-line
                if ($success === 1) {
                    return true;
                }
                if ($success === 0) {
                    return false;
                }
                // returns 1 on success, 0 on failure, -1 on error.
                throw new DomainException('OpenSSL error: ' . \openssl_error_string());
            case 'sodium_crypto':
                if (!\function_exists('sodium_crypto_sign_verify_detached')) {
                    throw new DomainException('libsodium is not available');
                }
                if (!\is_string($keyMaterial)) {
                    throw new InvalidArgumentException('key must be a string when using EdDSA');
                }
                try {
                    // The last non-empty line is used as the key.
                    $lines = array_filter(explode("\n", $keyMaterial));
                    $key = base64_decode((string) end($lines));
                    if (\strlen($key) === 0) {
                        throw new DomainException('Key cannot be empty string');
                    }
                    if (\strlen($signature) === 0) {
                        throw new DomainException('Signature cannot be empty string');
                    }
                    return sodium_crypto_sign_verify_detached($signature, $msg, $key);
                } catch (Exception $e) {
                    throw new DomainException($e->getMessage(), 0, $e);
                }
            case 'hash_hmac':
            default:
                if (!\is_string($keyMaterial)) {
                    throw new InvalidArgumentException('key must be a string when using hmac');
                }
                $hash = \hash_hmac($algorithm, $msg, $keyMaterial, true);
                return self::constantTimeEquals($hash, $signature);
        }
    }
    /**
     * Decode a JSON string into a PHP object.
     *
     * @param string $input JSON string
     *
     * @return mixed The decoded JSON string
     *
     * @throws DomainException Provided string was invalid JSON
     */
    public static function jsonDecode(string $input)
    {
        $obj = \json_decode($input, false, 512, JSON_BIGINT_AS_STRING);
        if ($errno = \json_last_error()) {
            self::handleJsonError($errno);
        } elseif ($obj === null && $input !== 'null') {
            throw new DomainException('Null result with non-null input');
        }
        return $obj;
    }
    /**
     * Encode a PHP array into a JSON string.
     *
     * @param array<mixed> $input A PHP array
     *
     * @return string JSON representation of the PHP array
     *
     * @throws DomainException Provided object could not be encoded to valid JSON
     */
    public static function jsonEncode(array $input) : string
    {
        if (PHP_VERSION_ID >= 50400) {
            $json = \json_encode($input, \JSON_UNESCAPED_SLASHES);
        } else {
            // PHP 5.3 only
            $json = \json_encode($input);
        }
        if ($errno = \json_last_error()) {
            self::handleJsonError($errno);
        } elseif ($json === 'null' && $input !== null) {
            throw new DomainException('Null result with non-null input');
        }
        if ($json === false) {
            throw new DomainException('Provided object could not be encoded to valid JSON');
        }
        return $json;
    }
    /**
     * Decode a string with URL-safe Base64.
     *
     * @param string $input A Base64 encoded string
     *
     * @return string A decoded string
     *
     * @throws InvalidArgumentException invalid base64 characters
     */
    public static function urlsafeB64Decode(string $input) : string
    {
        $remainder = \strlen($input) % 4;
        if ($remainder) {
            $padlen = 4 - $remainder;
            $input .= \str_repeat('=', $padlen);
        }
        return \base64_decode(\strtr($input, '-_', '+/'));
    }
    /**
     * Encode a string with URL-safe Base64.
     *
     * @param string $input The string you want encoded
     *
     * @return string The base64 encode of what you passed in
     */
    public static function urlsafeB64Encode(string $input) : string
    {
        return \str_replace('=', '', \strtr(\base64_encode($input), '+/', '-_'));
    }
    /**
     * Determine if an algorithm has been provided for each Key
     *
     * @param Key|ArrayAccess<string,Key>|array<string,Key> $keyOrKeyArray
     * @param string|null            $kid
     *
     * @throws UnexpectedValueException
     *
     * @return Key
     */
    private static function getKey($keyOrKeyArray, ?string $kid) : Key
    {
        if ($keyOrKeyArray instanceof Key) {
            return $keyOrKeyArray;
        }
        if (empty($kid)) {
            throw new UnexpectedValueException('"kid" empty, unable to lookup correct key');
        }
        if ($keyOrKeyArray instanceof CachedKeySet) {
            // Skip "isset" check, as this will automatically refresh if not set
            return $keyOrKeyArray[$kid];
        }
        if (!isset($keyOrKeyArray[$kid])) {
            throw new UnexpectedValueException('"kid" invalid, unable to lookup correct key');
        }
        return $keyOrKeyArray[$kid];
    }
    /**
     * @param string $left  The string of known length to compare against
     * @param string $right The user-supplied string
     * @return bool
     */
    public static function constantTimeEquals(string $left, string $right) : bool
    {
        if (\function_exists('hash_equals')) {
            return \hash_equals($left, $right);
        }
        $len = \min(self::safeStrlen($left), self::safeStrlen($right));
        $status = 0;
        for ($i = 0; $i < $len; $i++) {
            $status |= \ord($left[$i]) ^ \ord($right[$i]);
        }
        $status |= self::safeStrlen($left) ^ self::safeStrlen($right);
        return $status === 0;
    }
    /**
     * Helper method to create a JSON error.
     *
     * @param int $errno An error number from json_last_error()
     *
     * @throws DomainException
     *
     * @return void
     */
    private static function handleJsonError(int $errno) : void
    {
        $messages = [JSON_ERROR_DEPTH => 'Maximum stack depth exceeded', JSON_ERROR_STATE_MISMATCH => 'Invalid or malformed JSON', JSON_ERROR_CTRL_CHAR => 'Unexpected control character found', JSON_ERROR_SYNTAX => 'Syntax error, malformed JSON', JSON_ERROR_UTF8 => 'Malformed UTF-8 characters'];
        throw new DomainException(isset($messages[$errno]) ? $messages[$errno] : 'Unknown JSON error: ' . $errno);
    }
    /**
     * Get the number of bytes in cryptographic strings.
     *
     * @param string $str
     *
     * @return int
     */
    private static function safeStrlen(string $str) : int
    {
        if (\function_exists('mb_strlen')) {
            return \mb_strlen($str, '8bit');
        }
        return \strlen($str);
    }
    /**
     * Convert an ECDSA signature to an ASN.1 DER sequence
     *
     * @param   string $sig The ECDSA signature to convert
     * @return  string The encoded DER object
     */
    private static function signatureToDER(string $sig) : string
    {
        // Separate the signature into r-value and s-value
        $length = max(1, (int) (\strlen($sig) / 2));
        list($r, $s) = \str_split($sig, $length);
        // Trim leading zeros
        $r = \ltrim($r, "\x00");
        $s = \ltrim($s, "\x00");
        // Convert r-value and s-value from unsigned big-endian integers to
        // signed two's complement
        if (\ord($r[0]) > 0x7f) {
            $r = "\x00" . $r;
        }
        if (\ord($s[0]) > 0x7f) {
            $s = "\x00" . $s;
        }
        return self::encodeDER(self::ASN1_SEQUENCE, self::encodeDER(self::ASN1_INTEGER, $r) . self::encodeDER(self::ASN1_INTEGER, $s));
    }
    /**
     * Encodes a value into a DER object.
     *
     * @param   int     $type DER tag
     * @param   string  $value the value to encode
     *
     * @return  string  the encoded object
     */
    private static function encodeDER(int $type, string $value) : string
    {
        $tag_header = 0;
        if ($type === self::ASN1_SEQUENCE) {
            $tag_header |= 0x20;
        }
        // Type
        $der = \chr($tag_header | $type);
        // Length
        $der .= \chr(\strlen($value));
        return $der . $value;
    }
    /**
     * Encodes signature from a DER object.
     *
     * @param   string  $der binary signature in DER format
     * @param   int     $keySize the number of bits in the key
     *
     * @return  string  the signature
     */
    private static function signatureFromDER(string $der, int $keySize) : string
    {
        // OpenSSL returns the ECDSA signatures as a binary ASN.1 DER SEQUENCE
        list($offset, $_) = self::readDER($der);
        list($offset, $r) = self::readDER($der, $offset);
        list($offset, $s) = self::readDER($der, $offset);
        // Convert r-value and s-value from signed two's compliment to unsigned
        // big-endian integers
        $r = \ltrim($r, "\x00");
        $s = \ltrim($s, "\x00");
        // Pad out r and s so that they are $keySize bits long
        $r = \str_pad($r, $keySize / 8, "\x00", STR_PAD_LEFT);
        $s = \str_pad($s, $keySize / 8, "\x00", STR_PAD_LEFT);
        return $r . $s;
    }
    /**
     * Reads binary DER-encoded data and decodes into a single object
     *
     * @param string $der the binary data in DER format
     * @param int $offset the offset of the data stream containing the object
     * to decode
     *
     * @return array{int, string|null} the new offset and the decoded object
     */
    private static function readDER(string $der, int $offset = 0) : array
    {
        $pos = $offset;
        $size = \strlen($der);
        $constructed = \ord($der[$pos]) >> 5 & 0x1;
        $type = \ord($der[$pos++]) & 0x1f;
        // Length
        $len = \ord($der[$pos++]);
        if ($len & 0x80) {
            $n = $len & 0x1f;
            $len = 0;
            while ($n-- && $pos < $size) {
                $len = $len << 8 | \ord($der[$pos++]);
            }
        }
        // Value
        if ($type === self::ASN1_BIT_STRING) {
            $pos++;
            // Skip the first contents octet (padding indicator)
            $data = \substr($der, $pos, $len - 1);
            $pos += $len - 1;
        } elseif (!$constructed) {
            $data = \substr($der, $pos, $len);
            $pos += $len;
        } else {
            $data = null;
        }
        return [$pos, $data];
    }
}
}

namespace Firebase\JWT {
class SignatureInvalidException extends \UnexpectedValueException
{
}
}


/**
 * This file contains the client code for Vanilla jsConnect single sign on.
 *
 * @author Todd Burry <todd@vanillaforums.com>
 * @version 2.0
 * @copyright 2008-2020 Vanilla Forums, Inc.
 * @license MIT
 */

namespace {

    use Vanilla\JsConnect\JsConnectJSONP;

    function writeJsConnect($user, $request, $clientID, $secret, $secure = true) {
        JsConnectJSONP::writeJsConnect($user, $request, $clientID, $secret, $secure);
    }

    function signJsConnect($data, $clientID, $secret, $hashType, $returnData = false) {
        return JsConnectJSONP::signJsConnect($data, $clientID, $secret, $hashType, $returnData);
    }

    function jsHash($string, $secure = true) {
        return JsConnectJSONP::hash($string, $secure);
    }

    function jsTimestamp() {
        return JsConnectJSONP::timestamp();
    }

    function jsSSOString($user, $clientID, $secret) {
        return JsConnectJSONP::ssoString($user, $clientID, $secret);
    }

    function jsConnectContentType(array $request): string {
        return JsConnectJSONP::contentType($request);
    }
}
