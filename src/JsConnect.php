<?php
/**
 * @author Todd Burry <todd@vanillaforums.com>
 * @copyright 2009-2020 Vanilla Forums Inc.
 * @license MIT
 */

namespace Vanilla\JsConnect;

use Exception;
use Firebase\JWT\JWT;
use UnexpectedValueException;
use Vanilla\JsConnect\Exceptions\FieldNotFoundException;
use Vanilla\JsConnect\Exceptions\InvalidValueException;

/**
 * Handles the jsConnect protocol v3.x.
 */
class JsConnect {
    const VERSION = 'php:3';

    const FIELD_UNIQUE_ID = 'id';
    const FIELD_PHOTO = 'photo';
    const FIELD_NAME = 'name';
    const FIELD_EMAIL = 'email';
    const FIELD_ROLES = 'roles';
    const FIELD_JWT = 'jwt';

    const TIMEOUT = 10 * 60;

    const ALLOWED_ALGORITHMS = [
        'ES256', 'HS256', 'HS384', 'HS512', 'RS256', 'RS384', 'RS512'
    ];

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
    public function __construct() {
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
    protected static function validateNotEmpty($value, string $valueName): void {
        if ($value === null) {
            throw new InvalidValueException("$valueName is required.");
        }
        if (empty($value)) {
            throw new InvalidValueException("$valueName cannot be empty.");
        }
    }

    /**
     * Set the current user's email address.
     *
     * @param string $email
     * @return $this
     */
    public function setEmail(string $email) {
        return $this->setUserField(self::FIELD_EMAIL, $email);
    }

    /**
     * Set the a field on the current user.
     *
     * @param string $key The key on the user.
     * @param string|int|bool|array|null $value The value to set. This must be a basic type that can be JSON encoded.
     * @return $this
     */
    public function setUserField(string $key, $value) {
        $this->user[$key] = $value;
        return $this;
    }

    /**
     * Set the current user's username.
     *
     * @param string $name
     * @return $this
     */
    public function setName(string $name) {
        return $this->setUserField(self::FIELD_NAME, $name);
    }

    /**
     * Set the current user's avatar.
     *
     * @param string $photo
     * @return $this
     */
    public function setPhotoURL(string $photo) {
        return $this->setUserField(self::FIELD_PHOTO, $photo);
    }

    /**
     * Set the current user's unique ID.
     *
     * @param string $id
     * @return $this
     */
    public function setUniqueID(string $id) {
        return $this->setUserField(self::FIELD_UNIQUE_ID, $id);
    }

    /**
     * Handle the authentication request and redirect back to Vanilla.
     *
     * @param array $query
     */
    public function handleRequest(array $query): void {
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
    protected static function validateFieldExists(string $field, $collection, string $collectionName = 'payload', bool $validateEmpty = true) {
        if (!(is_array($collection) || $collection instanceof \ArrayAccess)) {
            throw new InvalidValueException("Invalid array: $collectionName");
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
    public function generateResponseLocation(string $requestJWT): string {
        // Validate the request token.
        $request = $this->jwtDecode($requestJWT);

        if ($this->isGuest()) {
            $data = [
                self::FIELD_USER => new \stdClass(),
                self::FIELD_STATE => $request[self::FIELD_STATE] ?? [],
            ];
        } else {
            // Generate the response token.
            $data = [
                self::FIELD_USER => $this->user,
                self::FIELD_STATE => $request[self::FIELD_STATE] ?? [],
            ];
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
    public function jwtDecode(string $jwt): array {
        /**
         * @psalm-suppress InvalidArgument
         */
        $payload = JWT::decode($jwt, $this->keys, self::ALLOWED_ALGORITHMS);
        $payload = $this->stdClassToArray($payload);
        return $payload;
    }

    /**
     * Convert an object to an array, recursively.
     *
     * @param array|object $o
     * @return array
     */
    protected function stdClassToArray($o): array {
        if (!is_array($o) && !($o instanceof \stdClass)) {
            throw new UnexpectedValueException("JsConnect::stdClassToArray() expects an object or array, scalar given.", 400);
        }

        $o = (array)$o;
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
    public function isGuest(): bool {
        return $this->guest;
    }

    /**
     * Set whether or not the user is signed in.
     *
     * @param bool $isGuest
     * @return $this
     */
    public function setGuest(bool $isGuest) {
        $this->guest = $isGuest;
        return $this;
    }

    /**
     * Wrap a payload in a JWT.
     *
     * @param array $payload
     * @return string
     */
    public function jwtEncode(array $payload): string {
        $payload += [
            'v' => $this->getVersion(),
            'iat' => $this->getTimestamp(),
            'exp' => $this->getTimestamp() + $this->getTimeout(),
        ];

        $jwt = JWT::encode($payload, $this->getSigningSecret(), $this->getSigningAlgorithm(), null, [
            self::FIELD_CLIENT_ID => $this->getSigningClientID(),
        ]);
        return $jwt;
    }

    /**
     * Get the current timestamp.
     *
     * This time is used for signing and verifying tokens.
     *
     * @return int
     */
    protected function getTimestamp(): int {
        $r = JWT::$timestamp ?: time();
        return $r;
    }

    /**
     * Get the secret that is used to sign JWTs.
     *
     * @return string
     */
    public function getSigningSecret(): string {
        return $this->keys[$this->signingClientID];
    }

    /**
     * Get the algorithm used to sign tokens.
     *
     * @return string
     */
    public function getSigningAlgorithm(): string {
        return $this->signingAlgorithm;
    }

    /**
     * Set the algorithm used to sign tokens.
     *
     * @param string $signingAlgorithm
     * @return $this
     */
    public function setSigningAlgorithm(string $signingAlgorithm) {
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
    public function getSigningClientID(): string {
        return $this->signingClientID;
    }

    /**
     * Redirect to a new location.
     *
     * @param string $location
     */
    protected function redirect(string $location): void {
        header("Location: $location", true, 302);
        die();
    }

    /**
     * Set the credentials that will be used to sign requests.
     *
     * @param string $clientID
     * @param string $secret
     * @return $this
     */
    public function setSigningCredentials(string $clientID, string $secret) {
        $this->keys[$clientID] = $secret;
        $this->signingClientID = $clientID;
        return $this;
    }

    public function getUser(): array {
        return $this->user;
    }

    /**
     * Set the roles on the user.
     *
     * @param array $roles
     * @return $this
     */
    public function setRoles(array $roles) {
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
    final public static function decodeJWTHeader(string $jwt): ?array {
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
    public function getVersion(): string {
        return self::VERSION;
    }

    /**
     * Get the JWT expiry timeout.
     *
     * @return int
     */
    public function getTimeout(): int {
        return $this->timeout;
    }

    /**
     * Set the JWT expiry timeout.
     *
     * @param int $timeout
     * @return $this
     */
    public function setTimeout(int $timeout) {
        $this->timeout = $timeout;
        return $this;
    }
}
