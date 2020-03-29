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

    const TIMEOUT = 10 * 60;

    const ALLOWED_ALGORITHMS = [
        'ES256', 'HS256', 'HS384', 'HS512', 'RS256', 'RS384', 'RS512'
    ];
    const FIELD_STATE = 'st';
    const FIELD_USER = 'u';
    const FIELD_REDIRECT_URL = 'rurl';

    /**
     * @var \ArrayAccess
     */
    protected $keys;

    protected $signingClientID = '';

    protected $user = [];

    protected $signingAlgorithm;

    public function __construct() {
        $this->keys = new \ArrayObject();
        $this->setSigningAlgorithm('HS256');
    }

    /**
     * Set the current user's email address.
     *
     * @param string $email
     * @return $this
     */
    public function setEmail(string $email) {
        return $this->setField(self::FIELD_EMAIL, $email);
    }

    /**
     * Set the a field on the current user.
     *
     * @param string $key
     * @param $value
     * @return $this
     */
    public function setField(string $key, $value) {
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
        return $this->setField(self::FIELD_NAME, $name);
    }

    /**
     * Set the current user's avatar.
     *
     * @param string $photo
     * @return $this
     */
    public function setPhotoURL(string $photo) {
        return $this->setField(self::FIELD_PHOTO, $photo);
    }

    /**
     * Set the current user's unique ID.
     *
     * @param string $id
     * @return $this
     */
    public function setUniqueID(string $id) {
        return $this->setField(self::FIELD_UNIQUE_ID, $id);
    }

    /**
     * Handle the authentication request and redirect back to Vanilla.
     *
     * @param string $jwt
     */
    public function handleRequest(string $jwt) {
        try {
            $location = $this->generateResponseLocation($jwt);
            $this->redirect($location);
        } catch (Exception $ex) {
            echo htmlspecialchars($ex->getMessage());
        }
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

        // Generate the response token.
        $data = [
            self::FIELD_USER => $this->user,
            self::FIELD_STATE => $request[self::FIELD_STATE] ?? [],
        ];
        $response = $this->jwtEncode($data);

        $location = $request[self::FIELD_REDIRECT_URL] . '#' . http_build_query(['jwt' => $response]);
        return $location;
    }

    public function setSigningCredentials(string $clientID, string $secret) {
        $this->keys[$clientID] = $secret;
        $this->signingClientID = $clientID;
        return $this;
    }

    /**
     * Wrap a payload in a JWT.
     *
     * @param array $payload
     * @return string
     */
    protected function jwtEncode(array $payload): string {
        $payload += [
            'v' => self::VERSION,
            'exp' => $this->getTimestamp() + self::TIMEOUT,
        ];

        $jwt = JWT::encode($payload, $this->getSigningSecret(), $this->getSigningAlgorithm(), null, [
            'kid' => $this->getSigningClientID(),
        ]);
        return $jwt;
    }

    /**
     * @param string $jwt
     * @return array
     */
    protected function jwtDecode(string $jwt): array {
        $payload = JWT::decode($jwt, $this->keys, self::ALLOWED_ALGORITHMS);
        $payload = $this->stdClassToArray($payload);
        return $payload;
    }

    /**
     * @param array|object $o
     */
    protected function stdClassToArray($o): array {
        if (is_scalar($o)) {
            throw new \UnexpectedValueException("JsConnect::stdClassToArray() expects an object or array, scalar given.", 400);
        }

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
     * Get the client ID that is used to sign JWTs.
     *
     * @return string
     */
    protected function getSigningClientID(): string {
        return $this->signingClientID;
    }

    /**
     * Get the secret that is used to sign JWTs.
     *
     * @return string
     */
    protected function getSigningSecret(): string {
        return $this->keys[$this->signingClientID];
    }

    /**
     * @param string $location
     */
    protected function redirect(string $location) {
        header("Location: $location", true, 302);
    }

    public function getUser(): array {
        return $this->user;
    }

    /**
     * @return string
     */
    public function getSigningAlgorithm(): string {
        return $this->signingAlgorithm;
    }

    /**
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
     * Validate that a field exists in a collection.
     *
     * @param string $field The name of the field to validate.
     * @param mixed $collection The collection to look at.
     * @param string $collectionName The name of the collection.
     * @param bool $validateEmpty If true, make sure the value is also not empty.
     * @throws FieldNotFoundException
     * @throws InvalidValueException
     */
    protected static function validateFieldExists(string $field, $collection, string $collectionName = 'payload', bool $validateEmpty = true) {
        if (!(is_array($collection) || $collection instanceof \ArrayAccess)) {
            throw new InvalidValueException("The payload is not a valid array.", 400);
        }

        if (!isset($collection[$field])) {
            throw new FieldNotFoundException($field, $collectionName);
        }

        if ($validateEmpty && empty($collection[$field])) {
            throw new InvalidValueException("Field cannot be empty: {$collectionName}[{$field}]");
        }
    }
}
