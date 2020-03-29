<?php
/**
 * @author Todd Burry <todd@vanillaforums.com>
 * @copyright 2009-2020 Vanilla Forums Inc.
 * @license MIT
 */

namespace Vanilla\JsConnect;

use Firebase\JWT\JWT;
use Vanilla\JsConnect\Exceptions\FieldNotFoundException;
use Vanilla\JsConnect\Exceptions\InvalidValueException;

class JsConnectServer extends JsConnect {
    const FIELD_NONCE = 'n';

    /**
     * @var string
     */
    protected $authenticateUrl = '';

    /**
     * @var string
     */
    protected $redirectUrl = '';

    /**
     * Set the keystore that is used for validating and signing JWTs.
     *
     * @param \ArrayAccess $keystore
     */
    public function setKeyStore(\ArrayAccess $keystore) {
        $this->keys = $keystore;
    }

    /**
     * Generates a jsConnect request.
     *
     * @param array $state Additional state information.
     * @return array Returns an array in the format `[$requestUrl, $cookie]`.
     */
    public function generateRequest(array $state = []): array {
        $nonce = JWT::urlsafeB64Encode(openssl_random_pseudo_bytes(15));
        $cookie = $this->jwtEncode([self::FIELD_NONCE => $nonce]);

        $requestJWT = $this->jwtEncode([
            'st' => $state + [
                self::FIELD_NONCE => $nonce,
            ],
            'rurl' => $this->getRedirectUrl(),
        ]);
        $requestUrl = $this->getAuthenticateUrl().'?'.http_build_query(['jwt' => $requestJWT]);

        return [$requestUrl, $cookie];
    }

    public function validateResponse(string $jwt, string $cookieJWT): array {
        $payload = $this->jwtDecode($jwt);
        $cookie = $this->jwtDecode($cookieJWT);

        static::validateFieldExists(static::FIELD_USER, $payload);
        static::validateFieldExists(static::FIELD_STATE, $payload);
        static::validateFieldExists(static::FIELD_NONCE, $cookie, 'cookie');

        $user = $payload[static::FIELD_USER];
        $state = $payload[static::FIELD_STATE];

        static::validateFieldExists(static::FIELD_NONCE, $state, 'state');
        if (!hash_equals($cookie[static::FIELD_NONCE], $state[static::FIELD_NONCE])) {
            throw new InvalidValueException("The response nonce is invalid.");
        }

        return [$user, $state];
    }

    public function addSigningCredentials(string $clientID, string $secret) {
        $this->keys[$clientID] = $secret;
        return $this;
    }

    /**
     * @return string
     */
    public function getAuthenticateUrl(): string {
        return $this->authenticateUrl;
    }

    /**
     * @param string $authenticateUrl
     * @return $this
     */
    public function setAuthenticateUrl(string $authenticateUrl) {
        $this->authenticateUrl = $authenticateUrl;
        return $this;
    }

    /**
     * @return string
     */
    public function getRedirectUrl(): string {
        return $this->redirectUrl;
    }

    /**
     * @param string $redirectUrl
     * @return $this
     */
    public function setRedirectUrl(string $redirectUrl) {
        $this->redirectUrl = $redirectUrl;
        return $this;
    }
}
