<?php
/**
 * @author Todd Burry <todd@vanillaforums.com>
 * @copyright 2009-2020 Vanilla Forums Inc.
 * @license MIT
 */

namespace Vanilla\JsConnect;

use Firebase\JWT\ExpiredException;
use Firebase\JWT\JWT;
use Vanilla\JsConnect\Exceptions\InvalidValueException;

class JsConnectServer extends JsConnect {
    const FIELD_NONCE = 'n';
    const FIELD_COOKIE = 'cookie';

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
     * @return $this
     */
    public function setKeyStore(\ArrayAccess $keystore) {
        $this->keys = $keystore;
        return $this;
    }

    /**
     * Generates a jsConnect request.
     *
     * @param array $state Additional state information.
     * @return array Returns an array in the format `[$requestUrl, $cookie]`.
     */
    public function generateRequest(array $state = []): array {
        if (isset($state[self::FIELD_COOKIE])) {
            // The cookie was already set. Make sure it's one of ours.
            try {
                $decodedCookie = $this->jwtDecode($state[self::FIELD_COOKIE]);
            } catch (ExpiredException $ex) {
                // The cookie was valid, but expired so issue a new one.
                goto GENERATE_COOKIE;
            } catch (\Exception $ex) {
                throw new InvalidValueException('Could not use supplied jsConnect SSO token: '.$ex->getMessage());
            }
            $nonce = self::validateFieldExists(self::FIELD_NONCE, $decodedCookie, 'ssoToken');
            $cookie = $state[self::FIELD_COOKIE];
            unset($state[self::FIELD_COOKIE]);
        } else {
            GENERATE_COOKIE:
            $nonce = JWT::urlsafeB64Encode(openssl_random_pseudo_bytes(15));
            $cookie = $this->jwtEncode([self::FIELD_NONCE => $nonce]);
        }

        $requestJWT = $this->jwtEncode([
            'st' => [
                self::FIELD_NONCE => $nonce,
            ] + $state,
            'rurl' => $this->getRedirectUrl(),
        ]);
        $requestUrl = $this->getAuthenticateUrlWithSeparator().http_build_query(['jwt' => $requestJWT]);

        return [$requestUrl, $cookie];
    }

    /**
     * Validate an SSO response.
     *
     * @param ?string $jwt The JWT to validate.
     * @param ?string $cookieJWT The cookie that was set using `JsConnectServer::generateRequest()`.
     * @return array Returns an array in the form: `[$user, $state, $fullPayload]`.
     * @throws Exceptions\FieldNotFoundException
     * @throws InvalidValueException
     */
    public function validateResponse(?string $jwt, ?string $cookieJWT): array {
        static::validateNotEmpty($jwt, 'SSO token');
        static::validateNotEmpty($cookieJWT, 'State cookie');

        $payload = $this->jwtDecode($jwt);
        $cookie = $this->jwtDecode($cookieJWT);

        $user = static::validateFieldExists(static::FIELD_USER, $payload, 'payload', false) ?: [];
        $state = static::validateFieldExists(static::FIELD_STATE, $payload);
        $cookieNonce = static::validateFieldExists(static::FIELD_NONCE, $cookie, 'cookie');
        $stateNonce = static::validateFieldExists(static::FIELD_NONCE, $state, 'state');

        if (!hash_equals($cookieNonce, $stateNonce)) {
            throw new InvalidValueException("The response nonce is invalid.");
        }

        return [$user, $state, $payload];
    }

    /**
     * Add a new key/secret pair that can be used to verify signatures.
     *
     * @param string $clientID
     * @param string $secret
     * @return $this
     */
    public function addKey(string $clientID, string $secret) {
        $this->keys[$clientID] = $secret;
        return $this;
    }

    /**
     * The URL on the client's site that will run the jsConnect client library.
     *
     * This URL is analogous to OAuth's authenticate URL.
     *
     * @return string
     */
    public function getAuthenticateUrl(): string {
        return $this->authenticateUrl;
    }

    /**
     * Get the authenticate URL with the proper query string separator.
     *
     * @return string
     */
    protected function getAuthenticateUrlWithSeparator(): string {
        return $this->authenticateUrl.(strpos($this->authenticateUrl, '?') === false ? '?' : '&');
    }

    /**
     * Set the URL on the client's site that will run the jsConnect client library.
     *
     * @param string $authenticateUrl
     * @return $this
     */
    public function setAuthenticateUrl(string $authenticateUrl) {
        $this->authenticateUrl = $authenticateUrl;
        return $this;
    }

    /**
     * The URL on Vanilla' that will process the client's authentication response.
     *
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
