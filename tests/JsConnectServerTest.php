<?php
/**
 * @author Todd Burry <todd@vanillaforums.com>
 * @copyright 2009-2020 Vanilla Forums Inc.
 * @license MIT
 */

namespace Vanilla\JsConnect\Tests;

use PHPUnit\Framework\TestCase;
use Vanilla\JsConnect\Exceptions\InvalidValueException;
use Vanilla\JsConnect\JsConnectServer;

/**
 * Tests for the `JsConnectServer` class.
 */
class JsConnectServerTest extends TestCase {
    use JsConnectTestTrait;

    private $jsc;

    /**
     * {@inheritDoc}
     */
    public function setUp() {
        parent::setUp();
        $this->jsc = new JsConnectServer();
        $this->initializeJsConnect($this->jsc);

        $this->jsc
            ->setAuthenticateUrl('https://example.com/authenticate')
            ->setRedirectUrl('https://example.com/redirect');
    }

    /**
     * Test a full SSO flow.
     */
    public function testBasicHappyFlow() {
        // 1. Vanilla generate the request.
        list($requestUrl, $cookie) = $this->jsc->generateRequest();

        // 2. The client authenticates the request and generates a response.
        $responseLocation = $this->jsc->generateResponseLocation($this->jwtFromUrl($requestUrl));

        // 3. Vanilla verifies the response.
        list($user) = $this->jsc->validateResponse(
            $this->jwtFromUrl($responseLocation, PHP_URL_FRAGMENT),
            $cookie
        );

        $this->assertSame($this->jsc->getUser(), $user);
    }

    /**
     * Test a full SSO flow with a signed out user (guest).
     */
    public function testGuestHappyFlow() {
        // 1. Vanilla generate the request.
        list($requestUrl, $cookie) = $this->jsc->generateRequest();

        // 2. The client authenticates the request and generates a response.
        $this->jsc->setGuest(true);
        $responseLocation = $this->jsc->generateResponseLocation($this->jwtFromUrl($requestUrl));

        // 3. Vanilla verifies the response.
        list($user, $state) = $this->jsc->validateResponse(
            $this->jwtFromUrl($responseLocation, PHP_URL_FRAGMENT),
            $cookie
        );

        $this->assertEmpty($user);
    }

    /**
     * Test an SSO flow that should fail due to an invalid nonce.
     */
    public function testInvalidNonce() {
        // 1. Vanilla generate the request.
        list($requestUrl1, $cookie1) = $this->jsc->generateRequest();
        list($requestUrl2, $cookie2) = $this->jsc->generateRequest();

        // 2. The client authenticates the request and generates a response.
        $responseLocation = $this->jsc->generateResponseLocation($this->jwtFromUrl($requestUrl1));

        // 3. Vanilla verifies the response.
        $this->expectException(InvalidValueException::class);
        $this->expectExceptionMessage('The response nonce is invalid.');
        list($user, $state) = $this->jsc->validateResponse(
            $this->jwtFromUrl($responseLocation, PHP_URL_FRAGMENT),
            $cookie2
        );
    }

    /**
     * Test an SSO flow that should fail due to a missing cookie.
     */
    public function testMissingCookie() {
        // 1. Vanilla generate the request.
        list($requestUrl, $cookie) = $this->jsc->generateRequest();

        // 2. The client authenticates the request and generates a response.
        $responseLocation = $this->jsc->generateResponseLocation($this->jwtFromUrl($requestUrl));

        // 3. Vanilla verifies the response.
        $this->expectException(InvalidValueException::class);
        $this->expectExceptionMessage('State cookie cannot be empty.');
        $this->jsc->validateResponse(
            $this->jwtFromUrl($responseLocation, PHP_URL_FRAGMENT),
            ''
        );
    }
}
