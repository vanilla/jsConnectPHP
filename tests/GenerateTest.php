<?php
/**
 * @author Todd Burry <todd@vanillaforums.com>
 * @copyright 2009-2020 Vanilla Forums Inc.
 * @license MIT
 */

namespace Vanilla\JsConnect\Tests;

use Firebase\JWT\ExpiredException;
use Firebase\JWT\JWT;
use Firebase\JWT\SignatureInvalidException;
use PHPUnit\Framework\TestCase;
use Vanilla\JsConnect\JsConnect;
use Vanilla\JsConnect\JsConnectServer;
use Vanilla\JsConnect\Tests\Fixtures\TestJsConnect;

/**
 * Tests that generate a JSON data file for other libraries to use.
 */
class GenerateTest extends TestCase {
    use JsConnectTestTrait;

    const TIMESTAMP = 1577836800;
    const NONCE = 'nonce';

    /**
     * @var JsConnectServer
     */
    private $jsc;

    /**
     * @inheritDoc
     */
    public function setUp() {
        parent::setUp();
        JWT::$timestamp = self::TIMESTAMP;
        $this->jsc = new TestJsConnect();
        $this->initializeJsConnect($this->jsc);

        $this->jsc
            ->setAuthenticateUrl('https://example.com/authenticate')
            ->setRedirectUrl('https://example.com/redirect');
    }

    /**
     * @inheritDoc
     */
    public function tearDown() {
        parent::tearDown();
        JWT::$timestamp = null;
    }

    /**
     * Write a specific test to the JSON file.
     *
     * @param string $name
     * @param string $jwt
     * @return array
     * @throws \Exception Throws an exception if the response is an exception response.
     */
    protected function writeTest(string $name, string $jwt): array {
        if ($this->jsc->isGuest()) {
            $user = new \stdClass();
        } else {
            $user = $this->jsc->getUser();
        }

        $data = [
            'jwt' => $jwt,
            'clientID' => $this->jsc->getSigningClientID(),
            'secret' => $this->jsc->getSigningSecret(),
            'version' => $this->jsc->getVersion(),
            'timestamp' => JWT::$timestamp,
            'user' => $this->jsc->isGuest() ? new \stdClass() : $this->jsc->getUser(),
        ];

        try {
            $url = $this->jsc->generateResponseLocation($jwt);
            $data += [
                'user' => $user,
                'response' => $url,
            ];
        } catch (\Exception $ex) {
            $exception = get_class($ex);
            $exception = substr($exception, strrpos($exception, '\\') + 1);

            $data += [
                'exception' => $exception,
                'message' => $ex->getMessage(),
            ];
        }

        $path = __DIR__.'/tests.json';
        if (file_exists($path)) {
            $json = (array)json_decode(file_get_contents($path));
            $this->assertNotNull($json);
        } else {
            $json = [];
        }

        $json[$name] = $data;
        ksort($json);
        $r = file_put_contents($path, json_encode($json, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES));
        $this->assertNotFalse($r);

        if (isset($ex)) {
            throw $ex;
        }

        return $data;
    }

    /**
     * @return string
     */
    protected function generateRequestJWT(array $state = []): string {
        [$url] = $this->jsc->generateRequest($state, self::NONCE);
        $jwt = $this->jwtFromUrl($url);
        return $jwt;
    }

    protected function generateTest($name, $state = []): array {
        $jwt = $this->generateRequestJWT($state);
        $r = $this->writeTest($name, $jwt);
        return $r;
    }

    /**
     * Test a basic successful flow.
     */
    public function testBasic() {
        $r = $this->generateTest('basic');
    }

    /**
     * Test a basic successful flow with a guest user.
     */
    public function testBasicGuest() {
        $this->jsc->setGuest(true);
        $this->generateTest('basic-guest');
    }

    /**
     * Test state passing through.
     */
    public function testBasicWithState() {
        $this->generateTest('basic-state', [JsConnect::FIELD_TARGET => '/foo']);
    }

    /**
     * Test an invalid secret.
     */
    public function testBadSecret() {
        $jwt = $this->generateRequestJWT();
        $this->jsc->setSigningCredentials($this->jsc->getSigningClientID(), 'foo');
        $this->expectException(SignatureInvalidException::class);
        $this->writeTest('bad-secret', $jwt);
    }

    /**
     * Test an expired token.
     */
    public function testExpiredToken() {
        $jwt = $this->generateRequestJWT();
        JWT::$timestamp += 1000000;
        $this->expectException(ExpiredException::class);
        $this->writeTest('expired-token', $jwt);
    }
}
