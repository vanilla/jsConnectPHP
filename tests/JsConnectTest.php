<?php
/**
 * @author Todd Burry <todd@vanillaforums.com>
 * @copyright 2009-2020 Vanilla Forums Inc.
 * @license MIT
 */

namespace Vanilla\JsConnect\Tests;

use Firebase\JWT\JWT;
use PHPUnit\Framework\TestCase;
use Vanilla\JsConnect\Exceptions\FieldNotFoundException;
use Vanilla\JsConnect\Exceptions\InvalidValueException;
use Vanilla\JsConnect\JsConnect;
use Vanilla\JsConnect\Tests\Fixtures\TestJsConnect;

/**
 * Tests for the `JsConnect` class.
 *
 * Class JsConnectTest
 * @package Vanilla\JsConnect\Tests
 */
class JsConnectTest extends TestCase {
    private $jsc;

    /**
     * {@inheritDoc}
     */
    public function setUp(): void {
        parent::setUp();
        $this->jsc = new TestJsConnect();
        $this->jsc->setSigningCredentials('foo', 'bar');
    }

    /**
     * Test signing algorithm access.
     */
    public function testSigningAlgorithmAccess() {
        $this->jsc->setSigningAlgorithm('HS512');
        $this->assertSame('HS512', $this->jsc->getSigningAlgorithm());
    }

    /**
     * A whitelist of signing algorithms are allowed.
     */
    public function testInvalidSigningAlgorithm() {
        $this->expectException(\UnexpectedValueException::class);
        $this->jsc->setSigningAlgorithm('none');
    }

    /**
     * Test field validation.
     */
    public function testValidateFieldExistsBadCollection() {
        $this->expectException(InvalidValueException::class);
        $this->expectExceptionMessage('Invalid array: baz');
        TestJsConnect::validateFieldExists('foo', 'bar', 'baz');
    }

    /**
     * A missing key should be a specific exception.
     */
    public function testValidateFieldExistsFieldNotSet() {
        $this->expectException(FieldNotFoundException::class);
        $this->expectExceptionMessage("Missing field: bar[foo]");
        TestJsConnect::validateFieldExists('foo', [], 'bar');
    }

    /**
     * An empty value should be a specific exception.
     */
    public function testValidateFieldExistsFieldEmpty() {
        $this->expectException(InvalidValueException::class);
        $this->expectExceptionMessage("Field cannot be empty: bar[foo]");
        TestJsConnect::validateFieldExists('foo', ['foo' => ''], 'bar');
    }

    /**
     * A supplied field should NOT be an exception.
     */
    public function testValidateFieldExistsFieldEmptyOK() {
        $actual = TestJsConnect::validateFieldExists('foo', ['foo' => ''], 'bar', false);
        $this->assertSame('', $actual);
    }

    /**
     * Test a basic use of JWT header decoding.
     */
    public function testDecodeHeader() {
        $expected = ['foo' => 'bar'];

        $jwt = JWT::encode([], 'foo', 'HS256', 'kid', $expected);
        $actual = JsConnect::decodeJWTHeader($jwt);
        $this->assertSame($expected, array_intersect($expected, $actual));
    }
}
