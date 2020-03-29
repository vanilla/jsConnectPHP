<?php
/**
 * @author Todd Burry <todd@vanillaforums.com>
 * @copyright 2009-2020 Vanilla Forums Inc.
 * @license MIT
 */

namespace Vanilla\JsConnect\Tests;


use PHPUnit\Framework\TestCase;
use Vanilla\JsConnect\JsConnect;

class JsConnectTest extends TestCase {
    private $jsc;

    public function setUp() {
        parent::setUp();
        $this->jsc = new JsConnect();
        $this->jsc->setSigningCredentials('foo', 'bar');
    }

    public function testSigningAlgorithmAccess() {
        $this->jsc->setSigningAlgorithm('HS512');
        $this->assertSame('HS512', $this->jsc->getSigningAlgorithm());
    }

    public function testInvalidSigningAlgorithm() {
        $this->expectException(\UnexpectedValueException::class);
        $this->jsc->setSigningAlgorithm('none');
    }
}
