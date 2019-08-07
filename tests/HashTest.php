<?php
/**
 * @author Alexandre (DaazKu) Chouinard <alexandre.c@vanillaforums.com>
 * @copyright 2009-2017 Vanilla Forums Inc.
 * @license GNU GPLv2 http://www.opensource.org/licenses/gpl-2.0.php
 */

namespace JsConnect\Tests;

/**
 * Unit tests hashing
 */
class HashTest extends \PHPUnit\Framework\TestCase {

    /**
     *  Test {@link jsHash} with no $secure parameter.
     */
    public function testHashDefault() {
        $this->assertEquals(md5('hashMe'), jsHash('hashMe'));
    }

    /**
     *  Test {@link jsHash} with true as the $secure parameter.
     */
    public function testHashSecureTrue() {
        $this->assertEquals(md5('hashMe'), jsHash('hashMe', true));
    }

    /**
     *  Test {@link jsHash} with 'md5' as the $secure parameter.
     */
    public function testHashSecureMD5() {
        $this->assertEquals(md5('hashMe'), jsHash('hashMe', 'md5'));
    }

    /**
     *  Test {@link jsHash} with 'sha256' as the $secure parameter.
     */
    public function testHashSecureSHA256() {
        $this->assertEquals(hash('sha256', 'hashMe'), jsHash('hashMe', 'sha256'));
    }
}
