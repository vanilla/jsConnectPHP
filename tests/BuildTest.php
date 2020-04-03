<?php
/**
 * @author Todd Burry <todd@vanillaforums.com>
 * @copyright 2009-2020 Vanilla Forums Inc.
 * @license MIT
 */

namespace Vanilla\JsConnect\Tests;

use PHPUnit\Framework\TestCase;

/**
 * Tests the build to ensure its integrity.
 */
class BuildTest extends TestCase {
    /**
     * Ensure that the dist build had been done.
     */
    public function testBuild() {
        $testPath = tempnam(sys_get_temp_dir(), ".jsconnect.php");
        exec(__DIR__.'/../build '.$testPath, $out, $return);
        $this->assertSame(0, $return);

        $this->assertFileEquals(__DIR__.'/../dist/functions.jsconnect.php', $testPath);
    }
}
