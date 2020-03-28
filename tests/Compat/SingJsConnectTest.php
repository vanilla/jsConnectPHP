<?php
/**
 * @author Alexandre (DaazKu) Chouinard <alexandre.c@vanillaforums.com>
 * @copyright 2009-2020 Vanilla Forums Inc.
 * @license GNU GPLv2 http://www.opensource.org/licenses/gpl-2.0.php
 */

namespace Vanilla\JsConnect\Tests\Compat;

use PHPUnit\Framework\TestCase;

/**
 * Unit tests signJsConnect
 */
class SignJsConnectTest extends TestCase {

    /**
     * @param $data
     * @param $clientID
     * @param $secret
     * @param $hashType
     * @param $returnData
     * @param $expectedResult
     *
     * @dataProvider provideSignJsConnectTests
     */
    public function testSignJsConnect($data, $clientID, $secret, $hashType, $returnData, $expectedResult) {
        $this->assertEquals(signJsConnect($data, $clientID, $secret, $hashType, $returnData), $expectedResult);
    }


    /**
     * Provide signature to sign
     *
     * @return array Returns a test array.
     */
    public function provideSignJsConnectTests() {
        return [
            'default' => [
                [
                    'name' => 'John PHP',
                    'email' => 'john.php@example.com',
                    'unique_id' => '123',
                ],
                'clientID',
                'secret',
                'sha256',
                false,
                '71528bfbb99aba97734f79beab6d1eca1416e05a0587e9ab55b99095753f74b6',
            ],
            'unordered' => [
                [
                    'unique_id' => '123',
                    'email' => 'john.php@example.com',
                    'name' => 'John PHP',
                ],
                'clientID',
                'secret',
                'sha256',
                false,
                '71528bfbb99aba97734f79beab6d1eca1416e05a0587e9ab55b99095753f74b6',
            ],
            'incorrectKeyCase' => [
                [
                    'Name' => 'John PHP',
                    'eMail' => 'john.php@example.com',
                    'UNIQUE_id' => '123',
                ],
                'clientID',
                'secret',
                'sha256',
                false,
                '71528bfbb99aba97734f79beab6d1eca1416e05a0587e9ab55b99095753f74b6',
            ],
            'trueAsHashType' => [
                [
                    'Name' => 'John PHP',
                    'eMail' => 'john.php@example.com',
                    'unique_id' => '123',
                ],
                'clientID',
                'secret',
                true,
                false,
                'f1639a1838bd904cb967423be0567802',
            ],
            'extraInfo' => [
                [
                    'unique_id' => '123',
                    'email' => 'john.php@example.com',
                    'name' => 'John PHP',
                    'custom_field' => 'custom',
                ],
                'clientID',
                'secret',
                'sha256',
                false,
                '72976aaaa96cb1acc94aa8c1638a0b3e10bb638e3985e25f60f6db79f65fcefb',
            ],
            'defaultReturnData' => [
                [
                    'name' => 'John PHP',
                    'email' => 'john.php@example.com',
                    'unique_id' => '123',
                ],
                'clientID',
                'secret',
                'sha256',
                true,
                [
                    'name' => 'John PHP',
                    'email' => 'john.php@example.com',
                    'unique_id' => '123',
                    'client_id' => 'clientID',
                    'sig' => '71528bfbb99aba97734f79beab6d1eca1416e05a0587e9ab55b99095753f74b6',
                ]
            ],
        ];
    }
}
