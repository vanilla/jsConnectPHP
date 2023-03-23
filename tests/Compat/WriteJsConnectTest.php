<?php
/**
 * @author Alexandre (DaazKu) Chouinard <alexandre.c@vanillaforums.com>
 * @copyright 2009-2020 Vanilla Forums Inc.
 * @license GNU GPLv2 http://www.opensource.org/licenses/gpl-2.0.php
 */

namespace Vanilla\JsConnect\Tests\Compat;

use PHPUnit\Framework\TestCase;
use Vanilla\JsConnect\JsConnectJSONP;

/**
 * Unit tests signJsConnect
 */
class WriteJsConnectTest extends TestCase
{
    /**
     * @param $user
     * @param $request
     * @param $clientID
     * @param $secret
     * @param $secure
     * @param $expectedResult
     *
     * @dataProvider provideWriteJsConnectTests
     */
    public function testWriteJsConnect(
        $user,
        $request,
        $clientID,
        $secret,
        $secure,
        $expectedResult
    ) {
        ob_start();
        writeJsConnect($user, $request, $clientID, $secret, $secure);
        $result = ob_get_contents();
        ob_end_clean();

        $result = json_decode($result, true);
        ksort($result);

        $this->assertEquals($result, $expectedResult);
    }

    /**
     * Provide signature to sign
     *
     * @return array Returns a test array.
     */
    public function provideWriteJsConnectTests()
    {
        $clientID = "clientID";
        $timestamp = time();
        $secret = "secret";
        $ip = "127.0.0.1";
        $secure = "sha256";
        $nonce = "nonceToken";
        $sig = jsHash($ip . $nonce . $timestamp . $secret, $secure);
        $version = "2";

        $userData = [
            "name" => "John PHP",
            "email" => "john.php@example.com",
            "unique_id" => "123",
        ];

        $fnGenerateTestData = function () use (
            &$userData,
            &$clientID,
            &$timestamp,
            &$secret,
            &$ip,
            &$secure,
            &$nonce,
            &$sig,
            &$version
        ) {
            $request = [
                "client_id" => $clientID,
                "ip" => $ip,
                "nonce" => $nonce,
                "sig" => $sig,
                "timestamp" => $timestamp,
                "v" => $version,
            ];

            $expectedResult =
                [
                    "sig" => signJsConnect(
                        $userData + ["ip" => $ip, "nonce" => $nonce],
                        $clientID,
                        $secret,
                        $secure
                    ),
                ] +
                $request +
                $userData;
            unset($expectedResult["timestamp"]);
            ksort($expectedResult);

            return [
                "userData" => $userData,
                "request" => $request,
                "clientID" => $clientID,
                "secret" => $secret,
                "secure" => $secure,
                "expectedResult" => $expectedResult,
            ];
        };

        $fnGenerateAlteratedData = function (
            &$var,
            $value,
            $expectedResult
        ) use ($fnGenerateTestData) {
            $tmpVar = $var;
            $var = $value;
            $data = $fnGenerateTestData();
            $var = $tmpVar;
            $data["expectedResult"] = $expectedResult;
            return $data;
        };

        $data = [];
        // Default
        $data["default"] = $fnGenerateTestData();

        // Wrong version
        $data["wrongVersion"] = $fnGenerateAlteratedData($version, 1, [
            "error" => "invalid_request",
            "message" => "Unsupported version 1.",
        ]);

        // Missings
        $missings = ["v", "client_id", "sig", "nonce", "ip"];
        foreach ($missings as $missing) {
            $tmp = $fnGenerateTestData();
            unset($tmp["request"][$missing]);
            $tmp["expectedResult"] = [
                "error" => "invalid_request",
                "message" => "Missing the $missing parameter.",
            ];
            $data["missing[$missing]"] = $tmp;
        }

        // Missing timestamp
        $tmp = $fnGenerateTestData();
        unset($tmp["request"]["timestamp"]);
        $tmp["expectedResult"] = [
            "error" => "invalid_request",
            "message" => "The timestamp parameter is missing or invalid.",
        ];
        $data["missing[timestamp]"] = $tmp;

        // Non numeric timestamp
        $data["invalidTimestamp"] = $fnGenerateAlteratedData(
            $timestamp,
            "notatimestamp",
            [
                "error" => "invalid_request",
                "message" => "The timestamp parameter is missing or invalid.",
            ]
        );

        // Timed Out timestamp
        $data["timedOutTimestamp"] = $fnGenerateAlteratedData(
            $timestamp,
            $timestamp - (JsConnectJSONP::TIMEOUT + 1),
            [
                "error" => "invalid_request",
                "message" => "The timestamp is invalid.",
            ]
        );

        // Bad client_id
        $tmp = $fnGenerateTestData();
        $tmp["request"]["client_id"] = "wrong" . $clientID;
        $tmp["expectedResult"] = [
            "error" => "invalid_client",
            "message" => "Unknown client {$tmp["request"]["client_id"]}.",
        ];
        $data["wrongClientID"] = $tmp;

        // No sig, no timestamp sent with user logged
        $tmp = $fnGenerateTestData();
        unset($tmp["request"]["sig"], $tmp["request"]["timestamp"]);
        $tmp["expectedResult"] = [
            "name" => "John PHP",
            "photourl" => null,
            "signedin" => true,
        ];
        $data["noSigNoTimestamp"] = $tmp;

        // No sig, no timestamp sent with user not logged
        $tmp = $fnGenerateTestData();
        $tmp["userData"] = [];
        unset($tmp["request"]["sig"], $tmp["request"]["timestamp"]);
        $tmp["expectedResult"] = ["name" => "", "photourl" => ""];
        $data["noSigNoTimestamp"] = $tmp;

        // Bad signature
        $data["badSignature"] = $fnGenerateAlteratedData(
            $ip,
            "255.255.255.255",
            ["error" => "access_denied", "message" => "Signature invalid."]
        );

        // Secure disabled
        $data["timedOutTimestamp"] = $fnGenerateAlteratedData(
            $secure,
            null,
            $userData
        );

        return $data;
    }
}
