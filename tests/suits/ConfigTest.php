<?php
/**
 * Created by Marcin.
 * Date: 03.03.2019
 * Time: 16:52
 */

namespace Tests\Mrcnpdlk\Lib\Snmp;

use Mrcnpdlk\Lib\Snmp\Config;
use Mrcnpdlk\Lib\Snmp\Enum\Version;
use PHPUnit\Framework\TestCase;

class ConfigTest extends TestCase
{
    /**
     * @throws \Mrcnpdlk\Lib\ConfigurationException
     */
    public function testConfig(): void
    {
        new Config([
            'host'      => '10.0.10.10',
            'community' => 'some_community',
            'version'   => Version::VER_1,
        ]);
        $this->assertTrue(true);
    }
}
