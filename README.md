 # SNMP Utils
 
 This bundle is based on main class of [opensolutions/OSS_SNMP](https://github.com/opensolutions/OSS_SNMP) project.
 Is a lightweight fork for simple get() and set() things.
 
 ## Installation
 
 Install the latest version with [composer](https://packagist.org/packages/mrcnpdlk/snmp)
 ```bash
 composer require mrcnpdlk/snmp
 ```
 
 ## Basic usage

```php
use Mrcnpdlk\Lib\Snmp\Agent;
use Mrcnpdlk\Lib\Snmp\Config;
use Mrcnpdlk\Lib\Snmp\Enum\Version;

require __DIR__ . '/../vendor/autoload.php';

$oConfig = new Config([
    'host'      => '10.0.10.10',
    'community' => 'some_community',
    'version'   => Version::VER_1,
    'mibFiles'  => [__DIR__ . '/some_mib_file.MIB'],
]);

$oSnmp = new Agent($oConfig);

var_dump($oSnmp->get('masterVoltageL2.0'));
```
