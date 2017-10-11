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
$oSnmp = new mrcnpdlk\Snmp\Agent(
    __IP__,
    __USER__,
    \mrcnpdlk\Snmp\Agent::SNMP_VER_3,
    \mrcnpdlk\Snmp\Agent::SEC_LEVEL_AUTH_NO_PRIV,
    \mrcnpdlk\Snmp\Agent::SEC_LEVEL_MD5,
    __PASS__);

# If you need import external MIB file just do it
$oSnmp->importMibFile(__DIR__.'/mibs/SNMPv2-MIB.mib');

$res = $oSnmp->get('SNMPv2-SMI::enterprises.2024.1.2.??????');
```
