<?php

declare(strict_types=1);
/**
 * SNMP
 *
 * Copyright (c) 2017 pudelek.org.pl
 *
 * @license MIT License (MIT)
 *
 * For the full copyright and license information, please view source file
 * that is bundled with this package in the file LICENSE
 * @author  Marcin Pudełek <marcin@pudelek.org.pl>
 */

namespace Mrcnpdlk\Lib\Snmp;

use Mrcnpdlk\Lib\Snmp\Enum\Version;

/**
 * Class Agent
 *
 * @see    https://github.com/opensolutions/OSS_SNMP[opensolutions/OSS_SNMP]
 *
 * Contact: Barry O'Donovan - barry (at) opensolutions (dot) ie
 * @see    http://www.opensolutions.ie/
 */
class Agent
{
    /**
     * A variable to hold the last unaltered result of an SNMP query
     *
     * @var mixed|null The last unaltered result of an SNMP query
     */
    protected $_lastResult = null;
    /**
     * @var \Mrcnpdlk\Lib\Snmp\Config
     */
    private $oConfig;

    /**
     * The constructor.
     *
     * @param \Mrcnpdlk\Lib\Snmp\Config $oConfig
     */
    public function __construct(Config $oConfig)
    {
        snmp_set_oid_output_format(SNMP_OID_OUTPUT_FULL);
        $this->oConfig = $oConfig;
    }

    /**
     * Get a single SNMP value
     *
     * @param string $oid The OID to get
     *
     * @throws Exception On *any* SNMP error, warnings are supressed and a generic exception is thrown
     *
     * @return mixed The resultant value
     */
    public function get(string $oid)
    {
        switch ($this->oConfig->getVersion()->getValue()) {
            case Version::VER_1:
                $this->_lastResult = @snmpget(
                    $this->oConfig->getHost(),
                    $this->oConfig->getCommunity(),
                    $oid,
                    $this->oConfig->getTimeout(),
                    $this->oConfig->getRetry());
                break;
            case  Version::VER_2C:
                $this->_lastResult = @snmp2_get(
                    $this->oConfig->getHost(),
                    $this->oConfig->getCommunity(),
                    $oid,
                    $this->oConfig->getTimeout(),
                    $this->oConfig->getRetry());
                break;
            case  Version::VER_3:
                $this->_lastResult = @snmp3_get(
                    $this->oConfig->getHost(),
                    $this->oConfig->getSecName(),
                    $this->oConfig->getSecLevel()->getValue(),
                    $this->oConfig->getAuthProtocol()->getValue(),
                    $this->oConfig->getAuthPassphrase(),
                    $this->oConfig->getPrivProtocol()->getValue(),
                    $this->oConfig->getPrivPassphrase(),
                    $oid, $this->oConfig->getTimeout(),
                    $this->oConfig->getRetry()
                );
                break;
            default:
                throw new Exception('Invalid SNMP version: ' . $this->oConfig->getVersion());
        }
        if (false === $this->_lastResult) {
            throw new Exception('Could not perform walk for OID ' . $oid);
        }

        return $this->parseSnmpValue($this->_lastResult);
    }

    /**
     * Returns the unaltered original last SNMP result
     *
     * @return mixed The unaltered original last SNMP result
     */
    public function getLastResult()
    {
        return $this->_lastResult;
    }

    /**
     * Parse the result of an SNMP query into a PHP type
     *
     * For example, [STRING: "blah"] is parsed to a PHP string containing: blah
     *
     * @param string $v The value to parse
     *
     * @throws \Mrcnpdlk\Lib\Snmp\Exception
     *
     * @return mixed The parsed value
     */
    public function parseSnmpValue(string $v)
    {
        // first, rule out an empty string
        if ('""' === $v || '' === $v) {
            return '';
        }
        $type  = substr($v, 0, strpos($v, ':'));
        $value = trim(substr($v, strpos($v, ':') + 1));
        switch ($type) {
            case 'STRING':
                if (0 === strpos($value, '"')) {
                    $rtn = (string)trim(substr(substr($value, 1), 0, -1));
                } else {
                    $rtn = (string)$value;
                }
                break;
            case 'INTEGER':
                if (!is_numeric($value)) {
                    // find the first digit and offset the string to that point
                    // just in case there is some mib strangeness going on
                    preg_match('/\d/', $value, $m, PREG_OFFSET_CAPTURE);
                    $rtn = (int)substr($value, $m[0][1]);
                } else {
                    $rtn = (int)$value;
                }
                break;
            case 'Counter64':
            case 'Gauge32':
            case 'Counter32':
                $rtn = (int)$value;
                break;
            case 'Hex-STRING':
                $rtn = (string)implode('', explode(' ', preg_replace('/[^A-Fa-f0-9]/', '', $value)));
                break;
            case 'OID':
            case 'IpAddress':
                $rtn = (string)$value;
                break;
            case 'Timeticks':
                $rtn = (int)substr($value, 1, strrpos($value, ')') - 1);
                break;
            default:
                throw new Exception("ERR: Unhandled SNMP return type: $type\n");
        }

        return $rtn;
    }

    /**
     * Proxy to the snmp2_real_walk command
     *
     * @param string $oid The OID to walk
     *
     * @throws \Mrcnpdlk\Lib\Snmp\Exception
     *
     * @return array<mixed>|false The results of the walk
     */
    public function realWalk(string $oid)
    {
        switch ($this->oConfig->getVersion()->getValue()) {
            case Version::VER_1:
                return $this->_lastResult = @snmprealwalk(
                    $this->oConfig->getHost(),
                    $this->oConfig->getCommunity(),
                    $oid,
                    $this->oConfig->getTimeout(),
                    $this->oConfig->getRetry()
                );
            case Version::VER_2C:
                return $this->_lastResult = @snmp2_real_walk(
                    $this->oConfig->getHost(),
                    $this->oConfig->getCommunity(),
                    $oid,
                    $this->oConfig->getTimeout(),
                    $this->oConfig->getRetry()
                );
            case Version::VER_3:
                return $this->_lastResult = @snmp3_real_walk(
                    $this->oConfig->getHost(),
                    $this->oConfig->getSecName(),
                    $this->oConfig->getSecLevel()->getValue(),
                    $this->oConfig->getAuthProtocol()->getValue(),
                    $this->oConfig->getAuthPassphrase(),
                    $this->oConfig->getPrivProtocol()->getValue(),
                    $this->oConfig->getPrivPassphrase(),
                    $oid,
                    $this->oConfig->getTimeout(),
                    $this->oConfig->getRetry()
                );
            default:
                throw new Exception('Invalid SNMP version: ' . $this->oConfig->getVersion());
        }
    }

    /**
     * Set the value of an SNMP object
     *
     * @param string $oid   The OID to set
     * @param string $type  The MIB defines the type of each object id
     * @param mixed  $value The new value
     *
     * @throws Exception
     *
     * @return mixed
     */
    public function set(string $oid, string $type, $value)
    {
        switch ($this->oConfig->getVersion()->getValue()) {
            case Version::VER_1:
                $this->_lastResult = @snmpset(
                    $this->oConfig->getHost(),
                    $this->oConfig->getCommunitySet(),
                    $oid,
                    $type,
                    $value,
                    $this->oConfig->getTimeout(),
                    $this->oConfig->getRetry()
                );
                break;
            case Version::VER_2C:
                $this->_lastResult = @snmp2_set(
                    $this->oConfig->getHost(),
                    $this->oConfig->getCommunitySet(),
                    $oid,
                    $type,
                    $value,
                    $this->oConfig->getTimeout(),
                    $this->oConfig->getRetry()
                );
                break;
            case Version::VER_3:
                $this->_lastResult = @snmp3_set(
                    $this->oConfig->getHost(),
                    $this->oConfig->getSecName(),
                    $this->oConfig->getSecLevel()->getValue(),
                    $this->oConfig->getAuthProtocol()->getValue(),
                    $this->oConfig->getAuthPassphrase(),
                    $this->oConfig->getPrivProtocol()->getValue(),
                    $this->oConfig->getPrivPassphrase(),
                    $oid,
                    $type,
                    $value,
                    $this->oConfig->getTimeout(),
                    $this->oConfig->getRetry()
                );
                break;
            default:
                throw new Exception('Invalid SNMP version: ' . $this->oConfig->getVersion());
        }
        if (false === $this->_lastResult) {
            throw new Exception('Could not add variable ' . $value . ' for OID ' . $oid);
        }

        return $this->_lastResult;
    }

    /**
     * Get indexed SNMP values where the array key is the given position of the OID
     *
     * I.e. the following query with sample results:
     *
     * subOidWalk( '.1.3.6.1.4.1.9.9.23.1.2.1.1.9', 15 )
     *
     *
     *       .1.3.6.1.4.1.9.9.23.1.2.1.1.9.10101.5 = Hex-STRING: 00 00 00 01
     *       .1.3.6.1.4.1.9.9.23.1.2.1.1.9.10105.2 = Hex-STRING: 00 00 00 01
     *       .1.3.6.1.4.1.9.9.23.1.2.1.1.9.10108.4 = Hex-STRING: 00 00 00 01
     *
     * would yield an array:
     *
     *      10101 => Hex-STRING: 00 00 00 01
     *      10105 => Hex-STRING: 00 00 00 01
     *      10108 => Hex-STRING: 00 00 00 01
     *
     * subOidWalk( '.1.3.6.1.2.1.17.4.3.1.1', 15, -1 )
     *
     *        .1.3.6.1.2.1.17.4.3.1.1.0.0.136.54.152.12 = Hex-STRING: 00 00 75 33 4E 92
     *        .1.3.6.1.2.1.17.4.3.1.1.8.3.134.58.182.16 = Hex-STRING: 00 00 75 33 4E 93
     *        .1.3.6.1.2.1.17.4.3.1.1.0.4.121.22.55.8 = Hex-STRING: 00 00 75 33 4E 94
     *
     * would yield an array:
     *        [54.152.12] => Hex-STRING: 00 00 75 33 4E 92
     *        [58.182.16] => Hex-STRING: 00 00 75 33 4E 93
     *        [22.55.8]   => Hex-STRING: 00 00 75 33 4E 94
     *
     * @param string $oid      The OID to walk
     * @param int    $position The position of the OID to use as the key
     * @param int    $elements Number of additional elements to include in the returned array keys after $position.
     *                         This defaults to 1 meaning just the requested OID element (see examples above).
     *                         With -1, retrieves ALL to the end.
     *                         If there is less elements than $elements, return all availables (no error).
     *
     * @throws \Mrcnpdlk\Lib\Snmp\Exception
     *
     * @return array<mixed> On *any* SNMP error, warnings are supressed and a generic exception is thrown
     */
    public function subOidWalk(string $oid, int $position, int $elements = 1): array
    {
        $this->_lastResult = $this->realWalk($oid);
        if (false === $this->_lastResult) {
            throw new Exception('Could not perform walk for OID ' . $oid);
        }
        $result = [];
        foreach ($this->_lastResult as $_oid => $value) {
            $oids  = explode('.', $_oid);
            $index = $oids[$position];
            for ($pos = $position + 1; $pos < count($oids) && (-1 === $elements || $pos < $position + $elements); ++$pos) {
                $index .= '.' . $oids[$pos];
            }
            $result[$index] = $this->parseSnmpValue($value);
        }

        return $result;
    }

    /**
     * Get indexed SNMP values where the array key is spread over a number of OID positions
     *
     * @param string $oid       The OID to walk
     * @param int    $positionS The start position of the OID to use as the key
     * @param int    $positionE The end position of the OID to use as the key
     *
     * @throws \Mrcnpdlk\Lib\Snmp\Exception
     *
     * @return array<mixed> On *any* SNMP error, warnings are supressed and a generic exception is thrown
     */
    public function subOidWalkLong(string $oid, int $positionS, int $positionE): array
    {
        $this->_lastResult = $this->realWalk($oid);
        if (false === $this->_lastResult) {
            throw new Exception('Could not perform walk for OID ' . $oid);
        }
        $result = [];
        foreach ($this->_lastResult as $_oid => $value) {
            $oids   = explode('.', $_oid);
            $oidKey = '';
            for ($i = $positionS; $i <= $positionE; ++$i) {
                $oidKey .= $oids[$i] . '.';
            }
            $result[$oidKey] = $this->parseSnmpValue($value);
        }

        return $result;
    }

    /**
     * Get indexed SNMP values (first degree)
     *
     * Walks the SNMP tree returning an array of key => value pairs.
     *
     * This is a first degree walk and it will throw an exception if there is more that one degree of values.
     *
     * I.e. the following query with sample results:
     *
     * walk1d( '.1.0.8802.1.1.2.1.3.7.1.4' )
     *
     *       .1.0.8802.1.1.2.1.3.7.1.4.1 = STRING: "GigabitEthernet1/0/1"
     *       .1.0.8802.1.1.2.1.3.7.1.4.2 = STRING: "GigabitEthernet1/0/2"
     *       .1.0.8802.1.1.2.1.3.7.1.4.3 = STRING: "GigabitEthernet1/0/3"
     *       .....
     *
     * would yield an array:
     *
     *      1 => GigabitEthernet1/0/1
     *      2 => GigabitEthernet1/0/2
     *      3 => GigabitEthernet1/0/3
     *
     * @param string $oid The OID to walk
     *
     * @throws \Mrcnpdlk\Lib\Snmp\Exception
     *
     * @return array<mixed> The resultant values
     */
    public function walk1d(string $oid): array
    {
        $this->_lastResult = $this->realWalk($oid);
        if (false === $this->_lastResult) {
            throw new Exception('Could not perform walk for OID ' . $oid);
        }
        $result    = [];
        $oidPrefix = null;
        foreach ($this->_lastResult as $_oid => $value) {
            if (null !== $oidPrefix && 0 !== strpos($_oid, $oidPrefix)) {
                throw new Exception('Requested OID tree is not a first degree indexed SNMP value');
            }
            $oidPrefix = substr($_oid, 0, strrpos($_oid, '.'));

            $result[substr($_oid, strrpos($_oid, '.') + 1)] = $this->parseSnmpValue($value);
        }

        return $result;
    }

    /**
     * Get indexed SNMP values where they are indexed by IPv4 addresses
     *
     * I.e. the following query with sample results:
     *
     * subOidWalk( '.1.3.6.1.2.1.15.3.1.1. )
     *
     *
     *       .1.3.6.1.2.1.15.3.1.1.10.20.30.4 = IpAddress: 192.168.10.10
     *       ...
     *
     * would yield an array:
     *
     *      [10.20.30.4] => "192.168.10.10"
     *      ....
     *
     * @param string $oid The OID to walk
     *
     * @throws \Mrcnpdlk\Lib\Snmp\Exception
     *
     * @return array<mixed> On *any* SNMP error, warnings are supressed and a generic exception is thrown
     */
    public function walkIPv4(string $oid): array
    {
        $this->_lastResult = $this->realWalk($oid);
        if (false === $this->_lastResult) {
            throw new Exception('Could not perform walk for OID ' . $oid);
        }
        $result = [];
        foreach ($this->_lastResult as $_oid => $value) {
            $oids                                                                                            = explode('.', $_oid);
            $len                                                                                             = count($oids);
            $result[$oids[$len - 4] . '.' . $oids[$len - 3] . '.' . $oids[$len - 2] . '.' . $oids[$len - 1]] = $this->parseSnmpValue($value);
        }

        return $result;
    }
}
