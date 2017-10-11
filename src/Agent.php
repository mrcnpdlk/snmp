<?php
/**
 * SNMP
 *
 * Copyright (c) 2017 pudelek.org.pl
 *
 * @license MIT License (MIT)
 *
 * For the full copyright and license information, please view source file
 * that is bundled with this package in the file LICENSE
 *
 * @author  Marcin Pudełek <marcin@pudelek.org.pl>
 */

namespace mrcnpdlk\Snmp;

/**
 * Class Agent
 *
 * @package mrcnpdlk\Snmp
 *
 * This class is based on opensolutions/OSS_SNMP project main class.
 * @link    https://github.com/opensolutions/OSS_SNMP[opensolutions/OSS_SNMP]
 *
 * Contact: Barry O'Donovan - barry (at) opensolutions (dot) ie
 * @link    http://www.opensolutions.ie/
 */
class Agent
{
    /**
     * SNMP output constants to mirror those of PHP
     *
     * @var int SNMP output constants to mirror those of PHP
     */
    const OID_OUTPUT_FULL = SNMP_OID_OUTPUT_FULL;
    /**
     * SNMP output constants to mirror those of PHP
     *
     * @var int SNMP output constants to mirror those of PHP
     */
    const OID_OUTPUT_NUMERIC = SNMP_OID_OUTPUT_NUMERIC;

    const SEC_LEVEL_NO_AUTH_NO_PRIV = 'noAuthNoPriv';
    const SEC_LEVEL_AUTH_NO_PRIV    = 'authNoPriv';
    const SEC_LEVEL_AUTH_PRIV       = 'authPriv';

    const SEC_LEVEL_MD5 = 'MD5';
    const SEC_LEVEL_SHA = 'SHA';

    const PRIV_PROTOCOL_DES = 'DES';
    const PRIV_PROTOCOL_AES = 'AES';

    const SNMP_VER_1  = '1';
    const SNMP_VER_2C = '2c';
    const SNMP_VER_3  = '3';
    /**
     * The SNMP community to use when polling SNMP services. Defaults to 'public' by the constructor.
     *
     * @var string The SNMP community to use when polling SNMP services. Defaults to 'public' by the constructor.
     */
    protected $_community;
    /**
     * The SNMP host to query. Defaults to '127.0.0.1'
     *
     * @var string The SNMP host to query. Defaults to '127.0.0.1' by the constructor.
     */
    protected $_host;
    /**
     * The SNMP host to query. Defaults to v2
     *
     * @var string The SNMP host to query. Defaults to v2 by the constructor.
     */
    protected $_version;
    /**
     * Essentially the same thing as the community for v1 and v2
     *
     * @var string
     */
    protected $_secName;
    /**
     * The security level on the device. Defaults to noAuthNoPriv by the constructor.
     * valid strings: (noAuthNoPriv|authNoPriv|authPriv)
     *
     * @var string
     */
    protected $_secLevel;
    /**
     * The authentication encryption picked on the device.
     * Defaults to MD5 by the constructor.
     * valid strings: (MD5|SHA)
     *
     * @var string
     */
    protected $_authProtocol;
    /**
     * The password for the secName. Defaults to None by the constructor.
     *
     * @var string
     */
    protected $_authPassphrase;
    /**
     * The communication encryption picked on the device.
     * Defaults to DES by the constructor.
     * valid strings: (DES|AES)
     *
     * @var string
     */
    protected $_privProtocol;
    /**
     * The password for the secName. Defaults to None by the constructor.
     *
     * @var string
     */
    protected $_privPassphrase;
    /**
     * The SNMP query timeout value (microseconds). Default: 1000000
     *
     * @var int The SNMP query timeout value (microseconds). Default: 1000000
     */
    protected $_timeout = 1000000;
    /**
     * The SNMP query retry count. Default: 5
     *
     * @var int The SNMP query retry count. Default: 5
     */
    protected $_retry = 5;
    /**
     * A variable to hold the last unaltered result of an SNMP query
     *
     * @var mixed The last unaltered result of an SNMP query
     */
    protected $_lastResult = null;

    /**
     * The constructor.
     *
     * @param string $host      The target host for SNMP queries.
     * @param string $community The community to use for SNMP queries.
     * @param string $version
     * @param string $seclevel
     * @param string $authprotocol
     * @param string $authpassphrase
     * @param string $privprotocol
     * @param string $privpassphrase
     */
    public function __construct(
        string $host = '127.0.0.1',
        string $community = 'public',
        string $version = Agent::SNMP_VER_2C,
        string $seclevel = Agent::SEC_LEVEL_NO_AUTH_NO_PRIV,
        string $authprotocol = Agent::SEC_LEVEL_MD5,
        string $authpassphrase = 'None',
        string $privprotocol = Agent::PRIV_PROTOCOL_DES,
        string $privpassphrase = 'None'
    ) {

        return $this->setHost($host)
                    ->setCommunity($community)
                    ->setVersion($version)
                    ->setSecName($community)
                    ->setSecLevel($seclevel)
                    ->setAuthProtocol($authprotocol)
                    ->setAuthPassphrase($authpassphrase)
                    ->setPrivProtocol($privprotocol)
                    ->setPrivPassphrase($privpassphrase)
                    ->setOidOutputFormat(self::OID_OUTPUT_NUMERIC)
            ;
    }

    /**
     * Sets the output format for SNMP queries.
     *
     * Should be one of the class OID_OUTPUT_* constants
     *
     * @param int $f The format to use
     *
     * @return $this An instance of $this (for fluent interfaces)
     */
    public function setOidOutputFormat($f)
    {
        snmp_set_oid_output_format($f);

        return $this;
    }

    /**
     * Importing external MIB file
     *
     * @param string $path
     *
     * @return $this
     * @throws Exception
     */
    public function importMibFile(string $path)
    {
        if (file_exists($path) && is_file($path) && is_readable($path)) {
            snmp_read_mib($path);
        } else {
            throw new Exception(sprintf('MIB file [%s] malformed', realpath($path)));
        }

        return $this;
    }

    /**
     * Get a single SNMP value
     *
     * @throws Exception On *any* SNMP error, warnings are supressed and a generic exception is thrown
     *
     * @param string $oid The OID to get
     *
     * @return mixed The resultant value
     */
    public function get($oid)
    {
        switch ($this->getVersion()) {
            case Agent::SNMP_VER_1:
                $this->_lastResult = @snmpget($this->getHost(), $this->getCommunity(), $oid, $this->getTimeout(), $this->getRetry());
                break;
            case  Agent::SNMP_VER_2C:
                $this->_lastResult = @snmp2_get($this->getHost(), $this->getCommunity(), $oid, $this->getTimeout(), $this->getRetry());
                break;
            case  Agent::SNMP_VER_3:
                $this->_lastResult = @snmp3_get($this->getHost(), $this->getSecName(), $this->getSecLevel(),
                    $this->getAuthProtocol(), $this->getAuthPassphrase(), $this->getPrivProtocol(), $this->getPrivPassphrase(),
                    $oid, $this->getTimeout(), $this->getRetry()
                );
                break;
            default:
                throw new Exception('Invalid SNMP version: ' . $this->getVersion());
        }
        if ($this->_lastResult === false) {
            throw new Exception('Could not perform walk for OID ' . $oid);
        }

        return $this->parseSnmpValue($this->_lastResult);
    }

    /**
     * Gets the version for SNMP queries.
     *
     * @return string
     */
    public function getVersion()
    {
        return $this->_version;
    }

    /**
     * Sets the version for SNMP queries.
     *
     * @param string $v The version for SNMP queries.
     *
     * @return $this An instance of $this (for fluent interfaces)
     */
    public function setVersion($v)
    {
        $this->_version = $v;

        return $this;
    }

    /**
     * Returns the target host as currently configured for SNMP queries
     *
     * @return string The target host as currently configured for SNMP queries
     */
    public function getHost()
    {
        return $this->_host;
    }

    /**
     * Sets the target host for SNMP queries.
     *
     * @param string $h The target host for SNMP queries.
     *
     * @return $this An instance of $this (for fluent interfaces)
     */
    public function setHost($h)
    {
        $this->_host = $h;
        // clear the temporary result cache and last result
        $this->_lastResult = null;

        return $this;
    }

    /**
     * Returns the community string currently in use.
     *
     * @return string The community string currently in use.
     */
    public function getCommunity()
    {
        return $this->_community;
    }

    /**
     * Sets the community string to use for SNMP queries.
     *
     * @param string $c The community to use for SNMP queries.
     *
     * @return $this An instance of $this (for fluent interfaces)
     */
    public function setCommunity($c)
    {
        $this->_community = $c;

        return $this;
    }

    /**
     * Returns the SNMP query timeout (microseconds).
     *
     * @return int The the SNMP query timeout (microseconds)
     */
    public function getTimeout()
    {
        return $this->_timeout;
    }

    /**
     * Sets the timeout to use for SNMP queries (microseconds).
     *
     * @param int $t The timeout to use for SNMP queries (microseconds).
     *
     * @return $this An instance of $this (for fluent interfaces)
     */
    public function setTimeout($t)
    {
        $this->_timeout = $t;

        return $this;
    }

    /**
     * Returns the SNMP query retry count
     *
     * @return string The SNMP query retry count
     */
    public function getRetry()
    {
        return $this->_retry;
    }

    /**
     * Sets the SNMP query retry count.
     *
     * @param int $r The SNMP query retry count
     *
     * @return $this An instance of $this (for fluent interfaces)
     */
    public function setRetry($r)
    {
        $this->_retry = $r;

        return $this;
    }

    /**
     * @return mixed
     */
    public function getSecName()
    {
        return $this->_secName;
    }

    /**
     * @param string $n
     *
     * @return $this
     */
    public function setSecName(string $n)
    {
        $this->_secName = $n;

        return $this;
    }

    /**
     * @return string
     */
    public function getSecLevel()
    {
        return $this->_secLevel;
    }

    /**
     * @param string $l
     *
     * @return $this
     */
    public function setSecLevel(string $l)
    {
        $this->_secLevel = $l;

        return $this;
    }

    /**
     * @return string
     */
    public function getAuthProtocol()
    {
        return $this->_authProtocol;
    }

    /**
     * @param string $p
     *
     * @return $this
     */
    public function setAuthProtocol(string $p)
    {
        $this->_authProtocol = $p;

        return $this;
    }

    /**
     * @return string
     */
    public function getAuthPassphrase()
    {
        return $this->_authPassphrase;
    }

    /**
     * @param string $p
     *
     * @return $this
     */
    public function setAuthPassphrase(string $p)
    {
        $this->_authPassphrase = $p;

        return $this;
    }

    /**
     * @return string
     */
    public function getPrivProtocol()
    {
        return $this->_privProtocol;
    }

    public function setPrivProtocol($p)
    {
        $this->_privProtocol = $p;

        return $this;
    }

    /**
     * @return string
     */
    public function getPrivPassphrase()
    {
        return $this->_privPassphrase;
    }

    /**
     * @param string $p
     *
     * @return $this
     */
    public function setPrivPassphrase(string $p)
    {
        $this->_privPassphrase = $p;

        return $this;
    }

    /**
     * Parse the result of an SNMP query into a PHP type
     *
     * For example, [STRING: "blah"] is parsed to a PHP string containing: blah
     *
     * @param string $v The value to parse
     *
     * @return mixed The parsed value
     * @throws Exception
     */
    public function parseSnmpValue($v)
    {
        // first, rule out an empty string
        if ($v == '""' || $v == '') {
            return "";
        }
        $type  = substr($v, 0, strpos($v, ':'));
        $value = trim(substr($v, strpos($v, ':') + 1));
        switch ($type) {
            case 'STRING':
                if (substr($value, 0, 1) == '"') {
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
            case 'Counter32':
                $rtn = (int)$value;
                break;
            case 'Counter64':
                $rtn = (int)$value;
                break;
            case 'Gauge32':
                $rtn = (int)$value;
                break;
            case 'Hex-STRING':
                $rtn = (string)implode('', explode(' ', preg_replace('/[^A-Fa-f0-9]/', '', $value)));
                break;
            case 'IpAddress':
                $rtn = (string)$value;
                break;
            case 'OID':
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
     * @return array The resultant values
     * @throws \mrcnpdlk\Snmp\Exception
     */
    public function walk1d($oid)
    {

        $this->_lastResult = $this->realWalk($oid);
        if ($this->_lastResult === false) {
            throw new Exception('Could not perform walk for OID ' . $oid);
        }
        $result    = [];
        $oidPrefix = null;
        foreach ($this->_lastResult as $_oid => $value) {
            if ($oidPrefix !== null && $oidPrefix != substr($_oid, 0, strrpos($_oid, '.'))) {
                throw new Exception('Requested OID tree is not a first degree indexed SNMP value');
            } else {
                $oidPrefix = substr($_oid, 0, strrpos($_oid, '.'));
            }
            $result[substr($_oid, strrpos($_oid, '.') + 1)] = $this->parseSnmpValue($value);
        }

        return $result;
    }

    /**
     * Proxy to the snmp2_real_walk command
     *
     * @param string $oid The OID to walk
     *
     * @return array The results of the walk
     * @throws \mrcnpdlk\Snmp\Exception
     */
    public function realWalk($oid)
    {
        switch ($this->getVersion()) {
            case Agent::SNMP_VER_1:
                return $this->_lastResult = @snmprealwalk($this->getHost(), $this->getCommunity(), $oid, $this->getTimeout(), $this->getRetry());
                break;
            case Agent::SNMP_VER_2C:
                return $this->_lastResult = @snmp2_real_walk($this->getHost(), $this->getCommunity(), $oid, $this->getTimeout(), $this->getRetry());
                break;
            case Agent::SNMP_VER_3:
                return $this->_lastResult = @snmp3_real_walk($this->getHost(), $this->getSecName(), $this->getSecLevel(),
                    $this->getAuthProtocol(), $this->getAuthPassphrase(), $this->getPrivProtocol(), $this->getPrivPassphrase(),
                    $oid, $this->getTimeout(), $this->getRetry()
                );
                break;
            default:
                throw new Exception('Invalid SNMP version: ' . $this->getVersion());
        }
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
     *
     * @param string $oid      The OID to walk
     * @param int    $position The position of the OID to use as the key
     * @param int    $elements Number of additional elements to include in the returned array keys after $position.
     *                         This defaults to 1 meaning just the requested OID element (see examples above).
     *                         With -1, retrieves ALL to the end.
     *                         If there is less elements than $elements, return all availables (no error).
     *
     * @return array On *any* SNMP error, warnings are supressed and a generic exception is thrown
     *
     * @throws \mrcnpdlk\Snmp\Exception
     */
    public function subOidWalk($oid, $position, $elements = 1)
    {
        $this->_lastResult = $this->realWalk($oid);
        if ($this->_lastResult === false) {
            throw new Exception('Could not perform walk for OID ' . $oid);
        }
        $result = [];
        foreach ($this->_lastResult as $_oid => $value) {
            $oids  = explode('.', $_oid);
            $index = $oids[$position];
            for ($pos = $position + 1; $pos < sizeof($oids) && ($elements == -1 || $pos < $position + $elements); $pos++) {
                $index .= '.' . $oids[$pos];
            }
            $result[$index] = $this->parseSnmpValue($value);
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
     *
     * @param string $oid The OID to walk
     *
     * @return array On *any* SNMP error, warnings are supressed and a generic exception is thrown
     *
     * @throws \mrcnpdlk\Snmp\Exception
     */
    public function walkIPv4($oid)
    {

        $this->_lastResult = $this->realWalk($oid);
        if ($this->_lastResult === false) {
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
     * Get indexed SNMP values where the array key is spread over a number of OID positions
     *
     *
     * @param string $oid       The OID to walk
     * @param int    $positionS The start position of the OID to use as the key
     * @param int    $positionE The end position of the OID to use as the key
     *
     * @return array On *any* SNMP error, warnings are supressed and a generic exception is thrown
     *
     * @throws \mrcnpdlk\Snmp\Exception
     */
    public function subOidWalkLong($oid, $positionS, $positionE)
    {
        $this->_lastResult = $this->realWalk($oid);
        if ($this->_lastResult === false) {
            throw new Exception('Could not perform walk for OID ' . $oid);
        }
        $result = [];
        foreach ($this->_lastResult as $_oid => $value) {
            $oids   = explode('.', $_oid);
            $oidKey = '';
            for ($i = $positionS; $i <= $positionE; $i++) {
                $oidKey .= $oids[$i] . '.';
            }
            $result[$oidKey] = $this->parseSnmpValue($value);
        }

        return $result;
    }

    /**
     * Set the value of an SNMP object
     *
     * @param string $oid   The OID to set
     * @param string $type  The MIB defines the type of each object id
     * @param mixed  $value The new value
     *
     * @return bool
     * @throws Exception
     */
    public function set($oid, $type, $value)
    {
        switch ($this->getVersion()) {
            case 1:
                $this->_lastResult = @snmpset($this->getHost(), $this->getCommunity(), $oid, $type, $value, $this->getTimeout(), $this->getRetry());
                break;
            case '2c':
                $this->_lastResult = @snmp2_set($this->getHost(), $this->getCommunity(), $oid, $type, $value, $this->getTimeout(), $this->getRetry());
                break;
            case '3':
                $this->_lastResult = @snmp3_set($this->getHost(), $this->getSecName(), $this->getSecLevel(),
                    $this->getAuthProtocol(), $this->getAuthPassphrase(), $this->getPrivProtocol(), $this->getPrivPassphrase(),
                    $oid, $type, $value, $this->getTimeout(), $this->getRetry()
                );
                break;
            default:
                throw new Exception('Invalid SNMP version: ' . $this->getVersion());
        }
        if ($this->_lastResult === false) {
            throw new Exception('Could not add variable ' . $value . ' for OID ' . $oid);
        }

        return $this->_lastResult;
    }
}
