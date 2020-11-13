<?php
/**
 * Created by Marcin Pudełek <marcin@pudelek.org.pl>
 * Date: 12.07.2019
 * Time: 11:36
 */

namespace Mrcnpdlk\Lib\Snmp;

use Mrcnpdlk\Lib\ConfigurationException;
use Mrcnpdlk\Lib\ConfigurationOptionsAbstract;
use Mrcnpdlk\Lib\Snmp\Enum\AuthProtocol;
use Mrcnpdlk\Lib\Snmp\Enum\OidOutputFormat;
use Mrcnpdlk\Lib\Snmp\Enum\PrivProtocol;
use Mrcnpdlk\Lib\Snmp\Enum\SecLevel;
use Mrcnpdlk\Lib\Snmp\Enum\Version;

class Config extends ConfigurationOptionsAbstract
{
    /**
     * The SNMP community to use when polling SNMP services. Defaults to 'public' by the constructor.
     *
     * @var string The SNMP community to use when polling SNMP services. Defaults to 'public' by the constructor.
     */
    protected $community = 'public';
    /**
     * The SNMP community to use when polling SNMP services. Defaults to 'private' by the constructor.
     *
     * @var string The SNMP community to use when polling SNMP services. Defaults to 'private' by the constructor.
     */
    protected $communitySet = 'private';
    /**
     * The SNMP host to query. Defaults to '127.0.0.1'
     *
     * @var string The SNMP host to query. Defaults to '127.0.0.1' by the constructor.
     */
    protected $host;
    /**
     * The SNMP host to query. Defaults to v2
     *
     * @var \Mrcnpdlk\Lib\Snmp\Enum\Version The SNMP host to query. Defaults to v2 by the constructor.
     */
    protected $version;
    /**
     * Essentially the same thing as the community for v1 and v2
     *
     * @var string
     */
    protected $secName;
    /**
     * The security level on the device. Defaults to noAuthNoPriv by the constructor.
     * valid strings: (noAuthNoPriv|authNoPriv|authPriv)
     *
     * @var \Mrcnpdlk\Lib\Snmp\Enum\SecLevel
     */
    protected $secLevel;
    /**
     * The authentication encryption picked on the device.
     * Defaults to MD5 by the constructor.
     * valid strings: (MD5|SHA)
     *
     * @var \Mrcnpdlk\Lib\Snmp\Enum\AuthProtocol
     */
    protected $authProtocol;
    /**
     * The password for the secName. Defaults to None by the constructor.
     *
     * @var string
     */
    protected $authPassphrase = 'None';
    /**
     * The communication encryption picked on the device.
     * Defaults to DES by the constructor.
     * valid strings: (DES|AES)
     *
     * @var \Mrcnpdlk\Lib\Snmp\Enum\PrivProtocol
     */
    protected $privProtocol;
    /**
     * The password for the secName. Defaults to None by the constructor.
     *
     * @var string
     */
    protected $privPassphrase = 'None';
    /**
     * The SNMP query timeout value (microseconds). Default: 1000000
     *
     * @var int The SNMP query timeout value (microseconds). Default: 1000000
     */
    protected $timeout = 1000000;
    /**
     * The SNMP query retry count. Default: 5
     *
     * @var int The SNMP query retry count. Default: 5
     */
    protected $retry = 5;
    /**
     * Array of additional MIB files
     *
     * @var string[]
     */
    protected $mibFiles = [];

    /**
     * @var OidOutputFormat
     */
    protected $oidOutputFormat;

    /**
     * @return string
     */
    public function getAuthPassphrase(): string
    {
        return $this->authPassphrase;
    }

    /**
     * @return AuthProtocol
     */
    public function getAuthProtocol(): AuthProtocol
    {
        return $this->authProtocol;
    }

    /**
     * @return string
     */
    public function getCommunity(): string
    {
        return $this->community;
    }

    /**
     * @return string
     */
    public function getCommunitySet(): string
    {
        return $this->communitySet;
    }

    /**
     * @return string
     */
    public function getHost(): string
    {
        return $this->host;
    }

    /**
     * @return \Mrcnpdlk\Lib\Snmp\Enum\OidOutputFormat
     */
    public function getOidOutputFormat(): OidOutputFormat
    {
        return $this->oidOutputFormat;
    }

    /**
     * @return string
     */
    public function getPrivPassphrase(): string
    {
        return $this->privPassphrase;
    }

    /**
     * @return \Mrcnpdlk\Lib\Snmp\Enum\PrivProtocol
     */
    public function getPrivProtocol(): PrivProtocol
    {
        return $this->privProtocol;
    }

    /**
     * @return int
     */
    public function getRetry(): int
    {
        return $this->retry;
    }

    /**
     * @return \Mrcnpdlk\Lib\Snmp\Enum\SecLevel
     */
    public function getSecLevel(): SecLevel
    {
        return $this->secLevel;
    }

    /**
     * @return string
     */
    public function getSecName(): string
    {
        return $this->secName;
    }

    /**
     * @return int
     */
    public function getTimeout(): int
    {
        return $this->timeout;
    }

    /**
     * @return \Mrcnpdlk\Lib\Snmp\Enum\Version
     */
    public function getVersion(): Version
    {
        return $this->version;
    }

    /**
     * @param string $authPassphrase
     *
     * @return Config
     */
    public function setAuthPassphrase(string $authPassphrase): Config
    {
        $this->authPassphrase = $authPassphrase;

        return $this;
    }

    /**
     * @param \Mrcnpdlk\Lib\Snmp\Enum\AuthProtocol|string|mixed $authProtocol
     *
     * @throws \Mrcnpdlk\Lib\ConfigurationException
     *
     * @return Config
     */
    public function setAuthProtocol($authProtocol): Config
    {
        $authProtocol = $authProtocol ?? AuthProtocol::MD5;

        if ($authProtocol instanceof AuthProtocol) {
            $this->authProtocol = $authProtocol;
        } elseif (is_string($authProtocol)) {
            $this->authProtocol = new AuthProtocol($authProtocol);
        } else {
            throw new ConfigurationException(sprintf('%s has bad type', '$authProtocol'));
        }

        return $this;
    }

    /**
     * @param string $community
     *
     * @return Config
     */
    public function setCommunity(string $community): Config
    {
        $this->community = $community;

        return $this;
    }

    /**
     * @param string $host
     *
     * @return Config
     */
    public function setHost(string $host): Config
    {
        $this->host = $host;

        return $this;
    }

    /**
     * @param string $communitySet
     *
     * @return Config
     */
    public function setCommunitySet(string $communitySet): Config
    {
        $this->communitySet = $communitySet;

        return $this;
    }

    /**
     * @param string[] $mibFiles
     *
     * @throws \Mrcnpdlk\Lib\ConfigurationException
     *
     * @return Config
     */
    public function setMibFiles(array $mibFiles): Config
    {
        $this->mibFiles = $mibFiles;

        foreach ($this->mibFiles as $file) {
            if (file_exists($file) && is_file($file) && is_readable($file)) {
                snmp_read_mib($file);
            } else {
                throw new ConfigurationException(sprintf('MIB file [%s] malformed', realpath($file)));
            }
        }

        return $this;
    }

    /**
     * Sets the output format for SNMP queries.
     *
     * Should be one of the class OID_OUTPUT_* constants
     *
     * @param \Mrcnpdlk\Lib\Snmp\Enum\OidOutputFormat|string|mixed $oidOutputFormat
     *
     * @throws \Mrcnpdlk\Lib\ConfigurationException
     *
     * @return Config
     */
    public function setOidOutputFormat($oidOutputFormat): Config
    {
        if ($oidOutputFormat instanceof OidOutputFormat) {
            $this->oidOutputFormat = $oidOutputFormat;
        } elseif (is_string($oidOutputFormat)) {
            $this->oidOutputFormat = new OidOutputFormat($oidOutputFormat);
        } else {
            throw new ConfigurationException(sprintf('%s has bad type', '$oidOutputFormat'));
        }

        snmp_set_oid_output_format($this->oidOutputFormat->getValue());

        return $this;
    }

    /**
     * @param string $privPassphrase
     *
     * @return Config
     */
    public function setPrivPassphrase(string $privPassphrase): Config
    {
        $this->privPassphrase = $privPassphrase;

        return $this;
    }

    /**
     * @param \Mrcnpdlk\Lib\Snmp\Enum\PrivProtocol|string|mixed $privProtocol
     *
     * @throws \Mrcnpdlk\Lib\ConfigurationException
     *
     * @return Config
     */
    public function setPrivProtocol($privProtocol): Config
    {
        $privProtocol = $privProtocol ?? PrivProtocol::DES;
        if ($privProtocol instanceof PrivProtocol) {
            $this->privProtocol = $privProtocol;
        } elseif (is_string($privProtocol)) {
            $this->privProtocol = new PrivProtocol($privProtocol);
        } else {
            throw new ConfigurationException(sprintf('%s has bad type', '$privProtocol'));
        }

        return $this;
    }

    /**
     * @param int $retry
     *
     * @return Config
     */
    public function setRetry(int $retry): Config
    {
        $this->retry = $retry;

        return $this;
    }

    /**
     * @param \Mrcnpdlk\Lib\Snmp\Enum\SecLevel|string|mixed $secLevel
     *
     * @throws \Mrcnpdlk\Lib\ConfigurationException
     *
     * @return Config
     */
    public function setSecLevel($secLevel): Config
    {
        if ($secLevel instanceof SecLevel) {
            $this->secLevel = $secLevel;
        } elseif (is_string($secLevel)) {
            $this->secLevel = new SecLevel($secLevel);
        } else {
            throw new ConfigurationException(sprintf('%s has bad type', '$secLevel'));
        }

        return $this;
    }

    /**
     * @param string $secName
     *
     * @return Config
     */
    public function setSecName(string $secName): Config
    {
        $this->secName = $secName;

        return $this;
    }

    /**
     * @param int $timeout
     *
     * @return Config
     */
    public function setTimeout(int $timeout): Config
    {
        $this->timeout = $timeout;

        return $this;
    }

    /**
     * @param Version|string|mixed $version
     *
     * @throws \Mrcnpdlk\Lib\ConfigurationException
     *
     * @return Config
     */
    public function setVersion($version): Config
    {
        if ($version instanceof Version) {
            $this->version = $version;
        } elseif (is_string($version)) {
            $this->version = new Version($version);
        } else {
            throw new ConfigurationException(sprintf('%s has bad type', '$version'));
        }

        return $this;
    }
}
