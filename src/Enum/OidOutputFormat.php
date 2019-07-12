<?php
/**
 * Created by Marcin Pudełek <marcin@pudelek.org.pl>
 * Date: 12.07.2019
 * Time: 12:13
 */

namespace Mrcnpdlk\Lib\Snmp\Enum;

use MyCLabs\Enum\Enum;

/**
 * @method static OidOutputFormat FULL()
 * @method static OidOutputFormat NUMERIC()
 */
class OidOutputFormat extends Enum
{
    /**
     * SNMP output constants to mirror those of PHP
     *
     * @var int SNMP output constants to mirror those of PHP
     */
    public const FULL = SNMP_OID_OUTPUT_FULL;
    /**
     * SNMP output constants to mirror those of PHP
     *
     * @var int SNMP output constants to mirror those of PHP
     */
    public const NUMERIC = SNMP_OID_OUTPUT_NUMERIC;
}
