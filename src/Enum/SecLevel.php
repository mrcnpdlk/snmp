<?php
/**
 * Created by Marcin Pudełek <marcin@pudelek.org.pl>
 * Date: 12.07.2019
 * Time: 11:42
 */

namespace Mrcnpdlk\Lib\Snmp\Enum;

use MyCLabs\Enum\Enum;

/**
 * @method static SecLevel NO_AUTH_NO_PRIV()
 * @method static SecLevel AUTH_NO_PRIV()
 * @method static SecLevel AUTH_PRIV()
 */
class SecLevel extends Enum
{
    public const NO_AUTH_NO_PRIV = 'noAuthNoPriv';
    public const AUTH_NO_PRIV    = 'authNoPriv';
    public const AUTH_PRIV       = 'authPriv';
}
