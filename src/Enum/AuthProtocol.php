<?php
/**
 * Created by Marcin Pudełek <marcin@pudelek.org.pl>
 * Date: 12.07.2019
 * Time: 11:56
 */

namespace Mrcnpdlk\Lib\Snmp\Enum;

use MyCLabs\Enum\Enum;

/**
 * @method static AuthProtocol MD5()
 * @method static AuthProtocol SHA()
 */
class AuthProtocol extends Enum
{
    public const MD5 = 'MD5';
    public const SHA = 'SHA';
}
