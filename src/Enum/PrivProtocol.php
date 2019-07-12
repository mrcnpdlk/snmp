<?php
/**
 * Created by Marcin Pudełek <marcin@pudelek.org.pl>
 * Date: 12.07.2019
 * Time: 11:41
 */

namespace Mrcnpdlk\Lib\Snmp\Enum;

use MyCLabs\Enum\Enum;

/**
 * @method static PrivProtocol DES()
 * @method static PrivProtocol AES()
 */
class PrivProtocol extends Enum
{
    public const DES = 'DES';
    public const AES = 'AES';
}
