<?php
/**
 * Created by Marcin Pudełek <marcin@pudelek.org.pl>
 * Date: 12.07.2019
 * Time: 11:38
 */

namespace Mrcnpdlk\Lib\Snmp\Enum;

use MyCLabs\Enum\Enum;

/**
 * @method static Version VER_1()
 * @method static Version VER_2C()
 * @method static Version VER_3()
 */
class Version extends Enum
{
    public const VER_1  = '1';
    public const VER_2C = '2c';
    public const VER_3  = '3';
}
