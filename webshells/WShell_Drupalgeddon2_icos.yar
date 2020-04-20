/*
This Yara ruleset is under the GNU-GPLv2 license 
(http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or 
organization, as long as you use it under this license.
*/

/*
Author: Luis Fueris 
Date: 4 october, 2019
Description: Drupalgeddon 2 - Web Shells Extract. This rules matchs with
webshells that inserts the Drupal core vulnerability SA-CORE-2018-002 
(https://www.drupal.org/sa-core-2018-002)
*/

rule Dotico_PHP_webshell : webshell {
    meta:
        description = ".ico PHP webshell - file <eight-num-letter-chars>.ico"
        author = "Luis Fueris"
        reference = "https://rankinstudio.com/Drupal_ico_index_hack"
        date = "2019/12/04"
    strings:
        $php = "<?php" ascii
        $regexp = /basename\/\*[a-z0-9]{,6}\*\/\(\/\*[a-z0-9]{,5}\*\/trim\/\*[a-z0-9]{,5}\*\/\(\/\*[a-z0-9]{,5}\*\//
    condition:
        $php at 0 and $regexp and filesize > 70KB and filesize < 110KB
}
