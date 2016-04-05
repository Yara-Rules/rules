/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as    long as you use it under this license.

*/

rule TeslaCrypt {
meta:
    description = "Regla para detectar Tesla con md5"
    author = "CCN-CERT"
    version = "1.0"
strings:
    $ = { 4E 6F 77 20 69 74 27 73 20 25 49 3A 25 4D 25 70 2E 00 00 00 76 61 6C 20 69 73 20 25 64 0A 00 00 }
condition:
    all of them
}
