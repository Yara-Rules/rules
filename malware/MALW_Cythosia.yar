/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as
    long as you use it under this license.
*/

rule Cythosia
{

    meta:
        author = "Brian Wallace @botnet_hunter"
        author_email = "bwall@ballastsecurity.net"
        date = "2015-03-21"
        description = "Identify Cythosia"

    strings:
        $str1 = "HarvesterSocksBot.Properties.Resources" wide

    condition:
        all of them
}
