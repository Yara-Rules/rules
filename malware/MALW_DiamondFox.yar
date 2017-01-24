/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as
    long as you use it under this license.
*/

rule diamond_fox
{
   
    meta:
        author = "Brian Wallace @botnet_hunter"
        author_email = "bwall@ballastsecurity.net"
        date = "2015-08-22"
        description = "Identify DiamondFox"
   
    strings:
        $s1 = "UPDATE_B"
        $s2 = "UNISTALL_B"
        $s3 = "S_PROTECT"
        $s4 = "P_WALLET"
        $s5 = "GR_COMMAND"
        $s6 = "FTPUPLOAD"
   
    condition:
        all of them
}
