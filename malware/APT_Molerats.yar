/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as    long as you use it under this license.

*/

rule Molerats_certs
{
    
    meta:
        Author      = "FireEye Labs"
        Date        = "2013/08/23"
        Description = "this rule detections code signed with certificates used by the Molerats actor"
        Reference   = "https://www.fireeye.com/blog/threat-research/2013/08/operation-molerats-middle-east-cyber-attacks-using-poison-ivy.html"

    strings:
        $cert1 = { 06 50 11 A5 BC BF 83 C0 93 28 16 5E 7E 85 27 75 }
        $cert2 = { 03 e1 e1 aa a5 bc a1 9f ba 8c 42 05 8b 4a bf 28 }
        $cert3 = { 0c c0 35 9c 9c 3c da 00 d7 e9 da 2d c6 ba 7b 6d }

    condition:
        1 of ($cert*)
}
