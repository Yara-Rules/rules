/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as
    long as you use it under this license.
*/
rule andromeda : binary bot
{
    meta:
        author = "Brian Wallace @botnet_hunter"
        author_email = "bwall@ballastsecurity.net"
        date = "2014-03-13"
        description = "Identify Andromeda"
    strings:
        $config = {1c 1c 1d 03 49 47 46}
        $c1 = "hsk\\ehs\\dihviceh\\serhlsethntrohntcohurrehem\\chsyst"
    condition:
        all of them
}
rule Worm_Gamarue {
	meta:
		author = "Centro Criptológico Nacional (CCN)"
		ref = "https://www.ccn-cert.cni.es/informes/informes-ccn-cert-publicos.html"
		description = "Gamarue_Andromeda"		
	strings:
		$a = { 69 E1 2A B0 2D 80 44 E3 2D 80 44 E3 2D 80 44 E3 EE 8F 1B E3 2A 80 44 E3 EE 8F 19 E3 3A 80 44 E3 2D 80 45 E3 CD 81 44 E3 0A 46 39 E3 34 80 44 E3 0A 46 29 E3 A5 80 44 E3 0A 46 2A E3 5C 80 44 E3 0A 46 36 E3 2C 80 44 E3 0A 46 3C E3 2C 80 44 E3 }
	condition:
		$a 
}
