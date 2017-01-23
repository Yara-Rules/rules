/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as    long as you use it under this license.

*/

/*
	Yara Rule Set
	Author: Florian Roth
	Date: 2016-02-09
	Identifier: Poseidon Group APT
*/

rule PoseidonGroup_Malware 
{

    meta:
        description = "Detects Poseidon Group Malware"
        author = "Florian Roth"
        reference = "https://securelist.com/blog/research/73673/poseidon-group-a-targeted-attack-boutique-specializing-in-global-cyber-espionage/"
        date = "2016-02-09"
        score = 85
        hash1 = "337e94119cfad0b3144af81b72ac3b2688a219ffa0bdf23ca56c7a68fbe0aea4"
        hash2 = "344034c0bf9fcd52883dbc158abf6db687150d40a118d9cd6ebd843e186128d3"
        hash3 = "432b7f7f7bf94260a58ad720f61d91ba3289bf0a9789fc0c2b7ca900788dae61"
        hash4 = "8955df76182005a69f19f5421c355f1868efe65d6b9e0145625dceda94b84a47"
        hash5 = "d090b1d77e91848b1e2f5690b54360bbbd7ef808d017304389b90a0f8423367f"
        hash6 = "d7c8b47a0d0a9181fb993f17e165d75a6be8cf11812d3baf7cf11d085e21d4fb"
        hash7 = "ded0ee29af97496f27d810f6c16d78a3031d8c2193d5d2a87355f3e3ca58f9b3"

    strings:
        $s1 = "c:\\winnt\\system32\\cmd.exe" fullword ascii
        $s2 = "c:\\windows\\system32\\cmd.exe" fullword ascii
        $s3 = "c:\\windows\\command.com" fullword ascii
        $s4 = "copy \"%s\" \"%s\" /Y" fullword ascii
        $s5 = "http://%s/files/" fullword ascii
        $s6 = "\"%s\". %s: \"%s\"." fullword ascii
        $s7 = "0x0666" fullword ascii
        $s8 = "----------------This_is_a_boundary$" fullword ascii
        $s9 = "Server 2012" fullword ascii /* Goodware String - occured 1 times */
        $s10 = "Server 2008" fullword ascii /* Goodware String - occured 1 times */
        $s11 = "Server 2003" fullword ascii /* Goodware String - occured 1 times */
        $a1 = "net.exe group \"Domain Admins\" /domain" fullword ascii
        $a2 = "net.exe group \"Admins. do Dom" fullword ascii
        $a3 = "(SVRID=%d)" fullword ascii
        $a4 = "(TG=%d)" fullword ascii
        $a5 = "(SVR=%s)" fullword ascii
        $a6 = "Set-Cookie:\\b*{.+?}\\n" fullword wide
        $a7 = "net.exe localgroup Administradores" fullword ascii

    condition:
        ( uint16(0) == 0x5a4d and filesize < 650KB and 6 of ($s*) ) or ( 4 of ($s*) and 1 of ($a*) )
}

rule PoseidonGroup_MalDoc_1 
{

    meta:
        description = "Detects Poseidon Group - Malicious Word Document"
        author = "Florian Roth"
        reference = "https://securelist.com/blog/research/73673/poseidon-group-a-targeted-attack-boutique-specializing-in-global-cyber-espionage/"
        date = "2016-02-09"
        score = 80
        hash = "0983526d7f0640e5765ded6be6c9e64869172a02c20023f8a006396ff358999b"

    strings:
        $s1 = "c:\\cmd32dll.exe" fullword ascii

    condition:
        uint16(0) == 0xcfd0 and filesize < 500KB and all of them
}

rule PoseidonGroup_MalDoc_2 
{

    meta:
        description = "Detects Poseidon Group - Malicious Word Document"
        author = "Florian Roth"
        reference = "https://securelist.com/blog/research/73673/poseidon-group-a-targeted-attack-boutique-specializing-in-global-cyber-espionage/"
        date = "2016-02-09"
        score = 70
        hash1 = "3e4cacab0ff950da1c6a1c640fe6cf5555b99e36d4e1cf5c45f04a2048f7620c"
        hash2 = "1f77475d7740eb0c5802746d63e93218f16a7a19f616e8fddcbff07983b851af"
        hash3 = "f028ee20363d3a17d30175508bbc4738dd8e245a94bfb200219a40464dd09b3a"
        hash4 = "ec309300c950936a1b9f900aa30630b33723c42240ca4db978f2ca5e0f97afed"
        hash5 = "27449198542fed64c23f583617908c8648fa4b4633bacd224f97e7f5d8b18778"
        hash6 = "1e62629dae05bf7ee3fe1346faa60e6791c61f92dd921daa5ce2bdce2e9d4216"

    strings:
        $s0 = "{\\*\\generator Msftedit 5.41." ascii
        $s1 = "Attachment 1: Complete Professional Background" ascii
        $s2 = "E-mail:  \\cf1\\ul\\f1"
        $s3 = "Education:\\par" ascii
        $s5 = "@gmail.com" ascii

    condition:
        uint32(0) == 0x74725c7b and filesize < 500KB and 3 of them
}
