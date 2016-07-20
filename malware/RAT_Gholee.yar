/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as    long as you use it under this license.

*/

import "pe"

rule gholeeV1
{
    meta:
	 Author = "@GelosSnake"
    	 Date = "2014/08"
    	 Description = "Gholee first discovered variant "
	 Reference = "http://securityaffairs.co/wordpress/28170/cyber-crime/gholee-malware.html" 

    strings:
    	 $a = "sandbox_avg10_vc9_SP1_2011"
    	 $b = "gholee"

    condition:
    	 all of them
}

rule gholeeV2
{
   meta:
	Author = "@GelosSnake"
	Date = "2015-02-12"
    	Description = "Gholee first discovered variant "
	Reference = "http://securityaffairs.co/wordpress/28170/cyber-crime/gholee-malware.html" 

   strings:
	$string0 = "RichHa"
	$string1 = "         (((((                  H" wide
	$string2 = "1$1,141<1D1L1T1\\1d1l1t1"
	$string3 = "<8;$O' "
	$string4 = "@ABCDEFGHIJKLMNOPQRSTUVWXYZ[\\]"
	$string5 = "jYPQTVTSkllZTTXRTUiHceWda/"
	$string6 = "urn:schemas-microsoft-com:asm.v1"
	$string7 = "8.848H8O8i8s8y8"
	$string8 = "wrapper3" wide
	$string9 = "pwwwwwwww"
	$string10 = "Sunday"
	$string11 = "YYuTVWh"
	$string12 = "DDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDIN"
	$string13 = "ytMMMMMMUbbrrrrrxxxxxxxxrriUMMMMMMMMMUuzt"
	$string15 = "wrapper3 Version 1.0" wide
	$string16 = "77A779"
	$string17 = "<C<G<M<R<X<"
	$string18 = "9 9-9N9X9s9"

    condition:
	18 of them
}

rule MW_gholee_v1 : v1
{
meta:
    Author = "@GelosSnake"
    description = "http://securityaffairs.co/wordpress/28170/cyber-crime/gholee-malware.html"
    date = "2014-08"
    maltype = "Remote Access Trojan"
    sample_filetype = "dll"
    hash0 = "48573a150562c57742230583456b4c02"
   
strings:
    $a = "sandbox_avg10_vc9_SP1_2011"
    $b = "gholee"
   
condition:
    all of them
}
 
rule MW_gholee_v2 : v2
{
meta:
        author = "@GelosSnake"
        date = "2015-02-12"
        description = "http://securityaffairs.co/wordpress/28170/cyber-crime/gholee-malware.html"
        hash0 = "05523761ca296ec09afdf79477e5f18d"
        hash1 = "08e424ac42e6efa361eccefdf3c13b21"
        hash2 = "5730f925145f1a1cd8380197e01d9e06"
        hash3 = "73461c8578dd9ab86d42984f30c04610"
        sample_filetype = "dll"
strings:
        $string0 = "RichHa"
        $string1 = "         (((((                  H" wide
        $string2 = "1$1,141<1D1L1T1\\1d1l1t1"
        $string3 = "<8;$O' "
        $string4 = "@ABCDEFGHIJKLMNOPQRSTUVWXYZ[\\]"
        $string5 = "jYPQTVTSkllZTTXRTUiHceWda/"
        $string6 = "urn:schemas-microsoft-com:asm.v1"
        $string7 = "8.848H8O8i8s8y8"
        $string8 = "wrapper3" wide
        $string9 = "pwwwwwwww"
        $string10 = "Sunday"
        $string11 = "YYuTVWh"
        $string12 = "DDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDIN"
        $string13 = "ytMMMMMMUbbrrrrrxxxxxxxxrriUMMMMMMMMMUuzt"
        $string15 = "wrapper3 Version 1.0" wide
        $string16 = "77A779"
        $string17 = "<C<G<M<R<X<"
        $string18 = "9 9-9N9X9s9"
condition:
        18 of them
}

