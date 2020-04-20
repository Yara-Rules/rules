/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as    long as you use it under this license.
*/

/*
	Androguard module used in this rule file is under development by people at https://koodous.com/.

	You can get it, along with installation instructions, at https://github.com/Koodous/androguard-yara
*/

rule Trojan_Dendroid
{
meta:
author = "https://www.twitter.com/SadFud75"
description = "Detection of dendroid trojan"
strings:
$s1 = "/upload-pictures.php?"
$s2 = "/get-functions.php?"
$s3 = "/new-upload.php?"
$s4 = "/message.php?"
$s5 = "/get.php?"
condition:
3 of them
}
