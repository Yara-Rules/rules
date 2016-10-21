/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as    long as you use it under this license.

*/

rule viotto_keylogger
{
strings:
	$hdr = "MZ"
	$s1 = "Viotto Keylogger"
	$s2 = "msvbvm60"
	$s3 = "FtpPutFileA"
	$s4 = "VBA6"
	$s5 = "SetWindowsHookExA"
condition:
	($hdr at 0) and all of ($s*)

}
