/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as    long as you use it under this license.

*/
rule xRAT20
{
meta:
	author = "Rottweiler"
	date = "2015-08-20"
	description = "Identifies xRAT 2.0 samples"
	maltype = "Remote Access Trojan"
	hash0 = "cda610f9cba6b6242ebce9f31faf5d9c"
	hash1 = "60d7b0d2dfe937ac6478807aa7043525"
	hash2 = "d1b577fbfd25cc5b873b202cfe61b5b8"
	hash3 = "1820fa722906569e3f209d1dab3d1360"
	hash4 = "8993b85f5c138b0afacc3ff04a2d7871"
	hash5 = "0c231ed8a800b0f17f897241f1d5f4e3"
	hash5 = "0c231ed8a800b0f17f897241f1d5f4e3"
	hash1 = "60d7b0d2dfe937ac6478807aa7043525"
	hash8 = "2c198e3e0e299a51e5d955bb83c62a5e"
	sample_filetype = "exe"
	yaragenerator = "https://github.com/Xen0ph0n/YaraGenerator"
strings:
	$string0 = "GetDirectory: File not found" wide
	$string1 = "<>m__Finally8"
	$string2 = "Secure"
	$string3 = "ReverseProxyClient"
	$string4 = "DriveDisplayName"
	$string5 = "<IsError>k__BackingField"
	$string6 = "set_InstallPath"
	$string7 = "memcmp"
	$string8 = "urlHistory"
	$string9 = "set_AllowAutoRedirect"
	$string10 = "lpInitData"
	$string11 = "reader"
	$string12 = "<FromRawDataGlobal>d__f"
	$string13 = "mq.png" wide
	$string14 = "remove_KeyDown"
	$string15 = "ProtectedData"
	$string16 = "m_hotkeys"
	$string17 = "get_Hour"
	$string18 = "\\mozglue.dll" wide
condition:
	18 of them
}
