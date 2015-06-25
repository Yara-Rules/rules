/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as    long as you use it under this license.

*/

rule APT_OLE_JSRat
{
meta:
	author = "Rahul Mohandas"
	Date = "2015-06-16"
	Description = "Targeted attack using Excel/word documents"
strings:
	$header = {D0 CF 11 E0 A1 B1 1A E1}
	$key1 = "AAAAAAAAAA"
	$key2 = "Base64Str" nocase
	$key3 = "DeleteFile" nocase
	$key4 = "Scripting.FileSystemObject" nocase
condition:
	$header at 0 and (all of ($key*) )
}
