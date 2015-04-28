/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as    long as you use it under this license.

*/

import "pe"

rule backdoor_apt_pcclient
{
meta:
	author = "@patrickrolsen"
	maltype = "APT.PCCLient"
	filetype = "DLL"
	version = "0.1"
	description = "Detects the dropper: 869fa4dfdbabfabe87d334f85ddda234 AKA dw20.dll/msacm32.drv dropped by 4a85af37de44daf5917f545c6fd03902 (RTF)"
	date = "2012-10"
strings:
	$magic = { 4d 5a } // MZ
	$string1 = "www.micro1.zyns.com"
	$string2 = "Mozilla/4.0 (compatible; MSIE 8.0; Win32)"
	$string3 = "msacm32.drv" wide
	$string4 = "C:\\Windows\\Explorer.exe" wide
	$string5 = "Elevation:Administrator!" wide
	$string6 = "C:\\Users\\cmd\\Desktop\\msacm32\\Release\\msacm32.pdb"
condition:
	$magic at 0 and 4 of ($string*)
}
