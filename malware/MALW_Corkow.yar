/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as    long as you use it under this license.

*/
rule CorkowDLL : dll {
	meta:
		description = "Rule to detect the Corkow DLL files" 
		reference = "IB-Group | http://www.group-ib.ru/brochures/Group-IB-Corkow-Report-EN.pdf"
	strings:

		$mz = { 4d 5a }
		$binary1 = {60 [0-8] 9C [0-8] BB ?? ?? ?? ?? [0-8] 81 EB ?? ?? ?? ?? [0-8] E8 ?? 00 00 00 [0-8] 58 [0-8] 2B C3} 
		$binary2 = {(FF75??|53)FF7510FF750CFF7508E8????????[3-9]C9C20C 00} 
		$export1 = "Control_RunDLL"
		$export2 = "ServiceMain"
		$export3 = "DllGetClassObject"

	condition:

		($mz at 0) and ($binary1 and $binary2) and any of ($export*)
}
