/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as    long as you use it under this license.

*/
rule malrtf_ole2link : exploit
{
	meta:
		author = "@h3x2b <tracker _AT h3x.eu>"
		description = "Detect weaponized RTF documents with OLE2Link exploit"

	strings:
		//normal rtf beginning
		$rtf_format_00 = "{\\rtf1"
		//malformed rtf can have for example {\\rtA1
		$rtf_format_01 = "{\\rt"

		//having objdata structure
		$rtf_olelink_01 = "\\objdata" nocase

		//hex encoded OLE2Link
		$rtf_olelink_02 = "4f4c45324c696e6b" nocase

		//hex encoded docfile magic - doc file albilae
		$rtf_olelink_03 = "d0cf11e0a1b11ae1" nocase

		//hex encoded "http://"
		$rtf_payload_01 = "68007400740070003a002f002f00" nocase

		//hex encoded "https://"
		$rtf_payload_02 = "680074007400700073003a002f002f00" nocase

		//hex encoded "ftp://"
		$rtf_payload_03 = "6600740070003a002f002f00" nocase


	condition:
		//new_file and
		any of ($rtf_format_*)
		and all of ($rtf_olelink_*)
		and any of ($rtf_payload_*)
}
