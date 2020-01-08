/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as    long as you use it under this license.

*/

rule MIME_MSO_ActiveMime_base64 : maldoc
{
	meta:
		author = "Martin Willing (https://evild3ad.com)"
		description = "Detect MIME MSO Base64 encoded ActiveMime file"
		date = "2016-02-28"
		filetype = "Office documents"
		
	strings:
		$mime = "MIME-Version:"
		$base64 = "Content-Transfer-Encoding: base64"
		$mso = "Content-Type: application/x-mso"
		$activemime = /Q(\x0D\x0A|)W(\x0D\x0A|)N(\x0D\x0A|)0(\x0D\x0A|)a(\x0D\x0A|)X(\x0D\x0A|)Z(\x0D\x0A|)l(\x0D\x0A|)T(\x0D\x0A|)W/
	
	condition:
		$mime at 0 and $base64 and $mso and $activemime
}
