/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as    long as you use it under this license.

*/

import "pe"

rule Bolonyokte : rat 
{
	meta:
		description = "UnknownDotNet RAT - Bolonyokte"
		author = "Jean-Philippe Teissier / @Jipe_"
		date = "2013-02-01"
		filetype = "memory"
		version = "1.0" 

	strings:
		$campaign1 = "Bolonyokte" ascii wide
		$campaign2 = "donadoni" ascii wide
		
		$decoy1 = "nyse.com" ascii wide
		$decoy2 = "NYSEArca_Listing_Fees.pdf" ascii wide
		$decoy3 = "bf13-5d45cb40" ascii wide
		
		$artifact1 = "Backup.zip"  ascii wide
		$artifact2 = "updates.txt" ascii wide
		$artifact3 = "vdirs.dat" ascii wide
		$artifact4 = "default.dat"
		$artifact5 = "index.html"
		$artifact6 = "mime.dat"
		
		$func1 = "FtpUrl"
		$func2 = "ScreenCapture"
		$func3 = "CaptureMouse"
		$func4 = "UploadFile"

		$ebanking1 = "Internet Banking" wide
		$ebanking2 = "(Online Banking)|(Online banking)"
		$ebanking3 = "(e-banking)|(e-Banking)" nocase
		$ebanking4 = "login"
		$ebanking5 = "en ligne" wide
		$ebanking6 = "bancaires" wide
		$ebanking7 = "(eBanking)|(Ebanking)" wide
		$ebanking8 = "Anmeldung" wide
		$ebanking9 = "internet banking" nocase wide
		$ebanking10 = "Banking Online" nocase wide
		$ebanking11 = "Web Banking" wide
		$ebanking12 = "Power"

	condition:
		any of ($campaign*) or 2 of ($decoy*) or 2 of ($artifact*) or all of ($func*) or 3 of ($ebanking*)
}
