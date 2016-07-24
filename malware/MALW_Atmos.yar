/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as    long as you use it under this license.

*/

rule Atmos_Malware : kutuzov_101 Banker Atmos
{
    meta:
	description = "Generic Spyware.Citadel.Atmos Signature"
	author = "xylitol@temari.fr"
	reference = "http://www.xylibox.com/2016/02/citadel-0011-atmos.html"
	date = "20/08/2016"
	// May only the challenge guide you

    strings:
    	// Check for the presence of MZ and kutuzov license identifier
    	$MZ = {4D 5A}
	$LKEY = "533D9226E4C1CE0A9815DBEB19235AE4" wide ascii
        
        // TokenSpy identifiers
        $TS1 = "X-TS-Rule-Name: %s" wide ascii
        $TS2 = "X-TS-Rule-PatternID: %u" wide ascii
        $TS3 = "X-TS-BotID: %s" wide ascii
        $TS4 = "X-TS-Domain: %s" wide ascii
        $TS5 = "X-TS-SessionID: %s" wide ascii
        $TS6 = "X-TS-Header-Cookie: %S" wide ascii
        $TS7 = "X-TS-Header-Referer: %S" wide ascii
        $TS8 = "X-TS-Header-AcceptEncoding: %S" wide ascii
        $TS9 = "X-TS-Header-AcceptLanguage: %S" wide ascii
        $TS10 = "X-TS-Header-UserAgent: %S" wide ascii
        
        // Hidden VNC identifiers
        $VNC1 = "_hvnc_init@4" wide ascii
	$VNC2 = "_hvnc_uninit@0" wide ascii
	$VNC3 = "_hvnc_start@8" wide ascii
	$VNC4 = "_hvnc_stop@0" wide ascii
	$VNC5 = "_hvnc_wait@0" wide ascii
	$VNC6 = "_hvnc_work@0" wide ascii
        
        // Browsers identifiers
        $WB1 = "nspr4.dll" wide ascii
	$WB2 = "nss3.dll" wide ascii
	$WB3 = "chrome.dll" wide ascii
	$WB4 = "Internet Explorer" wide ascii
	$WB5 = "Firefox" wide ascii
	$WB6 = "Chrome" wide ascii

    condition:
	($MZ at 0 and $LKEY) and
	(
		(5 of ($TS*) and all of ($WB*)) or
		(3 of ($VNC*) and all of ($WB*))
	)
	and filesize < 300KB // Standard size (raw from builder) should be arround ~264kb
        // Remove the above line if you want to trig also on memory dumps, etc...
}


rule Atmos_Packed_Malware : Packed Atmos Banker
{
    meta:
	description = "Second Generic Spyware.Citadel.Atmos signture when builder add a packed layer"
	author = "xylitol@temari.fr"
	reference = "http://www.xylibox.com/2016/02/citadel-0011-atmos.html"
	date = "20/08/2016"
	// May only the challenge guide you

    strings:
    	$MZ = {4D 5A}
        
        // Entry point identifier with CreateThread pointer in '??' 
	$a = {55 8B EC 83 EC 0C 53 56 8B 35 ?? ?? ?? 00 57 33 DB BF 00 28 00 00}
	
	// End of main proc with sleep value in '??' and api call to sleep in '??'
	$b = {68 ?? ?? ?? ?? FF 15 ?? ?? ?? 00 E9 62 FF FF FF E8 69 10 FE FF 5F 5E 5B C9 C3}

	// API String identifier (ShellExecuteExW, SHELL32.dll, GetUserNameExW, Secur32.dll)
	$c = {53 68 65 6C 6C 45 78 65 63 75 74 65 45 78 57 00 53 48 45 4C 4C 33 32 2E 64 6C 6C 00 1E 00 47 65}
	$d = {74 55 73 65 72 4E 61 6D 65 45 78 57 00 00 53 65 63 75 72 33 32 2E 64 6C 6C 00 10 00}
		
	// New Thread identifier
	$e = {55 8B EC 83 E4 F8 83 EC 1C 83 7D 08 00 57 74 ?? 6A FF FF 75 08 FF 15 ?? ?? ?? 00}
		
    condition:
	all of them
        and filesize < 300KB // Standard size (raw from builder) should be arround ~264kb
        // Remove the above line if you want to trig also on memory dumps, etc...
}


rule Atmos_Builder : Cracked kutuzov Builder
{
    meta:
	description = "Generic signature for Hacktool.Atmos.Builder cracked version"
	author = "xylitol@temari.fr"
	reference = "http://www.xylibox.com/2016/02/citadel-0011-atmos.html"
	date = "20/08/2016"
	// May only the challenge guide you

    strings:
    	// Check for the presence of MZ, kutuzov license identifier, and good hardware ID
    	$MZ = {4D 5A}
	$LKEY = "533D9226E4C1CE0A9815DBEB19235AE4" wide ascii
        $HWID = "D19FC0FB14BE23BCF35DA427951BB5AE" wide ascii

	// Builder strings identifiers
	$s1 = "url_loader=%S" wide ascii
	$s2 = "url_webinjects=%S" wide ascii
	$s3 = "url_tokenspy=%S" wide ascii
	$s4 = "file_webinjects=%S" wide ascii
	$s5 = "moneyparser.enabled=%u" wide ascii
	$s6 = "enable_luhn10_post=%u" wide ascii
	$s7 = "insidevm_enable=%u" wide ascii
	$s8 = "disable_antivirus=%u" wide ascii
		
    condition:
	$MZ at 0 and $LKEY and $HWID and all of ($s*)
}
