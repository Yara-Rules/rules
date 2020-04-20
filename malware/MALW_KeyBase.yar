rule MALW_KeyBase
{
meta:
	description = "Identifies KeyBase aka Kibex."
	author = "@bartblaze"
	date = "2019-02"
	tlp = "White"

strings:	
	$s1 = " End:]" ascii wide
	$s2 = "Keystrokes typed:" ascii wide
	$s3 = "Machine Time:" ascii wide
	$s4 = "Text:" ascii wide
	$s5 = "Time:" ascii wide
	$s6 = "Window title:" ascii wide
	
	$x1 = "&application=" ascii wide
	$x2 = "&clipboardtext=" ascii wide
	$x3 = "&keystrokestyped=" ascii wide
	$x4 = "&link=" ascii wide
	$x5 = "&username=" ascii wide
	$x6 = "&windowtitle=" ascii wide
	$x7 = "=drowssap&" ascii wide
	$x8 = "=emitenihcam&" ascii wide

condition:
	uint16(0) == 0x5a4d and (
		5 of ($s*) or 6 of ($x*) or
		( 4 of ($s*) and 4 of ($x*) )
	)
}
