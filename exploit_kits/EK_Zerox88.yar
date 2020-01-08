rule zerox88_js2
{
meta:
	author = "Josh Berry"
	date = "2016-06-26"
	description = "0x88 Exploit Kit Detection"
	hash0 = "cad8b652338f5e3bc93069c8aa329301"
	sample_filetype = "js-html"
	yaragenerator = "https://github.com/Xen0ph0n/YaraGenerator"
strings:
	$string0 = "function gSH() {"
	$string1 = "200 HEIGHT"
	$string2 = "'sh.js'><\\/SCRIPT>"
	$string3 = " 2 - 26;"
	$string4 = "<IFRAME ID"
	$string5 = ",100);"
	$string6 = "200></IFRAME>"
	$string7 = "setTimeout("
	$string8 = "'about:blank' WIDTH"
	$string9 = "mf.document.write("
	$string10 = "document.write("
	$string11 = "Kasper "
condition:
	11 of them
}
rule zerox88_js3
{
meta:
	author = "Josh Berry"
	date = "2016-06-26"
	description = "0x88 Exploit Kit Detection"
	hash0 = "9df0ac2fa92e602ec11bac53555e2d82"
	sample_filetype = "js-html"
	yaragenerator = "https://github.com/Xen0ph0n/YaraGenerator"
strings:
	$string0 = " new ActiveXObject(szHTTP); "
	$string1 = " Csa2;"
	$string2 = "var ADO "
	$string3 = " new ActiveXObject(szOx88);"
	$string4 = " unescape("
	$string5 = "/test.exe"
	$string6 = " szEtYij;"
	$string7 = "var HTTP "
	$string8 = "%41%44%4F%44%42%2E"
	$string9 = "%4D%65%64%69%61"
	$string10 = "var szSRjq"
	$string11 = "%43%3A%5C%5C%50%72%6F%67%72%61%6D"
	$string12 = "var METHOD "
	$string13 = "ADO.Mode "
	$string14 = "%61%79%65%72"
	$string15 = "%2E%58%4D%4C%48%54%54%50"
	$string16 = " 7 - 6; HTTP.Open(METHOD, szURL, i-3); "
condition:
	16 of them
}
