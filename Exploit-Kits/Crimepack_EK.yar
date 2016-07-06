/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as    long as you use it under this license.

*/
rule crimepack_jar
{
meta:
	author = "Josh Berry"
	date = "2016-06-26"
	description = "CrimePack Exploit Kit Detection"
	hash0 = "d48e70d538225bc1807842ac13a8e188"
	sample_filetype = "unknown"
	yaragenerator = "https://github.com/Xen0ph0n/YaraGenerator"
strings:
	$string0 = "r.JM,IM"
	$string1 = "cpak/Crimepack$1.classPK"
	$string2 = "cpak/KAVS.classPK"
	$string3 = "cpak/KAVS.classmQ"
	$string4 = "cpak/Crimepack$1.classmP[O"
	$string5 = "META-INF/MANIFEST.MF"
	$string6 = "META-INF/MANIFEST.MFPK"
condition:
	6 of them
}
rule crimepack_jar3
{
meta:
	author = "Josh Berry"
	date = "2016-06-26"
	description = "CrimePack Exploit Kit Detection"
	hash0 = "40ed977adc009e1593afcb09d70888c4"
	sample_filetype = "unknown"
	yaragenerator = "https://github.com/Xen0ph0n/YaraGenerator"
strings:
	$string0 = "payload.serPK"
	$string1 = "vE/JD[j"
	$string2 = "payload.ser["
	$string3 = "Exploit$2.classPK"
	$string4 = "Exploit$2.class"
	$string5 = "Ho((i/"
	$string6 = "META-INF/MANIFEST.MF"
	$string7 = "H5641Yk"
	$string8 = "Exploit$1.classPK"
	$string9 = "Payloader.classPK"
	$string10 = "%p6$MCS"
	$string11 = "Exploit$1$1.classPK"
condition:
	11 of them
}
