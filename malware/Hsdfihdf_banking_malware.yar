/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as    long as you use it under this license.
*/
rule Hsdfihdf: banking malware 
{
meta:
	author = "Adam Ziaja <adam@adamziaja.com> http://adamziaja.com"
	date = "2014-04-06"
	description = "Polish banking malware"
	hash0 = "db1675c74a444fd35383d9a45631cada"
	hash1 = "f48ba39df38056449a3e9a1a7289f657"
	filetype = "exe"
strings:
	$s0 = "ANSI_CHARSET"
	$s1 = "][Vee_d_["
	$s2 = "qfcD:6<"
	$s3 = "%-%/%1%3%5%7%9%;%"
	$s4 = "imhzxsc\\WWKD<.)w"
	$s5 = "Vzlarf\\]VOZVMskf"
	$s6 = "JKWFAp\\Z"
	$s7 = "<aLLwhg"
	$s8 = "bdLeftToRight"
	$s9 = "F/.pTC7"
	$s10 = "O><8,)-$ "
	$s11 = "mjeUB>D.'8)5\\\\vhe["
	$s12 = "JGiVRk[W]PL("
	$s13 = "zwWNNG:8"
	$s14 = "zv7,'$"
	$a0 = "#hsdfihdf"
	$a1 = "polska.irc.pl"
	$b0 = "firehim@o2.pl"
	$b1 = "firehim@go2.pl"
	$b2 = "firehim@tlen.pl"
	$c0 = "cyberpunks.pl"
	$c1 = "kaper.phrack.pl"
	$c2 = "serwer.uk.to"
	$c3 = "ns1.ipv4.hu"
	$c4 = "scorebot.koth.hu"
	$c5 = "esopoland.pl"
condition:
	14 of ($s*) or all of ($a*) or 1 of ($b*) or 2 of ($c*)
}
