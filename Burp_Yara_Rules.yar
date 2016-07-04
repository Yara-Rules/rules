/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as    long as you use it under this license.

*/

/* Reference: https://github.com/codewatchorg/Burp-Yara-Rules */

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

rule angler_ek_checkpoint
{
	meta:
		description = "Angler EK Exploit Kit - Checkpoint Detection"
	strings:
		$a = "Jul 2039" nocase
		$b = "Jul 2040" nocase
	condition:
		any of them
}

rule AnglerEKredirector
{
   meta:
      description = "Angler Exploit Kit Redirector"
      ref = "http://blog.xanda.org/2015/08/28/yara-rule-for-angler-ek-redirector-js/"
      author = "adnan.shukor@gmail.com"
      date = "08-July-2015"
      impact = "5"
      version = "1"
   strings:
      $ekr1 = "<script>var date = new Date(new Date().getTime() + 60*60*24*7*1000);" fullword
      $ekr2 = "document.cookie=\"PHP_SESSION_PHP="
      $ekr3 = "path=/; expires=\"+date.toUTCString();</script>" fullword
      $ekr4 = "<iframe src=" fullword
      $ekr5 = "</iframe></div>" fullword
   condition:
      all of them
}

rule angler_flash
{
meta:
	author = "Josh Berry"
	date = "2016-06-26"
	description = "Angler Exploit Kit Detection"
	hash0 = "8081397c30b53119716c374dd58fc653"
	sample_filetype = "unknown"
	yaragenerator = "https://github.com/Xen0ph0n/YaraGenerator"
strings:
	$string0 = "(9OOSp"
	$string1 = "r$g@ 0'[A"
	$string2 = ";R-1qTP"
	$string3 = "xwBtR4"
	$string4 = "YbVjxp"
	$string5 = "ddgXkF"
	$string6 = ")n'URF"
	$string7 = "vAzq@W"
	$string8 = "rOkX$6m<"
	$string9 = "@@DB}q "
	$string10 = "TiKV'iV"
	$string11 = "538x;B"
	$string12 = "9pEM{d"
	$string13 = ".SIy/O"
	$string14 = "ER<Gu,"
condition:
	14 of them
}

rule angler_flash2
{
meta:
	author = "Josh Berry"
	date = "2016-06-26"
	description = "Angler Exploit Kit Detection"
	hash0 = "23812c5a1d33c9ce61b0882f860d79d6"
	sample_filetype = "unknown"
	yaragenerator = "https://github.com/Xen0ph0n/YaraGenerator"
strings:
	$string0 = "4yOOUj"
	$string1 = "CSvI4e"
	$string2 = "'fwaEnkI"
	$string3 = "'y4m%X"
	$string4 = "eOc)a,"
	$string5 = "'0{Q5<"
	$string6 = "1BdX;P"
	$string7 = "D _J)C"
	$string8 = "-epZ.E"
	$string9 = "QpRkP."
	$string10 = "<o/]atel"
	$string11 = "@B.,X<"
	$string12 = "5r[c)U"
	$string13 = "52R7F'"
	$string14 = "NZ[FV'P"
condition:
	14 of them
}

rule angler_flash4
{
meta:
	author = "Josh Berry"
	date = "2016-06-26"
	description = "Angler Exploit Kit Detection"
	hash0 = "dbb3f5e90c05602d92e5d6e12f8c1421"
	sample_filetype = "unknown"
	yaragenerator = "https://github.com/Xen0ph0n/YaraGenerator"
strings:
	$string0 = "_u;cwD;"
	$string1 = "lhNp74"
	$string2 = "Y0GQ%v"
	$string3 = "qjqCb,nx"
	$string4 = "vn{l{Wl"
	$string5 = "5j5jz5"
	$string6 = "a3EWwhM"
	$string7 = "hVJb/4Aut"
	$string8 = ",lm4v,"
	$string9 = ",6MekS"
	$string10 = "YM.mxzO"
	$string11 = ";6 -$E"
	$string12 = "QA%: fy"
	$string13 = "<@{qvR"
	$string14 = "b9'$'6l"
	$string15 = ",x:pQ@-"
	$string16 = "2Dyyr9"
condition:
	16 of them
}

rule angler_flash5
{
meta:
	author = "Josh Berry"
	date = "2016-06-26"
	description = "Angler Exploit Kit Detection"
	hash0 = "9f809272e59ee9ecd71093035b31eec6"
	sample_filetype = "unknown"
	yaragenerator = "https://github.com/Xen0ph0n/YaraGenerator"
strings:
	$string0 = "0k%2{u"
	$string1 = "\\Pb@(R"
	$string2 = "ys)dVI"
	$string3 = "tk4_y["
	$string4 = "LM2Grx"
	$string5 = "n}s5fb"
	$string6 = "jT Nx<hKO"
	$string7 = "5xL>>}"
	$string8 = "S%,1{b"
	$string9 = "C'3g7j"
	$string10 = "}gfoh]"
	$string11 = ",KFVQb"
	$string12 = "LA;{Dx"
condition:
	12 of them
}

rule angler_flash_uncompressed
{
meta:
	author = "Josh Berry"
	date = "2016-06-26"
	description = "Angler Exploit Kit Detection"
	hash0 = "2543855d992b2f9a576f974c2630d851"
	sample_filetype = "unknown"
	yaragenerator = "https://github.com/Xen0ph0n/YaraGenerator"
strings:
	$string0 = "DisplayObjectContainer"
	$string1 = "Xtime2"
	$string2 = "(HMRTQ"
	$string3 = "flash.events:EventDispatcher$flash.display:DisplayObjectContainer"
	$string4 = "_e_-___-__"
	$string5 = "ZviJbf"
	$string6 = "random-"
	$string7 = "_e_-_-_-_"
	$string8 = "_e_------"
	$string9 = "817677162"
	$string10 = "_e_-__-"
	$string11 = "-[vNnZZ"
	$string12 = "5:unpad: Invalid padding value. expected ["
	$string13 = "writeByte/"
	$string14 = "enumerateFonts"
	$string15 = "_e_---___"
	$string16 = "_e_-_-"
	$string17 = "f(fOJ4"
condition:
	17 of them
}

rule angler_html
{
meta:
	author = "Josh Berry"
	date = "2016-06-26"
	description = "Angler Exploit Kit Detection"
	hash0 = "afca949ab09c5583a2ea5b2006236666"
	sample_filetype = "js-html"
	yaragenerator = "https://github.com/Xen0ph0n/YaraGenerator"
strings:
	$string0 = " A9 3E AF D5 9AQ FA 14 BC F2 A0H EA 7FfJ A58 A3 B1 BD 85 DB F3 B4 B6 FB B2 B4 14 82 19 88 28 D0 EA 2"
	$string1 = " 2BS 25 26p 20 3F 81 0E D3 9C 84 C7 EC C3 C41M C48 D3 B5N 09 C2z 98 7B 09. DF 05 5EQ DF A3 B6 EE D5 "
	$string2 = "9 A1Fg A8 837 9A A9 0A 1D 40b02 A5U6 22o 16 DC 5D F5 F5 FA BE FB EDX F0 87 DB C9 7B D6 AC F6D 10 1AJ"
	$string3 = "24 AA 17 FB B0 96d DBN 05 EE F6 0F 24 D4 D0 C0 E4 96 03 A3 03 20/ 04 40 DB 8F 7FI A6 DC F5 09 0FWV 1"
	$string4 = "Fq B3 94 E3 3E EFw E6 AA9 3A 5B 9E2 D2 EC AF6 10c 83 0F DF BB FBx AF B4 1BV 5C DD F8 9BR 97v D0U 9EG"
	$string5 = "29 9B 01E C85 86 B0 09 EC E07 AFCY 19 E5 11 1C 92 E2 DA A9 5D 19P 3A BF AB D6 B3 3FZ B4 92 FF E1 27 "
	$string6 = "B A9 88 B8 F0 EBLd 8E 08 18 11P EE BFk 15 5BM D6 B7 CEh AF 9C 8F 04 89 88 5E F6 ED 13 8EN1p 86Vk BC "
	$string7 = "w F4 C8 16pV 22 0A BB EB 83 7D BC 89 B6 E06 8B 2A DC E6 7D CE. 0Dh 18 0A8 5E 60 0C BF A4 00M 00 E3 3"
	$string8 = "B7 C6 E3 8E DC 3BR 60L 94h D8 AA7k5s 0D 7Fb 8B 80P E0 1BP EBT B5 03zE D0o 2A B97 18 F39 7C 94 99 11 "
	$string9 = "kY 24 8E 3E 94 84 D2 00 1EB 16 A4 9C 28 24 C1B BB 22 7D 97c F5 BA AD C4 5C 23 5D 3D 5C A7d5 0C F6 EA"
	$string10 = "08 01 3A 15 3B E0 1A E2 89 5B A2 F4 ED 87O F9l A99 124 27 BF BB A1c 2BW 12Z 07 AA D9 81 B7 A6-5 E2 E"
	$string11 = " 16 BF A7 0E 00 16 BB 8FB CBn FC D8 9C C7 EA AC C2q 85n A96I D1 9B FC8 BDl B8 3Ajf 7B ADH FD 20 88 F"
	$string12 = "  ML    "
	$string13 = " AEJ 3B C7 BFy EF F07X D3 A0 1E B4q C4 BE 3A 10 E7 A0 FE D1Jhp 89 A0sj 1CW 08 D5 F7 C8 C6 D5I 81 D2 "
	$string14 = "B 24 90 ED CEP C8 C9 9B E5 25 09 C6B- 2B 3B C7 28 C9 C62 EB D3 D5 ED DE A8 7F A9mNs 87 12 82 03 A2 8"
	$string15 = "A 3A A2L DFa 18 11P 00 7F1 BBbY FA 5E 04 C4 5D 89 F3S DAN B5 CAi 8D 0A AC A8 0A ABI E6 1E 89 BB 07 D"
	$string16 = "C B5 FD 0B F9 0Ch CE 01 14 8Dp AF 24 E0 E3 D90 DD FF B0 07 2Ad 0B 7D B0 B2 D8 BD E6 A7 CE E1 E4 3E5 "
	$string17 = "19 0C 85 14r/ 8C F3 84 2B 8C CF 90 93 E2 F6zo C3 D40 A6 94 01 02Q 21G AB B9 CDx 9D FB 21 2C 10 C3 3C"
	$string18 = "FAV D7y A0 C7Ld4 01 22 EE B0 1EY FAB BA E0 01 24 15g C5 DA6 19 EEsl BF C7O 9F 8B E8 AF 93 F52 00 06 "
condition:
	18 of them
}

rule angler_html2
{
meta:
	author = "Josh Berry"
	date = "2016-06-26"
	description = "Angler Exploit Kit Detection"
	hash0 = "6c926bf25d1a8a80ab988c8a34c0102e"
	sample_filetype = "js-html"
	yaragenerator = "https://github.com/Xen0ph0n/YaraGenerator"
strings:
	$string0 = "E 06 E7i 1E 91q 9C D0J 1D 9B 14 E7g 1D DD ECK 20c 40 C6 0C AFR5 3D 03 9Em EC 0CB C9 A9 DFw C9 ADP 5B"
	$string1 = "14Bc 5C 3Bp CB 2A 12 3D A56 AA 14 87 E3 81 8A 80h 27 1C 3A4 CE 12 AE FAy F0 8A 21 B8I AD 1E B9 2C D1"
	$string2 = "0J 95 83 CC 1C 95D CAD 1A EA F3 00 E9 DA_ F2 ED 3CM1 A0 01t 1B EE 2C B6AWKq BF CAY FE D8 F2 7C 96 92"
	$string3 = "A8MTCsn C9 DBu D3 10 A0 D4 AC A9 97 06Rn 01 DAK EFFN ADP AE 0E 8FJd 8F DA B6 25RO 18 2A 00 EA F9 8B "
	$string4 = "A3 EB C1 CE 1E C4ok C4 19 F2 A7 17 9FCoz B6- C6 25J BB 0B 8C1OZ E4 7B AEz F6 06A 5D C0 D7 E8 FF DB D"
	$string5 = " 07 DE A3 F8 B0 B3 20V A4 B2 C8 60 BD EEG 95 BB 04 1Ckw A4 80 E6 23 F02 FA 9C 9A 14F BDC 18 BE BD B4"
	$string6 = "7 D1 B9 9B AC 2AN BA D3 00 A9 1CJ3J C0V 8F 8E FC B6p9 00 E1 01 21j B3 27 FF C3 8E 2B 92 8B DEiUI C3 "
	$string7 = " 99 2C AF9 F9 3F5 A8 F0 1BU C8e/ 00Q B4 10 DD BC 9D 8A BF B2 17 8F BFd DB D1 B7 E66 21 96 86 1E B2 1"
	$string8 = "E86 DF9 22Tg E93 9Em 29 0A 5B B5m E2 DCIF D6 D2 F5B CF F7XkRv BE EA A6 C5 82p 5E B3 B4aD B9 3A E0 22"
	$string9 = " 7C 95.q D6f E8 1AE 17 82T 84 F1/O 82 C2q C7 FE 05C E4 E5W F5 0A E4l 12 3Brt 8A E0 E7 DDJ 1F 1F C4 A"
	$string10 = "4t 91iE BD 2C 95U E9 1C AE 5B 5B A3 9D B2 F9 0B B5 15S9 AB 9D 94 85 A6 F1 AF B6 FC CAt 91iE BD 2C 95"
	$string11 = "  </input>"
	$string12 = "2 D12 93 FD AB 0DKK AEN 40 DA 88 7B FA 3B 18 EE 09 92 ED AF A8b 07 002 0A A3S 04 29 F9 A3 EA BB E9 7"
	$string13 = "40 C6 0C AFR5E 15 07 EE CBg B3 C6 60G 92tFt D7E 7D F0 C4 A89 29 EC BA E1 D9 3D 23 F0 0B E0o 3E2c B3 "
	$string14 = "2 A3. A3 F1 D8 D4 A83K 9C AEu FF EA 02 F4 B8 A0 EE C9 7B 15 C1 07D 80 7C 10 864 96 E3 AA F8 99bgve D"
	$string15 = "C 7D DC 0A E9 0D A1k 85s 9D 24 8C D0k E1 7E 3AH E2 052 D8q 16 FC 96 0AR C0 EC 99K4 3F BE ED CC DBE A"
	$string16 = "40 DA 88 7B 9E 1A B3 FA DE 90U 5B BD6x 9A 0C 163 AB EA ED B4 B5 98 ADL B7 06 EE E5y B8 9B C9Q 00 E9 "
	$string17 = "F BF_ F9 AC 5B CC 0B1 7B 60 20c 40 C6 0C AFR5 0B C7D 09 9D E30 14 AC 027 B2 B9B A7 06 E3z DC- B2 60 "
	$string18 = "0 80 97Oi 8C 85 D2 1Bp CDv 11 05 D4 26 E7 FC 3DlO AE 96 D2 1B 89 7C 16H 11 86 D0 A6 B95 FC 01 C5 8E "
condition:
	18 of them
}

rule angler_jar
{
meta:
	author = "Josh Berry"
	date = "2016-06-26"
	description = "Angler Exploit Kit Detection"
	hash0 = "3de78737b728811af38ea780de5f5ed7"
	sample_filetype = "unknown"
	yaragenerator = "https://github.com/Xen0ph0n/YaraGenerator"
strings:
	$string0 = "myftysbrth"
	$string1 = "classPK"
	$string2 = "8aoadN"
	$string3 = "j5/_<F"
	$string4 = "FXPreloader.class"
	$string5 = "V4w\\K,"
	$string6 = "W\\Vr2a"
	$string7 = "META-INF/MANIFEST.MF"
	$string8 = "Na8$NS"
	$string9 = "_YJjB'"
condition:
	9 of them
}

rule angler_js
{
meta:
	author = "Josh Berry"
	date = "2016-06-26"
	description = "Angler Exploit Kit Detection"
	hash0 = "482d6c24a824103f0bcd37fa59e19452"
	sample_filetype = "js-html"
	yaragenerator = "https://github.com/Xen0ph0n/YaraGenerator"
strings:
	$string0 = "    2654435769,   Be"
	$string1 = "DFOMIqka "
	$string2 = ",  Zydr$>>16"
	$string3 = "DFOMIqka( 'OPPj_phuPuiwzDFo')"
	$string4 = "U0BNJWZ9J0vM43TnlNZcWnZjZSelQZlb1HGTTllZTm19emc0dlsYF13GvhQJmTZmbVMxallMdhWW948YWi t    P  b50GW"
	$string5 = "    auSt;"
	$string6 = " eval    (NDbMFR "
	$string7 = "jWUwYDZhNVyMI2TzykEYjWk0MDM5MA%ZQ1TD1gEMzj         3  D       ',"
	$string8 = "('fE').substr    (2    ,    1 "
	$string9 = ",  -1 "
	$string10 = "    )  );Zydr$  [ 1]"
	$string11 = " 11;PsKnARPQuNNZMP<9;PsKnARPQuNNZMP"
	$string12 = "new   Array  (2),  Ykz"
	$string13 = "<script> "
	$string14 = ");    CYxin "
	$string15 = "Zydr$    [    1]"
	$string16 = "var tKTGVbw,auSt, vnEihY, gftiUIdV, XnHs, UGlMHG, KWlqCKLfCV;"
	$string17 = "reXKyQsob1reXKyQsob3 "
condition:
	17 of them
}

rule blackhole1_jar
{
meta:
	author = "Josh Berry"
	date = "2016-06-26"
	description = "BlackHole1 Exploit Kit Detection"
	hash0 = "724acccdcf01cf2323aa095e6ce59cae"
	sample_filetype = "unknown"
	yaragenerator = "https://github.com/Xen0ph0n/YaraGenerator"
strings:
	$string0 = "Created-By: 1.6.0_18 (Sun Microsystems Inc.)"
	$string1 = "workpack/decoder.classmQ]S"
	$string2 = "workpack/decoder.classPK"
	$string3 = "workpack/editor.classPK"
	$string4 = "xmleditor/GUI.classmO"
	$string5 = "xmleditor/GUI.classPK"
	$string6 = "xmleditor/peers.classPK"
	$string7 = "v(SiS]T"
	$string8 = ",R3TiV"
	$string9 = "META-INF/MANIFEST.MFPK"
	$string10 = "xmleditor/PK"
	$string11 = "Z[Og8o"
	$string12 = "workpack/PK"
condition:
	12 of them
}

rule blackhole_basic : exploit_kit
{
    strings:
        $a = /\.php\?.*?\:[a-zA-Z0-9\:]{6,}\&.*?\&/
    condition:
        $a
}

rule bleedinglife2_adobe_2010_1297_exploit
{
meta:
	author = "Josh Berry"
	date = "2016-06-26"
	description = "BleedingLife2 Exploit Kit Detection"
	hash0 = "8179a7f91965731daa16722bd95f0fcf"
	sample_filetype = "unknown"
	yaragenerator = "https://github.com/Xen0ph0n/YaraGenerator"
strings:
	$string0 = "getSharedStyle"
	$string1 = "currentCount"
	$string2 = "String"
	$string3 = "setSelection"
	$string4 = "BOTTOM"
	$string5 = "classToInstancesDict"
	$string6 = "buttonDown"
	$string7 = "focusRect"
	$string8 = "pill11"
	$string9 = "TEXT_INPUT"
	$string10 = "restrict"
	$string11 = "defaultButtonEnabled"
	$string12 = "copyStylesToChild"
	$string13 = " xmlns:xmpMM"
	$string14 = "_editable"
	$string15 = "classToDefaultStylesDict"
	$string16 = "IMEConversionMode"
	$string17 = "Scene 1"
condition:
	17 of them
}

rule bleedinglife2_adobe_2010_2884_exploit
{
meta:
	author = "Josh Berry"
	date = "2016-06-26"
	description = "BleedingLife2 Exploit Kit Detection"
	hash0 = "b22ac6bea520181947e7855cd317c9ac"
	sample_filetype = "unknown"
	yaragenerator = "https://github.com/Xen0ph0n/YaraGenerator"
strings:
	$string0 = "_autoRepeat"
	$string1 = "embedFonts"
	$string2 = "KeyboardEvent"
	$string3 = "instanceStyles"
	$string4 = "InvalidationType"
	$string5 = "autoRepeat"
	$string6 = "getScaleX"
	$string7 = "RadioButton_selectedDownIcon"
	$string8 = "configUI"
	$string9 = "deactivate"
	$string10 = "fl.controls:Button"
	$string11 = "_mouseStateLocked"
	$string12 = "fl.core.ComponentShim"
	$string13 = "toString"
	$string14 = "_group"
	$string15 = "addRadioButton"
	$string16 = "inCallLaterPhase"
	$string17 = "oldMouseState"
condition:
	17 of them
}

rule bleedinglife2_jar2
{
meta:
	author = "Josh Berry"
	date = "2016-06-26"
	description = "BleedingLife2 Exploit Kit Detection"
	hash0 = "2bc0619f9a0c483f3fd6bce88148a7ab"
	sample_filetype = "unknown"
	yaragenerator = "https://github.com/Xen0ph0n/YaraGenerator"
strings:
	$string0 = "META-INF/MANIFEST.MFPK"
	$string1 = "RequiredJavaComponent.classPK"
	$string2 = "META-INF/JAVA.SFm"
	$string3 = "RequiredJavaComponent.class"
	$string4 = "META-INF/MANIFEST.MF"
	$string5 = "META-INF/JAVA.DSAPK"
	$string6 = "META-INF/JAVA.SFPK"
	$string7 = "5EVTwkx"
	$string8 = "META-INF/JAVA.DSA3hb"
	$string9 = "y\\Dw -"
condition:
	9 of them
}

rule bleedinglife2_java_2010_0842_exploit
{
meta:
	author = "Josh Berry"
	date = "2016-06-26"
	description = "BleedingLife2 Exploit Kit Detection"
	hash0 = "b14ee91a3da82f5acc78abd10078752e"
	sample_filetype = "unknown"
	yaragenerator = "https://github.com/Xen0ph0n/YaraGenerator"
strings:
	$string0 = "META-INF/MANIFEST.MFManifest-Version: 1.0"
	$string1 = "ToolsDemo.classPK"
	$string2 = "META-INF/services/javax.sound.midi.spi.MidiDeviceProvider5"
	$string3 = "Created-By: 1.6.0_22 (Sun Microsystems Inc.)"
	$string4 = "META-INF/PK"
	$string5 = "ToolsDemo.class"
	$string6 = "META-INF/services/PK"
	$string7 = "ToolsDemoSubClass.classPK"
	$string8 = "META-INF/MANIFEST.MFPK"
	$string9 = "ToolsDemoSubClass.classeN"
condition:
	9 of them
}

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

rule cve_2013_0074
{
meta:
	author = "Kaspersky Lab"
	filetype = "Win32 EXE"
	date = "2015-07-23"
	version = "1.0"

strings:
	$b2="Can't find Payload() address" ascii wide
	$b3="/SilverApp1;component/App.xaml" ascii wide
	$b4="Can't allocate ums after buf[]" ascii wide
	$b5="------------ START ------------"

condition:
	( (2 of ($b*)) )
}

rule CVE_2013_0422
{
        meta:
                description = "Java Applet JMX Remote Code Execution"
                cve = "CVE-2013-0422"
                ref = "http://pastebin.com/JVedyrCe"
                author = "adnan.shukor@gmail.com"
                date = "12-Jan-2013"
                version = "1"
                impact = 4
                hide = false
        strings:
                $0422_1 = "com/sun/jmx/mbeanserver/JmxMBeanServer" fullword
                $0422_2 = "com/sun/jmx/mbeanserver/JmxMBeanServerBuilder" fullword
                $0422_3 = "com/sun/jmx/mbeanserver/MBeanInstantiator" fullword
                $0422_4 = "findClass" fullword
                $0422_5 = "publicLookup" fullword
                $class = /sun\.org\.mozilla\.javascript\.internal\.(Context|GeneratedClassLoader)/ fullword 
        condition:
                (all of ($0422_*)) or (all of them)
}

rule eleonore_jar
{
meta:
	author = "Josh Berry"
	date = "2016-06-26"
	description = "Eleonore Exploit Kit Detection"
	hash0 = "ad829f4315edf9c2611509f3720635d2"
	sample_filetype = "unknown"
	yaragenerator = "https://github.com/Xen0ph0n/YaraGenerator"
strings:
	$string0 = "r.JM,IM"
	$string1 = "dev/s/DyesyasZ.classPK"
	$string2 = "k4kjRv"
	$string3 = "dev/s/LoaderX.class}V[t"
	$string4 = "dev/s/PK"
	$string5 = "Hsz6%y"
	$string6 = "META-INF/MANIFEST.MF"
	$string7 = "dev/PK"
	$string8 = "dev/s/AdgredY.class"
	$string9 = "dev/s/DyesyasZ.class"
	$string10 = "dev/s/LoaderX.classPK"
	$string11 = "eS0L5d"
	$string12 = "8E{4ON"
condition:
	12 of them
}

rule eleonore_jar2
{
meta:
	author = "Josh Berry"
	date = "2016-06-26"
	description = "Eleonore Exploit Kit Detection"
	hash0 = "94e99de80c357d01e64abf7dc5bd0ebd"
	sample_filetype = "unknown"
	yaragenerator = "https://github.com/Xen0ph0n/YaraGenerator"
strings:
	$string0 = "META-INF/MANIFEST.MFManifest-Version: 1.0"
	$string1 = "wPVvVyz"
	$string2 = "JavaFX.class"
	$string3 = "{%D@'\\"
	$string4 = "JavaFXColor.class"
	$string5 = "bWxEBI}Y"
	$string6 = "$(2}UoD"
	$string7 = "j%4muR"
	$string8 = "vqKBZi"
	$string9 = "l6gs8;"
	$string10 = "JavaFXTrueColor.classeSKo"
	$string11 = "ZyYQx "
	$string12 = "META-INF/"
	$string13 = "JavaFX.classPK"
	$string14 = ";Ie8{A"
condition:
	14 of them
}

rule eleonore_jar3
{
meta:
	author = "Josh Berry"
	date = "2016-06-26"
	description = "Eleonore Exploit Kit Detection"
	hash0 = "f65f3b9b809ebf221e73502480ab6ea7"
	sample_filetype = "unknown"
	yaragenerator = "https://github.com/Xen0ph0n/YaraGenerator"
strings:
	$string0 = "16lNYF2V"
	$string1 = "META-INF/MANIFEST.MFPK"
	$string2 = "ghsdr/Jewredd.classPK"
	$string3 = "ghsdr/Gedsrdc.class"
	$string4 = "e[<n55"
	$string5 = "ghsdr/Gedsrdc.classPK"
	$string6 = "META-INF/"
	$string7 = "na}pyO"
	$string8 = "9A1.F\\"
	$string9 = "ghsdr/Kocer.class"
	$string10 = "MXGXO8"
	$string11 = "ghsdr/Kocer.classPK"
	$string12 = "ghsdr/Jewredd.class"
condition:
	12 of them
}

rule eleonore_js
{
meta:
	author = "Josh Berry"
	date = "2016-06-26"
	description = "Eleonore Exploit Kit Detection"
	hash0 = "08f8488f1122f2388a0fd65976b9becd"
	sample_filetype = "js-html"
	yaragenerator = "https://github.com/Xen0ph0n/YaraGenerator"
strings:
	$string0 = "var de"
	$string1 = "sdjk];"
	$string2 = "return dfshk;"
	$string3 = "function jkshdk(){"
	$string4 = "'val';"
	$string5 = "var sdjk"
	$string6 = "return fsdjkl;"
	$string7 = " window[d"
	$string8 = "var fsdjkl"
	$string9 = "function jklsdjfk() {"
	$string10 = "function rewiry(yiyr,fjkhd){"
	$string11 = " sdjd "
condition:
	11 of them
}

rule eleonore_js2
{
meta:
	author = "Josh Berry"
	date = "2016-06-26"
	description = "Eleonore Exploit Kit Detection"
	hash0 = "2f5ace22e886972a8dccc6aa5deb1e79"
	sample_filetype = "js-html"
	yaragenerator = "https://github.com/Xen0ph0n/YaraGenerator"
strings:
	$string0 = "var dfshk "
	$string1 = "arrow_next_down"
	$string2 = "return eval('yiyr.replac'"
	$string3 = "arrow_next_over"
	$string4 = "arrow_prev_over"
	$string5 = "xcCSSWeekdayBlock"
	$string6 = "xcCSSHeadBlock"
	$string7 = "xcCSSDaySpecial"
	$string8 = "xcCSSDay"
	$string9 = " window[df "
	$string10 = "day_special"
	$string11 = "var df"
	$string12 = "function jklsdjfk() {"
	$string13 = " sdjd "
	$string14 = "'e(/kljf hdfk sdf/g,fjkhd);');"
	$string15 = "arrow_next"
condition:
	15 of them
}

rule eleonore_js3
{
meta:
	author = "Josh Berry"
	date = "2016-06-26"
	description = "Eleonore Exploit Kit Detection"
	hash0 = "9dcb8cd8d4f418324f83d914ab4d4650"
	sample_filetype = "js-html"
	yaragenerator = "https://github.com/Xen0ph0n/YaraGenerator"
strings:
	$string0 = "@mozilla.org/file/directory_service;1"
	$string1 = "var exe "
	$string2 = "var file "
	$string3 = "foStream.write(data, data.length);"
	$string4 = "  var file_data "
	$string5 = "return "
	$string6 = " Components.classes["
	$string7 = "url : "
	$string8 = "].createInstance(Components.interfaces.nsILocalFile);"
	$string9 = "  var bstream "
	$string10 = " bstream.readBytes(size); "
	$string11 = "@mozilla.org/supports-string;1"
	$string12 = "  var channel "
	$string13 = "tmp.exe"
	$string14 = "  if (channel instanceof Components.interfaces.nsIHttpChannel "
	$string15 = "@mozilla.org/network/io-service;1"
	$string16 = " bstream.available()) { "
	$string17 = "].getService(Components.interfaces.nsIIOService); "
condition:
	17 of them
}

rule fragus_htm
{
meta:
	author = "Josh Berry"
	date = "2016-06-26"
	description = "Fragus Exploit Kit Detection"
	hash0 = "f76deec07a61b4276acc22beef41ea47"
	sample_filetype = "js-html"
	yaragenerator = "https://github.com/Xen0ph0n/YaraGenerator"
strings:
	$string0 = ">Hello, "
	$string1 = "http://www.clantemplates.com"
	$string2 = "this template was created by Bl1nk and is downloadable at <B>ClanTemplates.com<BR></B>Replace "
	$string3 = "></TD></TR></TABLE> "
	$string4 = "Image21"
	$string5 = "scrollbar etc.<BR><BR>Enjoy, Bl1nk</FONT></TD></TR></TABLE><BR></CENTER></TD></TR> "
	$string6 = "to this WarCraft Template"
	$string7 = " document.getElementById) x"
	$string8 = "    if (a[i].indexOf("
	$string9 = "x.oSrc;"
	$string10 = "x.src; x.src"
	$string11 = "<HTML>"
	$string12 = "FFFFFF"
	$string13 = " CELLSPACING"
	$string14 = "images/layoutnormal_03.gif"
	$string15 = "<TR> <TD "
	$string16 = " CELLPADDING"
condition:
	16 of them
}

rule fragus_js
{
meta:
	author = "Josh Berry"
	date = "2016-06-26"
	description = "Fragus Exploit Kit Detection"
	hash0 = "f234c11b5da9a782cb1e554f520a66cf"
	sample_filetype = "js-html"
	yaragenerator = "https://github.com/Xen0ph0n/YaraGenerator"
strings:
	$string0 = "));ELI6Q3PZ"
	$string1 = "VGhNU2pWQmMyUXhPSFI2TTNCVGVEUXpSR3huYm1aeE5UaFhXRFI0ZFhCQVMxWkRNVGh0V0hZNFZVYzBXWFJpTVRoVFpFUklaVGxG"
	$string2 = "eFgweDNaek5YZDFkaWFtTlhZbDlmV2tGa09Va3pSMlEyT0dwSFFIQlZRblpEYzBKRWNFeGZOVmx6V0RSU1JEYzJjRlY0TVY5SFkw"
	$string3 = "TkhXa0ZrT1haNGRFSXhRM3BrTkRoVGMxZEJSMmcyT0dwNlkzSTJYM1pCYkZnMVVqQmpWMEZIYURZNGFucGpjalpmZGtGc1dERXpT"
	$string4 = "byKZKkpZU<<18"
	$string5 = ");CUer0x"
	$string6 = "bzWRebpU3yE>>16"
	$string7 = "RUJEWlVvMGNsVTVNMEpNWDNaNGJVSkpPRUJrUlVwRVQwQlNaR2cyY0ZWSE5GbDBRVFZ5UjFnMk9HVldOWGhMYUdFelRIZG5NMWQz"
	$string8 = "WnZSVGxuT1ZSRkwwaFZSelZGUm5GRlJFVTBLVHQ0UWxKQ1drdzBiWEJ5WkhSdVBtdG9XVWd6TVVGSGFFeDVTMlk3ZUVKU1FscE1O"
	$string9 = "QmZjMGN4YjBCd1oyOXBURUJJZEhvMFdYcGtOamhFV1ZwU01GVlZZbXBpUUZKV1lqTXpWMDAwY0dSNlF6aE1SekZ5ZEc4ME9FeEtN"
	$string10 = "SCpMaWXOuME("
	$string11 = "VjJKcVkxZGlYMTlhUVdRNVNUTkhaRFk0YWpsYWJsWkRNVGh0V0hZNFZVYzBXWFJ2Tm5CVmFEUlpWVmhDT0ZWV05YaDBRa1ZTUkUw"
	$string12 = "2;}else{Yuii37DWU"
	$string13 = "ELI6Q3PZ"
	$string14 = "ZUhNNVZYQlZlRFY0UUZnMk9HMVlORkpFYkRsNGMxbEpPRUJSTVY5SGNETllPRXB0YjBsaloySnhPVVZ3UkZWQVgzTllORGgwV0RS"
	$string15 = "S05GbE1lalk0Vm1ORmVEWnpXbEpXZDBWaU5ubzJjRlkzVjFsbFgwVmlURlpuYnpCUE5HNTBhRFpaVEZrMVFYTjZObkIwWTBVNE4x"
	$string16 = "Vm5CWFFVZG9OamhxZW1OeU5sOTJRV3hZTVROSlpEWTRVM294V1VSUFFFdFdZalE0WlVjeGNsSmtObmhBYURVNFZVZEFjRlZDZGtO"
	$string17 = "Yuii37DWU<<12"
	$string18 = ";while(hdnR9eo3pZ6E3<ZZeD3LjJQ.length){eMImGB"
condition:
	18 of them
}

rule fragus_js2
{
meta:
	author = "Josh Berry"
	date = "2016-06-26"
	description = "Fragus Exploit Kit Detection"
	hash0 = "f234c11b5da9a782cb1e554f520a66cf"
	sample_filetype = "js-html"
	yaragenerator = "https://github.com/Xen0ph0n/YaraGenerator"
strings:
	$string0 = "(ELI6Q3PZ"
	$string1 = "SnJTbVJqV2tOa09VbGZSMHcwY0ZWZmRrRjBjRFY0Y3psVmNGVjROWGhBV0RZNGJWZzBVa1J4TjNCVlgwVmlhRjkyZURaS1NWOUhj"
	$string2 = "eFgweDNaek5YZDFkaWFtTlhZbDlmV2tGa09Va3pSMlEyT0dwSFFIQlZRblpEYzBKRWNFeGZOVmx6V0RSU1JEYzJjRlY0TVY5SFkw"
	$string3 = "VUpKUVdWS05ISlZjMXBTTUdWRlNFQmpaMjlrVDBCTFYzY3pZbGRpZG5oeldFUndkSE16YjB4M2JXSnFZMWRpZVY4ellreDNaMko1"
	$string4 = "((Yuii37DWU"
	$string5 = "YURVNFZXUlhjRlZDZGxsQVJ6UlNaRTlBUzFkM00ySlhiekU0ZEhnMWNrUjZZM0kyWDNaQmJGZ3hNMGxrTmpoVGVqRlpkSEUyV1dW"
	$string6 = "String.fromCharCode(ZZeD3LjJQ);}else if(QIyZsvvbEmVOpp"
	$string7 = "1);ELI6Q3PZ"
	$string8 = "));Yuii37DWU"
	$string9 = ");CUer0x"
	$string10 = "T1ZaQ05IUkRTVGhqT1VWd1ZWOUpRMlZLZG5oNlQwQkxWM2N6WWxkQmRrRkFPVmR3VlRsYWJsWnNOWGhKT1ZkeFZWazFRbEU1UlZK"
	$string11 = "TlpkM2wxS3lzcExUUTRYU2s4UEhocFVqRk9jazA3SUdsbUtIaHBVakZPY2swcGV5QkdWek5NVnlzOVVrSklWVE0wVDJ0NlpTZzJP"
	$string12 = "String.fromCharCode(((eMImGB"
	$string13 = "RGRDUkV0WFV6VkJkRkV4WHpCalYwRkhhRFk0YW5wamNqWmZka0ZzV0RaSWExZzBXWEZDUlZsQVpEWkJOMEoyZUhwd1duSlRXVE5J"
	$string14 = "SCpMaWXOuME(mi1mm8bu87rL0W);eval(Pcii3iVk1AG);</script></body></html>"
	$string15 = "Yuii37DWU"
	$string16 = "Yuii37DWU<<12"
	$string17 = "eTVzWlc1bmRHZ3NJRWhWUnpWRlJuRkZSRVUwUFRFd01qUXNJR2hQVlZsRVJFVmxVaXdnZUVKU1FscE1ORzF3Y21SMGJpd2dSbGN6"
condition:
	17 of them
}

rule fragus_js_flash
{
meta:
	author = "Josh Berry"
	date = "2016-06-26"
	description = "Fragus Exploit Kit Detection"
	hash0 = "377431417b34de8592afecaea9aab95d"
	sample_filetype = "js-html"
	yaragenerator = "https://github.com/Xen0ph0n/YaraGenerator"
strings:
	$string0 = "document.appendChild(bdy);try{for (i"
	$string1 = "0; i<10; i"
	$string2 = "default"
	$string3 = "var m "
	$string4 = "/g, document.getElementById('divid').innerHTML));"
	$string5 = " n.substring(0,r/2);"
	$string6 = "document.getElementById('f').innerHTML"
	$string7 = "'atk' onclick"
	$string8 = "function MAKEHEAP()"
	$string9 = "document.createElement('div');"
	$string10 = "<button id"
	$string11 = "/g, document.getElementById('divid').innerHTML);"
	$string12 = "document.body.appendChild(gg);"
	$string13 = "var bdy "
	$string14 = "var gg"
	$string15 = " unescape(gg);while(n.length<r/2) { n"
condition:
	15 of them
}

rule fragus_js_java
{
meta:
	author = "Josh Berry"
	date = "2016-06-26"
	description = "Fragus Exploit Kit Detection"
	hash0 = "7398e435e68a2fa31607518befef30fb"
	sample_filetype = "js-html"
	yaragenerator = "https://github.com/Xen0ph0n/YaraGenerator"
strings:
	$string0 = "I></XML><SPAN DATASRC"
	$string1 = "setTimeout('vparivatel()',8000);function vparivatel(){document.write('<iframe src"
	$string2 = "I DATAFLD"
	$string3 = " unescape("
	$string4 = ", 1);swf.setAttribute("
	$string5 = "function XMLNEW(){var spray "
	$string6 = "vparivatel.php"
	$string7 = "6) ){if ( (lv"
	$string8 = "'WIN 9,0,16,0')"
	$string9 = "d:/Program Files/Outlook Express/WAB.EXE"
	$string10 = "<XML ID"
	$string11 = "new ActiveXObject("
	$string12 = "'7.1.0') ){SHOWPDF('iepdf.php"
	$string13 = "function SWF(){try{sv"
	$string14 = "'WIN 9,0,28,0')"
	$string15 = "C DATAFORMATAS"
	$string16 = " shellcode;xmlcode "
	$string17 = "function SNAPSHOT(){var a"
condition:
	17 of them
}

rule fragus_js_quicktime
{
meta:
	author = "Josh Berry"
	date = "2016-06-26"
	description = "Fragus Exploit Kit Detection"
	hash0 = "6bfc7bb877e1a79be24bd9563c768ffd"
	sample_filetype = "js-html"
	yaragenerator = "https://github.com/Xen0ph0n/YaraGenerator"
strings:
	$string0 = "                setTimeout("
	$string1 = "wnd.location"
	$string2 = "window;"
	$string3 = "        var pls "
	$string4 = "        mem_flag "
	$string5 = ", 1500);} else{ PRyyt4O3wvgz(1);}"
	$string6 = "         } catch(e) { }"
	$string7 = " mem_flag) JP7RXLyEu();"
	$string8 = " 0x400000;"
	$string9 = "----------------------------------------------------------------------------------------------------"
	$string10 = "        heapBlocks "
	$string11 = "        return mm;"
	$string12 = "0x38);"
	$string13 = "        h();"
	$string14 = " getb(b,bSize);"
	$string15 = "getfile.php"
condition:
	15 of them
}

rule fragus_js_vml
{
meta:
	author = "Josh Berry"
	date = "2016-06-26"
	description = "Fragus Exploit Kit Detection"
	hash0 = "8ab72337c815e0505fcfbc97686c3562"
	sample_filetype = "js-html"
	yaragenerator = "https://github.com/Xen0ph0n/YaraGenerator"
strings:
	$string0 = " 0x100000;"
	$string1 = "            var gg "
	$string2 = "/g, document.getElementById('divid').innerHTML));"
	$string3 = "                                var sss "
	$string4 = "                }"
	$string5 = "                        document.body.appendChild(obj);"
	$string6 = "                                var hbs "
	$string7 = " shcode; }"
	$string8 = " '<div id"
	$string9 = " hbs - (shcode.length"
	$string10 = "){ m[i] "
	$string11 = " unescape(gg);"
	$string12 = "                                var z "
	$string13 = "                                var hb "
	$string14 = " Math.ceil('0'"
condition:
	14 of them
}

rule generic_javascript_obfuscation
{
meta:
	author = "Josh Berry"
	date = "2016-06-28"
	description = "JavaScript Obfuscation Detection"
	sample_filetype = "js-html"
strings:
	$string0 = /eval\(([\s]+)?(unescape|atob)\(/ nocase
	$string1 = /var([\s]+)?([a-zA-Z_$])+([a-zA-Z0-9_$]+)?([\s]+)?=([\s]+)?\[([\s]+)?\"\\x[0-9a-fA-F]+/ nocase
	$string2 = /var([\s]+)?([a-zA-Z_$])+([a-zA-Z0-9_$]+)?([\s]+)?=([\s]+)?eval;/
condition:
	any of them
}

rule possible_includes_base64_packed_functions  
{ 
	meta: 
		impact = 5 
		hide = true 
		desc = "Detects possible includes and packed functions" 
	strings: 
		$f = /(atob|btoa|;base64|base64,)/ nocase
		//$ff = /(?:[A-Za-z0-9]{4}){2,}(?:[A-Za-z0-9]{2}[AEIMQUYcgkosw048]=|[A-Za-z0-9][AQgw]==)/ nocase 
		$fff = /([A-Za-z0-9]{4})*([A-Za-z0-9]{2}==|[A-Za-z0-9]{3}=|[A-Za-z0-9]{4})/ 
	condition: 
		$f and $fff
} 
 
rule BeEF_browser_hooked {
	meta:
		description = "Yara rule related to hook.js, BeEF Browser hooking capability"
		author = "Pasquale Stirparo"
		date = "2015-10-07"
		hash1 = "587e611f49baf63097ad2421ad0299b7b8403169ec22456fb6286abf051228db"
	strings:
		$s0 = "mitb.poisonAnchor" wide ascii
		$s1 = "this.request(this.httpproto" wide ascii
		$s2 = "beef.logger.get_dom_identifier" wide ascii
		$s3 = "return (!!window.opera" wide ascii 
		$s4 = "history.pushState({ Be:\"EF\" }" wide ascii 
		$s5 = "window.navigator.userAgent.match(/Opera\\/9\\.80.*Version\\/10\\./)" wide ascii 
		$s6 = "window.navigator.userAgent.match(/Opera\\/9\\.80.*Version\\/11\\./)" wide ascii 
		$s7 = "window.navigator.userAgent.match(/Avant TriCore/)" wide ascii 
		$s8 = "window.navigator.userAgent.match(/Iceweasel" wide ascii 
		$s9 = "mitb.sniff(" wide ascii 
		$s10 = "Method XMLHttpRequest.open override" wide ascii 
		$s11 = ".browser.hasWebSocket" wide ascii 
		$s12 = ".mitb.poisonForm" wide ascii 
		$s13 = "resolved=require.resolve(file,cwd||" wide ascii 
		$s14 = "if (document.domain == domain.replace(/(\\r\\n|\\n|\\r)/gm" wide ascii 
		$s15 = "beef.net.request" wide ascii 
		$s16 = "uagent.search(engineOpera)" wide ascii 
		$s17 = "mitb.sniff" wide ascii
		$s18 = "beef.logger.start" wide ascii
	condition:
		all of them
}

rule src_ptheft_command {
	meta:
		description = "Auto-generated rule - file command.js"
		author = "Pasquale Stirparo"
		reference = "not set"
		date = "2015-10-08"
		hash = "49c0e5400068924ff87729d9e1fece19acbfbd628d085f8df47b21519051b7f3"
	strings:
		$s0 = "var lilogo = 'http://content.linkedin.com/etc/designs/linkedin/katy/global/clientlibs/img/logo.png';" fullword wide ascii /* score: '38.00' */
		$s1 = "dark=document.getElementById('darkenScreenObject'); " fullword wide ascii /* score: '21.00' */
		$s2 = "beef.execute(function() {" fullword wide ascii /* score: '21.00' */
		$s3 = "var logo  = 'http://www.youtube.com/yt/brand/media/image/yt-brand-standard-logo-630px.png';" fullword wide ascii /* score: '32.42' */
		$s4 = "description.text('Enter your Apple ID e-mail address and password');" fullword wide ascii /* score: '28.00' */
		$s5 = "sneakydiv.innerHTML= '<div id=\"edge\" '+edgeborder+'><div id=\"window_container\" '+windowborder+ '><div id=\"title_bar\" ' +ti" wide ascii /* score: '28.00' */
		$s6 = "var logo  = 'https://www.yammer.com/favicon.ico';" fullword wide ascii /* score: '27.42' */
		$s7 = "beef.net.send('<%= @command_url %>', <%= @command_id %>, 'answer='+answer);" fullword wide ascii /* score: '26.00' */
		$s8 = "var title = 'Session Timed Out <img src=\"' + lilogo + '\" align=right height=20 width=70 alt=\"LinkedIn\">';" fullword wide ascii /* score: '24.00' */
		$s9 = "var title = 'Session Timed Out <img src=\"' + logo + '\" align=right height=20 width=70 alt=\"YouTube\">';" fullword wide ascii /* score: '24.00' */
		$s10 = "var title = 'Session Timed Out <img src=\"' + logo + '\" align=right height=24 width=24 alt=\"Yammer\">';" fullword wide ascii /* score: '24.00' */
		$s11 = "var logobox = 'style=\"border:4px #84ACDD solid;border-radius:7px;height:45px;width:45px;background:#ffffff\"';" fullword wide ascii /* score: '21.00' */
		$s12 = "sneakydiv.innerHTML= '<br><img src=\\''+imgr+'\\' width=\\'80px\\' height\\'80px\\' /><h2>Your session has timed out!</h2><p>For" wide ascii /* score: '23.00' */
		$s13 = "inner.append(title, description, user,password);" fullword wide ascii /* score: '23.00' */
		$s14 = "sneakydiv.innerHTML= '<div id=\"window_container\" '+windowborder+ '><div id=\"windowmain\" ' +windowmain+ '><div id=\"title_bar" wide ascii /* score: '23.00' */
		$s15 = "sneakydiv.innerHTML= '<div id=\"window_container\" '+windowborder+ '><div id=\"windowmain\" ' +windowmain+ '><div id=\"title_bar" wide ascii /* score: '23.00' */
		$s16 = "answer = document.getElementById('uname').value+':'+document.getElementById('pass').value;" fullword wide ascii /* score: '22.00' */
		$s17 = "password.keydown(function(event) {" fullword wide ascii /* score: '21.01' */
	condition:
		13 of them
}

rule malicious_author : PDF
{
	meta:
		author = "Glenn Edwards (@hiddenillusion)"
		version = "0.1"
		weight = 5
		
	strings:
		$magic = { 25 50 44 46 }
		
		$reg0 = /Creator.?\(yen vaw\)/
		$reg1 = /Title.?\(who cis\)/
		$reg2 = /Author.?\(ser pes\)/
	condition:
		$magic at 0 and all of ($reg*)
}

rule suspicious_version : PDF
{
	meta:
		author = "Glenn Edwards (@hiddenillusion)"
		version = "0.1"
		weight = 3
		
	strings:
		$magic = { 25 50 44 46 }
		$ver = /%PDF-1.\d{1}/
	condition:
		$magic at 0 and not $ver
}

rule suspicious_creation : PDF
{
	meta:
		author = "Glenn Edwards (@hiddenillusion)"
		version = "0.1"
		weight = 2
		
	strings:
		$magic = { 25 50 44 46 }
		$header = /%PDF-1\.(3|4|6)/
		
		$create0 = /CreationDate \(D:20101015142358\)/
		$create1 = /CreationDate \(2008312053854\)/
	condition:
		$magic at 0 and $header and 1 of ($create*)
}

rule suspicious_title : PDF
{
	meta:
		author = "Glenn Edwards (@hiddenillusion)"
		version = "0.1"
		weight = 4
		
	strings:
		$magic = { 25 50 44 46 }
		$header = /%PDF-1\.(3|4|6)/
		
		$title0 = "who cis"
		$title1 = "P66N7FF"
		$title2 = "Fohcirya"
	condition:
		$magic at 0 and $header and 1 of ($title*)
}

rule suspicious_author : PDF
{
	meta:
		author = "Glenn Edwards (@hiddenillusion)"
		version = "0.1"
		weight = 4
		
	strings:
		$magic = { 25 50 44 46 }
		$header = /%PDF-1\.(3|4|6)/

		$author0 = "Ubzg1QUbzuzgUbRjvcUb14RjUb1"
		$author1 = "ser pes"
		$author2 = "Miekiemoes"
		$author3 = "Nsarkolke"
	condition:
		$magic at 0 and $header and 1 of ($author*)
}

rule suspicious_producer : PDF
{
	meta:
		author = "Glenn Edwards (@hiddenillusion)"
		version = "0.1"
		weight = 2
		
	strings:
		$magic = { 25 50 44 46 }
		$header = /%PDF-1\.(3|4|6)/
		
		$producer0 = /Producer \(Scribus PDF Library/
		$producer1 = "Notepad"
	condition:
		$magic at 0 and $header and 1 of ($producer*)
}

rule suspicious_creator : PDF
{
	meta:
		author = "Glenn Edwards (@hiddenillusion)"
		version = "0.1"
		weight = 3
		
	strings:
		$magic = { 25 50 44 46 }
		$header = /%PDF-1\.(3|4|6)/
		
		$creator0 = "yen vaw"
		$creator1 = "Scribus"
		$creator2 = "Viraciregavi"
	condition:
		$magic at 0 and $header and 1 of ($creator*)
}

rule possible_exploit : PDF
{
	meta:
		author = "Glenn Edwards (@hiddenillusion)"
		version = "0.1"
		weight = 3
		
	strings:
		$magic = { 25 50 44 46 }
		
		$attrib0 = /\/JavaScript /
		$attrib3 = /\/ASCIIHexDecode/
		$attrib4 = /\/ASCII85Decode/

		$action0 = /\/Action/
		$action1 = "Array"
		$shell = "A"
		$cond0 = "unescape"
		$cond1 = "String.fromCharCode"
		
		$nop = "%u9090%u9090"
	condition:
		$magic at 0 and (2 of ($attrib*)) or ($action0 and #shell > 10 and 1 of ($cond*)) or ($action1 and $cond0 and $nop)
}

rule shellcode_blob_metadata : PDF
{
        meta:
                author = "Glenn Edwards (@hiddenillusion)"
                version = "0.1"
                description = "When there's a large Base64 blob inserted into metadata fields it often indicates shellcode to later be decoded"
                weight = 4
        strings:
                $magic = { 25 50 44 46 }

                $reg_keyword = /\/Keywords.?\(([a-zA-Z0-9]{200,})/ //~6k was observed in BHEHv2 PDF exploits holding the shellcode
                $reg_author = /\/Author.?\(([a-zA-Z0-9]{200,})/
                $reg_title = /\/Title.?\(([a-zA-Z0-9]{200,})/
                $reg_producer = /\/Producer.?\(([a-zA-Z0-9]{200,})/
                $reg_creator = /\/Creator.?\(([a-zA-Z0-9]{300,})/
                $reg_create = /\/CreationDate.?\(([a-zA-Z0-9]{200,})/

        condition:
                $magic at 0 and 1 of ($reg*)
}

rule multiple_filtering : PDF 
{
        meta: 
                author = "Glenn Edwards (@hiddenillusion)"
                version = "0.2"
                weight = 3
                
        strings:
                $magic = { 25 50 44 46 }
                $attrib = /\/Filter.*?(\/ASCIIHexDecode\W+|\/LZWDecode\W+|\/ASCII85Decode\W+|\/FlateDecode\W+|\/RunLengthDecode){2}/           
				// left out: /CCITTFaxDecode, JBIG2Decode, DCTDecode, JPXDecode, Crypt

        condition: 
                $magic at 0 and $attrib
}

rule suspicious_js : PDF
{
	meta:
		author = "Glenn Edwards (@hiddenillusion)"
		version = "0.1"
		weight = 3
		
	strings:
		$magic = { 25 50 44 46 }
		
		$attrib0 = /\/OpenAction /
		$attrib1 = /\/JavaScript /

		$js0 = "eval"
		$js1 = "Array"
		$js2 = "String.fromCharCode"
		
	condition:
		$magic at 0 and all of ($attrib*) and 2 of ($js*)
}

rule suspicious_launch_action : PDF
{
	meta:
		author = "Glenn Edwards (@hiddenillusion)"
		version = "0.1"
		weight = 2
		
	strings:
		$magic = { 25 50 44 46 }
		
		$attrib0 = /\/Launch/
		$attrib1 = /\/URL /
		$attrib2 = /\/Action/
		$attrib3 = /\/F /

	condition:
		$magic at 0 and 3 of ($attrib*)
}

rule suspicious_embed : PDF
{
	meta:
		author = "Glenn Edwards (@hiddenillusion)"
		version = "0.1"
		ref = "https://feliam.wordpress.com/2010/01/13/generic-pdf-exploit-hider-embedpdf-py-and-goodbye-av-detection-012010/"
		weight = 2
		
	strings:
		$magic = { 25 50 44 46 }
		
		$meth0 = /\/Launch/
		$meth1 = /\/GoTo(E|R)/ //means go to embedded or remote
		$attrib0 = /\/URL /
		$attrib1 = /\/Action/
		$attrib2 = /\/Filespec/
		
	condition:
		$magic at 0 and 1 of ($meth*) and 2 of ($attrib*)
}

rule suspicious_obfuscation : PDF
{
	meta:
		author = "Glenn Edwards (@hiddenillusion)"
		version = "0.1"
		weight = 2
		
	strings:
		$magic = { 25 50 44 46 }
		$reg = /\/\w#[a-zA-Z0-9]{2}#[a-zA-Z0-9]{2}/
		
	condition:
		$magic at 0 and #reg > 5
}

rule invalid_XObject_js : PDF
{
	meta:
		author = "Glenn Edwards (@hiddenillusion)"
		description = "XObject's require v1.4+"
		ref = "https://blogs.adobe.com/ReferenceXObjects/"
		version = "0.1"
		weight = 2
		
	strings:
		$magic = { 25 50 44 46 }
		$ver = /%PDF-1\.[4-9]/
		
		$attrib0 = /\/XObject/
		$attrib1 = /\/JavaScript/
		
	condition:
		$magic at 0 and not $ver and all of ($attrib*)
}

rule invalid_trailer_structure : PDF
{
	meta:
		author = "Glenn Edwards (@hiddenillusion)"
		version = "0.1"
		weight = 1
		
        strings:
                $magic = { 25 50 44 46 }
				// Required for a valid PDF
                $reg0 = /trailer\r?\n?.*\/Size.*\r?\n?\.*/
                $reg1 = /\/Root.*\r?\n?.*startxref\r?\n?.*\r?\n?%%EOF/

        condition:
                $magic at 0 and not $reg0 and not $reg1
}

rule multiple_versions : PDF
{
	meta:
		author = "Glenn Edwards (@hiddenillusion)"
		version = "0.1"
        description = "Written very generically and doesn't hold any weight - just something that might be useful to know about to help show incremental updates to the file being analyzed"		
		weight = 0
		
        strings:
                $magic = { 25 50 44 46 }
                $s0 = "trailer"
                $s1 = "%%EOF"

        condition:
                $magic at 0 and #s0 > 1 and #s1 > 1
}

rule js_wrong_version : PDF
{
	meta:
		author = "Glenn Edwards (@hiddenillusion)"
		description = "JavaScript was introduced in v1.3"
		ref = "http://wwwimages.adobe.com/www.adobe.com/content/dam/Adobe/en/devnet/pdf/pdfs/pdf_reference_1-7.pdf"
		version = "0.1"
		weight = 2
		
        strings:
                $magic = { 25 50 44 46 }
				$js = /\/JavaScript/
				$ver = /%PDF-1\.[3-9]/

        condition:
                $magic at 0 and $js and not $ver
}

rule JBIG2_wrong_version : PDF
{
	meta:
		author = "Glenn Edwards (@hiddenillusion)"
		description = "JBIG2 was introduced in v1.4"
		ref = "http://wwwimages.adobe.com/www.adobe.com/content/dam/Adobe/en/devnet/pdf/pdfs/pdf_reference_1-7.pdf"
		version = "0.1"
		weight = 1
		
        strings:
                $magic = { 25 50 44 46 }
				$js = /\/JBIG2Decode/
				$ver = /%PDF-1\.[4-9]/

        condition:
                $magic at 0 and $js and not $ver
}

rule FlateDecode_wrong_version : PDF
{
	meta:
		author = "Glenn Edwards (@hiddenillusion)"
		description = "Flate was introduced in v1.2"
		ref = "http://wwwimages.adobe.com/www.adobe.com/content/dam/Adobe/en/devnet/pdf/pdfs/pdf_reference_1-7.pdf"
		version = "0.1"
		weight = 1
		
        strings:
                $magic = { 25 50 44 46 }
				$js = /\/FlateDecode/
				$ver = /%PDF-1\.[2-9]/

        condition:
                $magic at 0 and $js and not $ver
}

rule embed_wrong_version : PDF
{
	meta:
		author = "Glenn Edwards (@hiddenillusion)"
		description = "EmbeddedFiles were introduced in v1.3"
		ref = "http://wwwimages.adobe.com/www.adobe.com/content/dam/Adobe/en/devnet/pdf/pdfs/pdf_reference_1-7.pdf"
		version = "0.1"
		weight = 1
		
        strings:
                $magic = { 25 50 44 46 }
				$embed = /\/EmbeddedFiles/
				$ver = /%PDF-1\.[3-9]/

        condition:
                $magic at 0 and $embed and not $ver
}

rule invalid_xref_numbers : PDF
{
        meta:
			author = "Glenn Edwards (@hiddenillusion)"
			version = "0.1"
			description = "The first entry in a cross-reference table is always free and has a generation number of 65,535"
			notes = "This can be also be in a stream..."
			weight = 1
		
        strings:
                $magic = { 25 50 44 46 }
                $reg0 = /xref\r?\n?.*\r?\n?.*65535\sf/
                $reg1 = /endstream.*?\r?\n?endobj.*?\r?\n?startxref/
        condition:
                $magic at 0 and not $reg0 and not $reg1
}

rule js_splitting : PDF
{
        meta:
                author = "Glenn Edwards (@hiddenillusion)"
                version = "0.1"
                description = "These are commonly used to split up JS code"
                weight = 2
                
        strings:
                $magic = { 25 50 44 46 }
				$js = /\/JavaScript/
                $s0 = "getAnnots"
                $s1 = "getPageNumWords"
                $s2 = "getPageNthWord"
                $s3 = "this.info"
                                
        condition:
                $magic at 0 and $js and 1 of ($s*)
}

rule BlackHole_v2 : PDF
{
	meta:
		author = "Glenn Edwards (@hiddenillusion)"
		version = "0.1"
		ref = "http://fortknoxnetworks.blogspot.no/2012/10/blackhhole-exploit-kit-v-20-url-pattern.html"
		weight = 3
		
	strings:
		$magic = { 25 50 44 46 }
		$content = "Index[5 1 7 1 9 4 23 4 50"
		
	condition:
		$magic at 0 and $content
}


rule XDP_embedded_PDF : PDF
{
	meta:
		author = "Glenn Edwards (@hiddenillusion)"
		version = "0.1"
		ref = "http://blog.9bplus.com/av-bypass-for-malicious-pdfs-using-xdp"
        weight = 1		

	strings:
		$s1 = "<pdf xmlns="
		$s2 = "<chunk>"
		$s3 = "</pdf>"
		$header0 = "%PDF"
		$header1 = "JVBERi0"

	condition:
		all of ($s*) and 1 of ($header*)
}

rule FlashNewfunction: decodedPDF
{
   meta:  
      ref = "CVE-2010-1297"
      hide = true
      impact = 5 
      ref = "http://blog.xanda.org/tag/jsunpack/"
   strings:
      $unescape = "unescape" fullword nocase
      $shellcode = /%u[A-Fa-f0-9]{4}/
      $shellcode5 = /(%u[A-Fa-f0-9]{4}){5}/
      $cve20101297 = /\/Subtype ?\/Flash/
   condition:
      ($unescape and $shellcode and $cve20101297) or ($shellcode5 and $cve20101297)
}

rule phoenix_html
{
meta:
	author = "Josh Berry"
	date = "2016-06-26"
	description = "Phoenix Exploit Kit Detection"
	hash0 = "8395f08f1371eb7b2a2e131b92037f9a"
	sample_filetype = "js-html"
	yaragenerator = "https://github.com/Xen0ph0n/YaraGenerator"
strings:
	$string1 = "'></applet><body id"
	$string2 = "<applet mayscript"
	$string3 = "/gmi,String.fromCharCode(2"
	$string4 = "/gmi,' ').replace(/"
	$string5 = "pe;i;;.j1s->c"
	$string6 = "es4Det"
	$string7 = "<textarea>function"
        $string8 = ".replace(/"
	$string9 = ".jar' code"
	$string10 = ";iFc;ft'b)h{s"
condition:
	10 of them
}

rule phoenix_html10
{
meta:
	author = "Josh Berry"
	date = "2016-06-26"
	description = "Phoenix Exploit Kit Detection"
	hash0 = "f5f8dceca74a50076070f2593e82ec43"
	sample_filetype = "js-html"
	yaragenerator = "https://github.com/Xen0ph0n/YaraGenerator"
strings:
	$string0 = "pae>crAeahoilL"
	$string1 = "D11C0002C0069733E60656F6462070D000402DFF200696E"
	$string2 = "nbte)bbn"
	$string3 = "v9o16,0')0B80002328203;)82F00223A216ifA160A262A462(a"
	$string4 = "0442DFD2E30EC80E42D2E00AC3F3D53C9CAEBFF7E1E805080B044057CB1C0EF7F263DC64E0CBE47C2A21E370EE4A"
	$string5 = ";)npeits0e.uvr;][tvr"
	$string6 = "433EBE90242003E00C606D04036563435805000102000v020E656wa.i118,0',9F902F282620''C62022646660}{A780232A"
	$string7 = "350;var ysjzyq"
	$string8 = "aSmd'lm/t/im.}d.-Ljg,l-"
	$string9 = "0017687F6164706E6967060002008101'2176045ckb"
	$string10 = "63(dcma)nenn869"
	$string11 = "').replace(/"
	$string12 = "xd'c0lrls09sare"
	$string13 = "(]t.(7u(<p"
	$string14 = "d{et;bdBcriYtc:eayF20'F62;23C4AABA3B84FE21C2B0B066C0038B8353AF5C0B4DF8FF43E85FB6F05CEC4080236F3CDE6E"
	$string15 = "/var another;</textarea>"
	$string16 = "Fa527496C62eShHmar(bA,pPec"
	$string17 = "FaA244A676C,150e62A5B2B61,'2F"
condition:
	17 of them
}

rule phoenix_html11
{
meta:
	author = "Josh Berry"
	date = "2016-06-26"
	description = "Phoenix Exploit Kit Detection"
	hash0 = "be8c81288f9650e205ed13f3167ce256"
	sample_filetype = "js-html"
	yaragenerator = "https://github.com/Xen0ph0n/YaraGenerator"
strings:
	$string0 = "D'0009F0C6941617C43427A76080001000F47020C606volv99,0,6,"
	$string1 = "';)nWd"
	$string2 = "IW'eeCn)s.a9e;0CF300FF379011078E047873754163636960496270486264416455747D69737812060209011301010104D0"
	$string3 = "D8D51F5100019006D60667F2E056940170E01010747"
	$string4 = "515F2F436WemBh2A4560683aFanoi(utse.o1/f;pistelzi"
	$string5 = "/p(e/oah)FHw'aaarDsnwi-"
	$string6 = "COa506u%db10u%1057u%f850u%f500u%0683u%05a8u%0030u%0706u%d300u%585du%38d0u%0080u%5612u'u%A2DdF6u%1M:."
	$string7 = "S(yt)Dj"
	$string8 = "FaA26285325,150e8292A6968,'2F"
	$string9 = "0200e{b<0:D>r5d4u%c005u%0028u%251eu%a095u%6028u%0028u%2500u%f7f7u%70d7u%2025u%9008u%08f8u%c607usu%37"
	$string10 = "(mEtlltopo{{e"
	$string11 = "aSmd'lm/t/im.}d.-Ljg,l-"
	$string12 = "r)C4snfapfuo}"
	$string13 = "').replace(/"
	$string14 = "A282A5ifA160F2628206(a"
	$string15 = "obn0cf"
	$string16 = "d(i'C)rtr.'pvif)iv1ilW)S((Ltl.)2,0,9;0se"
	$string17 = "E23s3003476B18703C179396D08B841BC554F11678F0FEB9505FB355E044F33A540F61743738327E32D97D070FA37D87s000"
	$string18 = "603742E545904575'294E20680,6F902E292A60''E6202A4E6468},e))tep"
condition:
	18 of them
}

rule phoenix_html2
{
meta:
	author = "Josh Berry"
	date = "2016-06-26"
	description = "Phoenix Exploit Kit Detection"
	hash0 = "2fd263f5d988a92715f4146a0006cb31"
	sample_filetype = "js-html"
	yaragenerator = "https://github.com/Xen0ph0n/YaraGenerator"
strings:
	$string0 = "Pec.lilsD)E)i-gonP(mgge.eOmn"
	$string1 = "(trt;oo"
	$string2 = "aceeC:0h"
	$string3 = "Vubb.oec.n)a."
	$string4 = "t;o{(bspd}ci:0OO[g(cfjdh}1sN}ntnrlt;0pwf{-"
	$string5 = "seierb)gMle(}ev;is{(b;ga"
	$string6 = "e)}ift"
	$string7 = "Dud{rt"
	$string8 = "blecroeely}diuFI-"
	$string9 = "ttec]tr"
	$string10 = "fSgcso"
	$string11 = "eig.t)eR{t}aeesbdtbl{1sr)m"
	$string12 = ").}n,Raa.s"
	$string13 = "sLtfcb.nrf{Wiantscncad1ac)scb0eo]}Diuu(nar"
	$string14 = "dxc.,:tfr(ucxRn"
	$string15 = "eDnnforbyri(tbmns).[i.ee;dl(aNimp(l(h[u[ti;u)"
	$string16 = "}tn)i{ebr,_.ns(Nes,,gm(ar.t"
	$string17 = "l]it}N(pe3,iaaLds.)lqea:Ps00Hc;[{Euihlc)LiLI"
condition:
	17 of them
}

rule phoenix_html3
{
meta:
	author = "Josh Berry"
	date = "2016-06-26"
	description = "Phoenix Exploit Kit Detection"
	hash0 = "d7cacbff6438d866998fc8bfee18102d"
	sample_filetype = "js-html"
	yaragenerator = "https://github.com/Xen0ph0n/YaraGenerator"
strings:
	$string0 = "mtfla/,)asaf)'}"
	$string1 = "72267E7C'A3035CFC415DFAAA834B208D8C230FD303E2EFFE386BE05960C588C6E85650746E690C39F706F97DC74349BA134"
	$string2 = "N'eiui7F6e617e00F145A002645E527BFF264842F877B2FFC1FE84BCC6A50F0305B5B0C36A019F53674FD4D3736C494BD5C2"
	$string3 = "lndl}})<>"
	$string4 = "otodc};b<0:D>r5d4u%c005u%0028u%251eu%a095u%6028u%0028u%2500u%f7f7u%70d7u%2025u%9008u%08f8u%c607usu%3"
	$string5 = "tuJaboaopb"
	$string6 = "a(vxf{p'tSowa.i,1NIWm("
	$string7 = "2004et"
	$string8 = "2054sttE5356496478"
	$string9 = "yi%A%%A%%A%%A%Cvld3,5314,004,6211,931,,,011394617,983,1154,5,1,,1,1,13,08,4304,1"
	$string10 = "0ovel04ervEeieeem)h))B(ihsAE;u%04b8u%1c08u%0e50u%a000u%1010u%4000u%20afu%0006u%2478u%0020u%1065u%210"
	$string11 = "/gmi,String.fromCharCode(2"
	$string12 = "ncBcaocta.ye"
	$string13 = "0201010030004A033102090;na"
	$string14 = "66u%0(ec'h{iis%%A%%A%%A%%A%frS1,,8187,1,4,11,91516,,61,,10841,1,13,,,11248,01818849,23,,,,791meits0e"
	$string15 = "D11C0002C0069733E60656F6462070D000402DFF200696E"
	$string16 = "810p0y98"
	$string17 = "9,0,e'Fm692E583760"
	$string18 = "57784234633a)(u"
condition:
	18 of them
}

rule phoenix_html4
{
meta:
	author = "Josh Berry"
	date = "2016-06-26"
	description = "Phoenix Exploit Kit Detection"
	hash0 = "61fde003211ac83c2884fbecefe1fc80"
	sample_filetype = "js-html"
	yaragenerator = "https://github.com/Xen0ph0n/YaraGenerator"
strings:
	$string0 = "/dr.php"
	$string1 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
	$string2 = "launchjnlp"
	$string3 = "clsid:CAFEEFAC-DEC7-0000-0000-ABCDEFFEDCBA"
	$string4 = "urlmon.dll"
	$string5 = "<body>"
	$string6 = " docbase"
	$string7 = "</html>"
	$string8 = " classid"
	$string9 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
	$string10 = "63AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
	$string11 = "</object>"
	$string12 = "application/x-java-applet"
	$string13 = "java_obj"
condition:
	13 of them
}

rule phoenix_html5
{
meta:
	author = "Josh Berry"
	date = "2016-06-26"
	description = "Phoenix Exploit Kit Detection"
	hash0 = "30afdca94d301905819e00a7458f4a4e"
	sample_filetype = "js-html"
	yaragenerator = "https://github.com/Xen0ph0n/YaraGenerator"
strings:
	$string0 = "dtesu}"
	$string1 = "<textarea>function gvgsxoy(gwcqg1){return gwcqg1.replace(/"
	$string2 = "v}Ahnhxwet"
	$string3 = "0125C6BBA2B84F7A1D2940C04C8B7449A40EEB0D14C8003535C0042D75E05F0D7F3E0A7B4E33EB4D8D47119290FC"
	$string4 = "a2Fs2325223869e'Fm2873367130"
	$string5 = "m0000F0F6E66607C71646F6607000107FA61021F6060(aeWWIN"
	$string6 = ")(r>hd1/dNasmd(fpas"
	$string7 = "9,0,e'Fm692E583760"
	$string8 = "5ud(dis"
	$string9 = "nacmambuntcmi"
	$string10 = "Fa078597467,1C0e674366871,'2F"
	$string11 = "Fa56F386A76,180e828592024,'2F"
	$string12 = "alA)(2avoyOi;ic)t6])teptp,an}tnv0i'fms<uic"
	$string13 = "iR'nandee"
	$string14 = "('0.aEa-9leal"
	$string15 = "bsD0seF"
	$string16 = "t.ck263/6F3a001CE7A2684067F98BEC18B738801EF1F7F7E49A088695050C000865FC38080FE23727E0E8DE9CB53E748472"
condition:
	16 of them
}

rule phoenix_html6
{
meta:
	author = "Josh Berry"
	date = "2016-06-26"
	description = "Phoenix Exploit Kit Detection"
	hash0 = "4aabb710cf04240d26c13dd2b0ccd6cc"
	sample_filetype = "js-html"
	yaragenerator = "https://github.com/Xen0ph0n/YaraGenerator"
strings:
	$string0 = "F4B6B2E67)A780A373A633;ast2316363677fa'es6F3635244"
	$string1 = "piia.a}rneecc.cnuoir"
	$string2 = "0448D5A54BE10A5DA628100AC3F3D53C9CAEBFF7E1E805080B044057CB1C0EF7F263DC64E0CBE47C2A21E55E9EA620000106"
	$string3 = "],enEn..o"
	$string4 = "o;1()sna"
	$string5 = "(eres(0.,"
	$string6 = "}fs2he}o.t"
	$string7 = "f'u>jisch3;)Ie)C'eO"
	$string8 = "refhiacei"
	$string9 = "0026632528(sCE7A2684067F98BEC1s00000F512Fm286631666"
	$string10 = "vev%80b4u%ee18u%28b8u%2617u%5c08u%0e50u%a000u%9006u%76efu%b1cbu%ba2fu%6850u%0524u%9720u%f70<}1msa950"
	$string11 = "pdu,xziien,ie"
	$string12 = "rr)l;.)vr.nbl"
	$string13 = "ii)ruccs)1e"
	$string14 = "F30476737930anD<tAhnhxwet"
	$string15 = ")yf{(ee..erneef"
	$string16 = "ieiiXuMkCSwetEet"
	$string17 = "F308477E7A7itme"
condition:
	17 of them
}

rule phoenix_html7
{
meta:
	author = "Josh Berry"
	date = "2016-06-26"
	description = "Phoenix Exploit Kit Detection"
	hash0 = "f0e1b391ec3ce515fd617648bec11681"
	sample_filetype = "js-html"
	yaragenerator = "https://github.com/Xen0ph0n/YaraGenerator"
strings:
	$string0 = "EBF0a0001B05D266503046C7A491A0C00044F0002035D0D0twl''WIN"
	$string1 = "ah80672528657"
	$string2 = "n);tctt)Eltc(Dj"
	$string3 = ";cnt2<tEf"
	$string4 = "iwkne){bvfvgzg5"
	$string5 = "..'an{ea-Ect'8-huJ.)/l'/tCaaa}<Ct95l"
	$string6 = "'WIWhaFtF662F6577IseFe427347637"
	$string7 = "ddTh75e{"
	$string8 = "Ae'n,,9"
	$string9 = "%E7E3Vemtyi"
	$string10 = "cf'treran"
	$string11 = "ncBcaocta.ye"
	$string12 = ")'0,p8k"
	$string13 = "0;{tc4F}c;eptdpduoCuuedPl80evD"
	$string14 = "iq,q,Nd(nccfr'Bearc'nBtpw"
	$string15 = ";)npeits0e.uvhF$I'"
	$string16 = "nvasai0.-"
	$string17 = "lmzv'is'"
condition:
	17 of them
}

rule phoenix_html8
{
meta:
	author = "Josh Berry"
	date = "2016-06-26"
	description = "Phoenix Exploit Kit Detection"
	hash0 = "1c19a863fc4f8b13c0c7eb5e231bc3d1"
	sample_filetype = "js-html"
	yaragenerator = "https://github.com/Xen0ph0n/YaraGenerator"
strings:
	$string0 = "0x5)).replace(/"
	$string1 = "%A%%A%%nc(,145,9,84037,1711,,4121,56,1,,0505,,651,,3,514101,01,29,7868,90"
	$string2 = "/gmi,String.fromCharCode(2"
	$string3 = "turt;oo)s"
	$string4 = "91;var jtdpar"
	$string5 = "R(,13,7,63,48140601,5057,,319,,6,1,1,2,,110,0,1011171,2319,,,,10vEAs)tfmneyeh%A%%A%%A%%A%s<u91,4693,"
	$string6 = "y%%A%%A%%A%%A.meo21117,7,1,,10,1,9,8,1,9,100,6,141003,74181,163,441114,43,207,,remc'ut"
	$string7 = "epjtjqe){jtdpar"
	$string8 = "/gmi,'"
	$string9 = "<font></font><body id"
	$string10 = " epjtjqe; fqczi > 0; fqczi--){for (bwjmgl7 "
	$string11 = "nbte)bb(egs%A%%A%%A%%A%%m"
	$string12 = "fvC9614165,,,1,1801151030,,0,,487641114,,1,141,914810036,,888,201te.)'etdc:ysaA%%A%%A%%A%%5sao,61,0,"
	$string13 = "(tiAmrd{/tnA%%A%%A%%A%%Aiin11,,1637,34191,626958314,11007,,61145,411,7,9,1821,,43,8311,26;d'ebt.dyvs"
	$string14 = "A%%A%%A%%Ao"
	$string15 = "hrksywd(cpkwisk4);/"
	$string16 = ";</script>"
condition:
	16 of them
}

rule phoenix_html9
{
meta:
	author = "Josh Berry"
	date = "2016-06-26"
	description = "Phoenix Exploit Kit Detection"
	hash0 = "742d012b9df0c27ed6ccf3b234db20db"
	sample_filetype = "js-html"
	yaragenerator = "https://github.com/Xen0ph0n/YaraGenerator"
strings:
	$string0 = "tute)bbr:"
	$string1 = "nfho(tghRx"
	$string2 = "()irfE/Rt..cOcC"
	$string3 = "NcEnevbf"
	$string4 = "63FB8B4296BBC290A0.'0000079'Fh20216B6A6arA;<"
	$string5 = "wHe(cLnyeyet(a.i,r.{.."
	$string6 = "tute)bbdfiiix'bcr"
	$string7 = "itifdf)d1L2f'asau%d004u%8e00u%0419u%a58du%2093u%ec10u%0050u%00d4u%4622u%bcd1u%b1ceu%5000u%f7f5u%5606"
	$string8 = "2F4693529783'82F076676C38'te"
	$string9 = "sm(teoeoi)cfh))pihnipeeeo}.,(.(("
	$string10 = "ao)ntavlll{))ynlcoix}hiN.il'tes1ad)bm;"
	$string11 = "i)}m0f(eClei(/te"
	$string12 = "}aetsc"
	$string13 = "irefnig.pT"
	$string14 = "a0mrIif/tbne,(wsk,"
	$string15 = "500F14B06000000630E6B72636F60632C6E711C6E762E646F147F44767F650A0804061901020009006B120005A2006L"
	$string16 = ".hB.Csf)ddeSs"
	$string17 = "tnne,IPd4Le"
	$string18 = "hMdarc'nBtpw"
condition:
	18 of them
}

rule phoenix_jar
{
meta:
	author = "Josh Berry"
	date = "2016-06-26"
	description = "Phoenix Exploit Kit Detection"
	hash0 = "a8a18219b02d30f44799415ff19c518e"
	sample_filetype = "unknown"
	yaragenerator = "https://github.com/Xen0ph0n/YaraGenerator"
strings:
	$string0 = "r.JM,IM"
	$string1 = "qX$8$a"
	$string2 = "META-INF/services/javax.sound.midi.spi.MidiDeviceProvider5"
	$string3 = "a.classPK"
	$string4 = "6;\\Q]Q"
	$string5 = "h[s] X"
	$string6 = "ToolsDemoSubClass.classPK"
	$string7 = "a.class"
	$string8 = "META-INF/MANIFEST.MFPK"
	$string9 = "ToolsDemoSubClass.classeO"
	$string10 = "META-INF/services/javax.sound.midi.spi.MidiDeviceProviderPK"
condition:
	10 of them
}

rule phoenix_jar2
{
meta:
	author = "Josh Berry"
	date = "2016-06-26"
	description = "Phoenix Exploit Kit Detection"
	hash0 = "989c5b5eaddf48010e62343d7a4db6f4"
	sample_filetype = "unknown"
	yaragenerator = "https://github.com/Xen0ph0n/YaraGenerator"
strings:
	$string0 = "a66d578f084.classeQ"
	$string1 = "a4cb9b1a8a5.class"
	$string2 = ")szNu\\MutK"
	$string3 = "qCCwBU"
	$string4 = "META-INF/MANIFEST.MF"
	$string5 = "QR,GOX"
	$string6 = "ab5601d4848.classmT"
	$string7 = "a6a7a760c0e["
	$string8 = "2ZUK[L"
	$string9 = "2VT(Au5"
	$string10 = "a6a7a760c0ePK"
	$string11 = "aa79d1019d8.class"
	$string12 = "aa79d1019d8.classPK"
	$string13 = "META-INF/MANIFEST.MFPK"
	$string14 = "ab5601d4848.classPK"
condition:
	14 of them
}

rule phoenix_jar3
{
meta:
	author = "Josh Berry"
	date = "2016-06-26"
	description = "Phoenix Exploit Kit Detection"
	hash0 = "c5655c496949f8071e41ea9ac011cab2"
	sample_filetype = "unknown"
	yaragenerator = "https://github.com/Xen0ph0n/YaraGenerator"
strings:
	$string0 = "'> >$>"
	$string1 = "bpac/PK"
	$string2 = "bpac/purok$1.classmP]K"
	$string3 = "bpac/KAVS.classmQ"
	$string4 = "'n n$n"
	$string5 = "bpac/purok$1.classPK"
	$string6 = "$.4aX,Gt<"
	$string7 = "bpac/KAVS.classPK"
	$string8 = "bpac/b.classPK"
	$string9 = "bpac/b.class"
condition:
	9 of them
}

rule phoenix_pdf
{
meta:
	author = "Josh Berry"
	date = "2016-06-26"
	description = "Phoenix Exploit Kit Detection"
	hash0 = "16de68e66cab08d642a669bf377368da"
	hash1 = "bab281fe0cf3a16a396550b15d9167d5"
	sample_filetype = "pdf"
	yaragenerator = "https://github.com/Xen0ph0n/YaraGenerator"
strings:
	$string0 = "0000000254 00000 n"
	$string1 = "0000000295 00000 n"
	$string2 = "trailer<</Root 1 0 R /Size 7>>"
	$string3 = "0000000000 65535 f"
	$string4 = "3 0 obj<</JavaScript 5 0 R >>endobj"
	$string5 = "0000000120 00000 n"
	$string6 = "%PDF-1.0"
	$string7 = "startxref"
	$string8 = "0000000068 00000 n"
	$string9 = "endobjxref"
	$string10 = ")6 0 R ]>>endobj"
	$string11 = "0000000010 00000 n"
condition:
	11 of them
}

rule phoenix_pdf2
{
meta:
	author = "Josh Berry"
	date = "2016-06-26"
	description = "Phoenix Exploit Kit Detection"
	hash0 = "33cb6c67f58609aa853e80f718ab106a"
	sample_filetype = "pdf"
	yaragenerator = "https://github.com/Xen0ph0n/YaraGenerator"
strings:
	$string0 = "\\nQb<%"
	$string1 = "0000000254 00000 n"
	$string2 = ":S3>v0$EF"
	$string3 = "trailer<</Root 1 0 R /Size 7>>"
	$string4 = "%PDF-1.0"
	$string5 = "0000000000 65535 f"
	$string6 = "endstream"
	$string7 = "0000000010 00000 n"
	$string8 = "6 0 obj<</JS 7 0 R/S/JavaScript>>endobj"
	$string9 = "3 0 obj<</JavaScript 5 0 R >>endobj"
	$string10 = "}pr2IE"
	$string11 = "0000000157 00000 n"
	$string12 = "1 0 obj<</Type/Catalog/Pages 2 0 R /Names 3 0 R >>endobj"
	$string13 = "5 0 obj<</Names[("
condition:
	13 of them
}

rule phoenix_pdf3
{
meta:
	author = "Josh Berry"
	date = "2016-06-26"
	description = "Phoenix Exploit Kit Detection"
	hash0 = "bab281fe0cf3a16a396550b15d9167d5"
	sample_filetype = "pdf"
	yaragenerator = "https://github.com/Xen0ph0n/YaraGenerator"
strings:
	$string0 = "trailer<</Root 1 0 R /Size 7>>"
	$string1 = "stream"
	$string2 = ";_oI5z"
	$string3 = "0000000010 00000 n"
	$string4 = "3 0 obj<</JavaScript 5 0 R >>endobj"
	$string5 = "7 0 obj<</Filter[ /FlateDecode /ASCIIHexDecode /ASCII85Decode ]/Length 3324>>"
	$string6 = "endobjxref"
	$string7 = "L%}gE("
	$string8 = "0000000157 00000 n"
	$string9 = "1 0 obj<</Type/Catalog/Pages 2 0 R /Names 3 0 R >>endobj"
	$string10 = "0000000120 00000 n"
	$string11 = "4 0 obj<</Type/Page/Parent 2 0 R /Contents 12 0 R>>endobj"
condition:
	11 of them
}

rule redkit_bin_basic : exploit_kit
{
    strings:
        $a = /\/\d{2}.html\s/
    condition:
        $a
}

rule sakura_jar
{
meta:
	author = "Josh Berry"
	date = "2016-06-26"
	description = "Sakura Exploit Kit Detection"
	hash0 = "a566ba2e3f260c90e01366e8b0d724eb"
	sample_filetype = "unknown"
	yaragenerator = "https://github.com/Xen0ph0n/YaraGenerator"
strings:
	$string0 = "Rotok.classPK"
	$string1 = "nnnolg"
	$string2 = "X$Z'\\4^=aEbIdUmiprsxt}v<" wide
	$string3 = "()Ljava/util/Set;"
	$string4 = "(Ljava/lang/String;)V"
	$string5 = "Ljava/lang/Exception;"
	$string6 = "oooy32"
	$string7 = "Too.java"
	$string8 = "bbfwkd"
	$string9 = "Ljava/lang/Process;"
	$string10 = "getParameter"
	$string11 = "length"
	$string12 = "Simio.java"
	$string13 = "Ljavax/swing/JList;"
	$string14 = "-(Ljava/lang/String;)Ljava/lang/StringBuilder;"
	$string15 = "Ljava/io/InputStream;"
	$string16 = "vfnnnrof.exnnnroe"
	$string17 = "Olsnnfw"
condition:
	17 of them
}

rule sakura_jar2
{
meta:
	author = "Josh Berry"
	date = "2016-06-26"
	description = "Sakura Exploit Kit Detection"
	hash0 = "d21b4e2056e5ef9f9432302f445bcbe1"
	sample_filetype = "unknown"
	yaragenerator = "https://github.com/Xen0ph0n/YaraGenerator"
strings:
	$string0 = "getProperty"
	$string1 = "java/io/FileNotFoundException"
	$string2 = "LLolp;"
	$string3 = "cjhgreshhnuf "
	$string4 = "StackMapTable"
	$string5 = "onfwwa"
	$string6 = "(C)Ljava/lang/StringBuilder;"
	$string7 = "replace"
	$string8 = "LEsia$fffgss;"
	$string9 = "<clinit>"
	$string10 = "()Ljava/io/InputStream;"
	$string11 = "openConnection"
	$string12 = " gjhgreshhnijhgreshhrtSjhgreshhot.sjhgreshhihjhgreshht;)"
	$string13 = "Oi.class"
	$string14 = " rjhgreshhorjhgreshhre rajhgreshhv"
	$string15 = "java/lang/String"
	$string16 = "java/net/URL"
	$string17 = "Created-By: 1.7.0-b147 (Oracle Corporation)"
condition:
	17 of them
}

rule zeus_js
{
meta:
	author = "Josh Berry"
	date = "2016-06-26"
	description = "Zeus Exploit Kit Detection"
	hash0 = "c87ac7a25168df49a64564afb04dc961"
	sample_filetype = "js-html"
	yaragenerator = "https://github.com/Xen0ph0n/YaraGenerator"
strings:
	$string0 = "var jsmLastMenu "
	$string1 = "position:absolute; z-index:99' "
	$string2 = " -1)jsmSetDisplayStyle('popupmenu' "
	$string3 = " '<tr><td><a href"
	$string4 = "  jsmLastMenu "
	$string5 = "  var ids "
	$string6 = "this.target"
	$string7 = " jsmPrevMenu, 'none');"
	$string8 = "  if(jsmPrevMenu "
	$string9 = ")if(MenuData[i])"
	$string10 = " '<div style"
	$string11 = "popupmenu"
	$string12 = "  jsmSetDisplayStyle('popupmenu' "
	$string13 = "function jsmHideLastMenu()"
	$string14 = " MenuData.length; i"
condition:
	14 of them
}

rule zeroaccess_css
{
meta:
	author = "Josh Berry"
	date = "2016-06-27"
	description = "ZeroAccess Exploit Kit Detection"
	hash0 = "4944324bad3b020618444ee131dce3d0"
	sample_filetype = "js-html"
	yaragenerator = "https://github.com/Xen0ph0n/YaraGenerator"
strings:
	$string0 = "close-mail{right:130px "
	$string1 = "ccc;box-shadow:0 0 5px 1px "
	$string2 = "757575;border-bottom:1px solid "
	$string3 = "777;height:1.8em;line-height:1.9em;display:block;float:left;padding:1px 15px;margin:0;text-shadow:-1"
	$string4 = "C4C4C4;}"
	$string5 = "999;-webkit-box-shadow:0 0 3px "
	$string6 = "header div.service-links ul{display:inline;margin:10px 0 0;}"
	$string7 = "t div h2.title{padding:0;margin:0;}.box5-condition-news h2.pane-title{display:block;margin:0 0 9px;p"
	$string8 = "footer div.comp-info p{color:"
	$string9 = "pcmi-listing-center .full-page-listing{width:490px;}"
	$string10 = "pcmi-content-top .photo img,"
	$string11 = "333;}div.tfw-header a var{display:inline-block;margin:0;line-height:20px;height:20px;width:120px;bac"
	$string12 = "ay:none;text-decoration:none;outline:none;padding:4px;text-align:center;font-size:9px;color:"
	$string13 = "333;}body.page-videoplayer div"
	$string14 = "373737;position:relative;}body.node-type-video div"
	$string15 = "pcmi-content-sidebara,.page-error-page "
	$string16 = "fff;text-decoration:none;}"
	$string17 = "qtabs-list li a,"
	$string18 = "cdn2.dailyrx.com"
condition:
	18 of them
}

rule zeroaccess_css2
{
meta:
	author = "Josh Berry"
	date = "2016-06-27"
	description = "ZeroAccess Exploit Kit Detection"
	hash0 = "e300d6a36b9bfc3389f64021e78b1503"
	sample_filetype = "js-html"
	yaragenerator = "https://github.com/Xen0ph0n/YaraGenerator"
strings:
	$string0 = "er div.panel-hide{display:block;position:absolute;z-index:200;margin-top:-1.5em;}div.panel-pane div."
	$string1 = "ve.gif) right center no-repeat;}div.ctools-ajaxing{float:left;width:18px;background:url(http://cdn3."
	$string2 = "cdn2.dailyrx.com"
	$string3 = "efefef;margin:5px 0 5px 0;}"
	$string4 = "node{margin:0;padding:0;}div.panel-pane div.feed a{float:right;}"
	$string5 = ":0 5px 0 0;float:left;}div.tweets-pulled-listing div.tweet-authorphoto img{max-height:40px;max-width"
	$string6 = "i a{color:"
	$string7 = ":bold;}div.tweets-pulled-listing .tweet-time a{color:silver;}div.tweets-pulled-listing  div.tweet-di"
	$string8 = "div.panel-pane div.admin-links{font-size:xx-small;margin-right:1em;}div.panel-pane div.admin-links l"
	$string9 = "div.tweets-pulled-listing ul{list-style:none;}div.tweets-pulled-listing div.tweet-authorphoto{margin"
	$string10 = "FFFFDD none repeat scroll 0 0;border:1px solid "
	$string11 = "vider{clear:left;border-bottom:1px solid "
condition:
	11 of them
}

rule zeroaccess_htm
{
meta:
	author = "Josh Berry"
	date = "2016-06-27"
	description = "ZeroAccess Exploit Kit Detection"
	hash0 = "0e7d72749b60c8f05d4ff40da7e0e937"
	sample_filetype = "js-html"
	yaragenerator = "https://github.com/Xen0ph0n/YaraGenerator"
strings:
	$string0 = "screen.height:"
	$string1 = "</script></head><body onload"
	$string2 = "Fx0ZAQRKXUVgbh0qNDRJVxYwGg4tGh8aHQoAVQQSNyo0NElXFjAaDi0NFQYESl1FBBNnTFoSPiBmADwnPTQxPSdKWUUEE2UcGR0z"
	$string3 = "0);-10<b"
	$string4 = "function fl(){var a"
	$string5 = "0);else if(navigator.mimeTypes"
	$string6 = ");b.href"
	$string7 = "/presults.jsp"
	$string8 = "128.164.107.221"
	$string9 = ")[0].clientWidth"
	$string10 = "presults.jsp"
	$string11 = ":escape(c),e"
	$string12 = "navigator.plugins.length)navigator.plugins["
	$string13 = "window;d"
	$string14 = "gr(),j"
	$string15 = "VIEWPORT"
	$string16 = "FQV2D0ZAH1VGDxgZVg9COwYCAwkcTzAcBxscBFoKAAMHUFVuWF5EVVYVdVtUR18bA1QdAU8HQjgeUFYeAEZ4SBEcEk1FTxsdUlVA"
condition:
	16 of them
}

rule zeroaccess_js
{
meta:
	author = "Josh Berry"
	date = "2016-06-27"
	description = "ZeroAccess Exploit Kit Detection"
	hash0 = "a9f30483a197cfdc65b4a70b8eb738ab"
	sample_filetype = "js-html"
	yaragenerator = "https://github.com/Xen0ph0n/YaraGenerator"
strings:
	$string0 = "Square ad tag  (tile"
	$string1 = "  adRandNum "
	$string2 = " cellspacing"
	$string3 = "\\n//-->\\n</script>"
	$string4 = "format"
	$string5 = "//-->' "
	$string6 = "2287974446"
	$string7 = "NoScrBeg "
	$string8 = "-- start adblade -->' "
	$string9 = "3427054556"
	$string10 = "        while (i >"
	$string11 = "return '<table width"
	$string12 = "</scr' "
	$string13 = " s.substring(0, i"
	$string14 = " /></a></noscript>' "
	$string15 = "    else { isEmail "
	$string16 = ").submit();"
	$string17 = " border"
	$string18 = "pub-8301011321395982"
condition:
	18 of them
}

rule zeroaccess_js2
{
meta:
	author = "Josh Berry"
	date = "2016-06-27"
	description = "ZeroAccess Exploit Kit Detection"
	hash0 = "b5fda04856b98c254d33548cc1c1216c"
	sample_filetype = "js-html"
	yaragenerator = "https://github.com/Xen0ph0n/YaraGenerator"
strings:
	$string0 = "ApiClientConfig"
	$string1 = "function/.test(pa.toString())"
	$string2 = "background-image:url(http:\\/\\/static.ak.fbcdn.net\\/rsrc.php\\/v2\\/y6\\/x\\/s816eWC-2sl.gif)}"
	$string3 = "Music.init"
	$string4 = "',header:'bool',recommendations:'bool',site:'hostname'},create_event_button:{},degrees:{href:'url'},"
	$string5 = "cca6477272fc5cb805f85a84f20fca1d"
	$string6 = "document.createElement('form');c.action"
	$string7 = "javascript:false"
	$string8 = "s.onMessage){j.error('An instance without whenReady or onMessage makes no sense');throw new Error('A"
	$string9 = "NaN;}else h"
	$string10 = "sprintf"
	$string11 = "window,j"
	$string12 = "o.getUserID(),da"
	$string13 = "FB.Runtime.getLoginStatus();if(b"
	$string14 = ")');k.toString"
	$string15 = "rovide('XFBML.Send',{Dimensions:{width:80,height:25}});"
	$string16 = "{log:i};e.exports"
	$string17 = "a;FB.api('/fql','GET',f,function(g){if(g.error){ES5(ES5('Object','keys',false,b),'forEach',true,func"
	$string18 = "true;}}var ia"
condition:
	18 of them
}

rule zeroaccess_js3
{
meta:
	author = "Josh Berry"
	date = "2016-06-27"
	description = "ZeroAccess Exploit Kit Detection"
	hash0 = "5f13fdfb53a3e60e93d7d1d7bbecff4f"
	sample_filetype = "js-html"
	yaragenerator = "https://github.com/Xen0ph0n/YaraGenerator"
strings:
	$string0 = "document.createDocumentFragment();img.src"
	$string1 = "typeOf(events)"
	$string2 = "var i,x,y,ARRcookies"
	$string3 = "callbacks.length;j<l;j"
	$string4 = "encodeURIComponent(value);if(options.domain)value"
	$string5 = "event,HG.components.get('windowEvent_'"
	$string6 = "'read'in Cookie){return Cookie.read(c_name);}"
	$string7 = "item;},get:function(name,def){return HG.components.exists(name)"
	$string8 = "){window.addEvent(windowEvents[i],function(){var callbacks"
	$string9 = "reunload:function(callback){HG.events.add('beforeunload',callback);},add:function(event,callback){HG"
	$string10 = "name){if(HG.components.exists(name)){delete HG.componentList[name];}}},util:{uuid:function(){return'"
	$string11 = "window.HG"
	$string12 = "x.replace(/"
	$string13 = "encodeURIComponent(this.attr[key]));}"
	$string14 = "options.domain;if(options.path)value"
	$string15 = "this.page_sid;this.attr.user_sid"
condition:
	15 of them
}

rule zeroaccess_js4
{
meta:
	author = "Josh Berry"
	date = "2016-06-27"
	description = "ZeroAccess Exploit Kit Detection"
	hash0 = "268ae96254e423e9d670ebe172d1a444"
	sample_filetype = "js-html"
	yaragenerator = "https://github.com/Xen0ph0n/YaraGenerator"
strings:
	$string0 = ").join("
	$string1 = "JSON.stringify:function(o){if(o"
	$string2 = "){try{var a"
	$string3 = ");return $.jqotecache[i]"
	$string4 = "o.getUTCFullYear(),hours"
	$string5 = "seconds"
	$string6 = "')');};$.secureEvalJSON"
	$string7 = "isFinite(n);},secondsToTime:function(sec_numb){sec_numb"
	$string8 = "')');}else{throw new SyntaxError('Error parsing JSON, source is not valid.');}};$.quoteString"
	$string9 = "o[name];var ret"
	$string10 = "a[m].substr(2)"
	$string11 = ");if(d){return true;}}}catch(e){return false;}}"
	$string12 = "a.length;m<k;m"
	$string13 = "if(parentClasses.length"
	$string14 = "o.getUTCHours(),minutes"
	$string15 = "$.jqote(e,d,t),$$"
	$string16 = "q.test(x)){e"
	$string17 = "{};HGWidget.creator"
condition:
	17 of them
}

rule blackhole2_css
{
meta:
	author = "Josh Berry"
	date = "2016-06-27"
	description = "BlackHole2 Exploit Kit Detection"
	hash0 = "9664a16c65782d56f02789e7d52359cd"
	sample_filetype = "js-html"
	yaragenerator = "https://github.com/Xen0ph0n/YaraGenerator"
strings:
	$string1 = "background:url('%%?a=img&img=countries.gif')"
	$string2 = "background:url('%%?a=img&img=exploit.gif')"
	$string3 = "background:url('%%?a=img&img=oses.gif')"
	$string4 = "background:url('%%?a=img&img=browsers.gif')"
	$string5 = "background:url('%%?a=img&img=edit.png')"
	$string6 = "background:url('%%?a=img&img=add.png')"
	$string7 = "background:url('%%?a=img&img=accept.png')"
	$string8 = "background:url('%%?a=img&img=del.png')"
	$string9 = "background:url('%%?a=img&img=stat.gif')"
condition:
	18 of them
}

rule blackhole2_htm
{
meta:
	author = "Josh Berry"
	date = "2016-06-27"
	description = "BlackHole2 Exploit Kit Detection"
	hash0 = "92e21e491a90e24083449fd906515684"
	hash1 = "98b302a504a7ad0e3515ab6b96d623f9"
	hash2 = "a91d885ef4c4a0d16c88b956db9c6f43"
	hash3 = "d8336f7ae9b3a4db69317aea105f49be"
	hash4 = "eba5daf0442dff5b249274c99552177b"
	hash5 = "02d8e6daef5a4723621c25cfb766a23d"
	hash6 = "dadf69ce2124283a59107708ffa9c900"
	hash7 = "467199178ac940ca311896c7d116954f"
	hash8 = "17ab5b85f2e1f2b5da436555ea94f859"
	sample_filetype = "js-html"
	yaragenerator = "https://github.com/Xen0ph0n/YaraGenerator"
strings:
	$string0 = ">links/</a></td><td align"
	$string1 = ">684K</td><td>"
	$string2 = "> 36K</td><td>"
	$string3 = "move_logs.php"
	$string4 = "files/"
	$string5 = "cron_updatetor.php"
	$string6 = ">12-Sep-2012 23:45  </td><td align"
	$string7 = ">  - </td><td>"
	$string8 = "cron_check.php"
	$string9 = "-//W3C//DTD HTML 3.2 Final//EN"
	$string10 = "bhadmin.php"
	$string11 = ">21-Sep-2012 15:25  </td><td align"
	$string12 = ">data/</a></td><td align"
	$string13 = ">3.3K</td><td>"
	$string14 = "cron_update.php"
condition:
	14 of them
}

rule blackhole2_htm10
{
meta:
	author = "Josh Berry"
	date = "2016-06-27"
	description = "BlackHole2 Exploit Kit Detection"
	hash0 = "83704d531c9826727016fec285675eb1"
	hash1 = "103ef0314607d28b3c54cd07e954cb25"
	hash2 = "16c002dc45976caae259d7cabc95b2c3"
	hash3 = "fd84d695ac3f2ebfb98d3255b3a4e1de"
	hash4 = "c7b417a4d650c72efebc2c45eefbac2a"
	hash5 = "c3c35e465e316a71abccca296ff6cd22"
	hash2 = "16c002dc45976caae259d7cabc95b2c3"
	hash7 = "10ce7956266bfd98fe310d7568bfc9d0"
	hash8 = "60024caf40f4239d7e796916fb52dc8c"
	sample_filetype = "js-html"
	yaragenerator = "https://github.com/Xen0ph0n/YaraGenerator"
strings:
	$string0 = "</body></html>"
	$string1 = "/icons/back.gif"
	$string2 = ">373K</td><td>"
	$string3 = "/icons/unknown.gif"
	$string4 = ">Last modified</a></th><th><a href"
	$string5 = "tmp.gz"
	$string6 = ">tmp.gz</a></td><td align"
	$string7 = "nbsp;</td><td align"
	$string8 = "</table>"
	$string9 = ">  - </td><td>"
	$string10 = ">filefdc7aaf4a3</a></td><td align"
	$string11 = ">19-Sep-2012 07:06  </td><td align"
	$string12 = "><img src"
	$string13 = "file3fa7bdd7dc"
	$string14 = "  <title>Index of /files</title>"
	$string15 = "0da49e042d"
condition:
	15 of them
}

rule blackhole2_htm11
{
meta:
	author = "Josh Berry"
	date = "2016-06-27"
	description = "BlackHole2 Exploit Kit Detection"
	hash0 = "e89b56df597688c489f06a0a6dd9efed"
	hash1 = "06ba331ac5ae3cd1986c82cb1098029e"
	hash2 = "a899dedb50ad81d9dbba660747828c7b"
	hash3 = "7cbb58412554327fe8b643204a046e2b"
	hash2 = "a899dedb50ad81d9dbba660747828c7b"
	hash0 = "e89b56df597688c489f06a0a6dd9efed"
	hash2 = "a899dedb50ad81d9dbba660747828c7b"
	hash7 = "530d31a0c45b79c1ee0c5c678e242c02"
	hash2 = "a899dedb50ad81d9dbba660747828c7b"
	sample_filetype = "js-html"
	yaragenerator = "https://github.com/Xen0ph0n/YaraGenerator"
strings:
	$string0 = "></th><th><a href"
	$string1 = "/icons/back.gif"
	$string2 = ">Description</a></th></tr><tr><th colspan"
	$string3 = "nbsp;</td><td align"
	$string4 = "nbsp;</td></tr>"
	$string5 = ">  - </td><td>"
	$string6 = "-//W3C//DTD HTML 3.2 Final//EN"
	$string7 = "<h1>Index of /dummy</h1>"
	$string8 = ">Size</a></th><th><a href"
	$string9 = " </head>"
	$string10 = "/icons/blank.gif"
	$string11 = "><hr></th></tr>"
condition:
	11 of them
}

rule blackhole2_htm12
{
meta:
	author = "Josh Berry"
	date = "2016-06-27"
	description = "BlackHole2 Exploit Kit Detection"
	hash0 = "0d3acb5285cfe071e30be051d2aaf28a"
	hash1 = "6f27377115ba5fd59f007d2cb3f50b35"
	hash2 = "f7ffe1fd1a57d337a04d3c777cddc065"
	hash3 = "06997228f2769859ef5e4cd8a454d650"
	hash4 = "11062eea9b7f2a2675c1e60047e8735c"
	hash0 = "0d3acb5285cfe071e30be051d2aaf28a"
	hash2 = "f7ffe1fd1a57d337a04d3c777cddc065"
	hash7 = "4ec720cfafabd1c9b1034bb82d368a30"
	hash8 = "ecd7d11dc9bb6ee842e2a2dce56edc6f"
	sample_filetype = "js-html"
	yaragenerator = "https://github.com/Xen0ph0n/YaraGenerator"
strings:
	$string0 = "  <title>Index of /data</title>"
	$string1 = "<tr><th colspan"
	$string2 = "</body></html>"
	$string3 = "> 20K</td><td>"
	$string4 = "/icons/layout.gif"
	$string5 = " <body>"
	$string6 = ">Name</a></th><th><a href"
	$string7 = "spn.jar"
	$string8 = "spn2.jar"
	$string9 = " <head>"
	$string10 = "-//W3C//DTD HTML 3.2 Final//EN"
	$string11 = "> 10K</td><td>"
	$string12 = ">7.9K</td><td>"
	$string13 = ">Size</a></th><th><a href"
	$string14 = "><hr></th></tr>"
condition:
	14 of them
}

rule blackhole2_htm3
{
meta:
	author = "Josh Berry"
	date = "2016-06-27"
	description = "BlackHole2 Exploit Kit Detection"
	hash0 = "018ef031bc68484587eafeefa66c7082"
	sample_filetype = "js-html"
	yaragenerator = "https://github.com/Xen0ph0n/YaraGenerator"
strings:
	$string0 = "/download.php"
	$string1 = "./files/fdc7aaf4a3 md5 is 3169969e91f5fe5446909bbab6e14d5d"
	$string2 = "321e774d81b2c3ae"
	$string3 = "/files/new00010/554-0002.exe md5 is 8a497cf4ffa8a173a7ac75f0de1f8d8b"
	$string4 = "./files/3fa7bdd7dc md5 is 8a497cf4ffa8a173a7ac75f0de1f8d8b"
	$string5 = "1603256636530120915 md5 is 425ebdfcf03045917d90878d264773d2"
condition:
	3 of them
}

rule blackhole2_htm4
{
meta:
	author = "Josh Berry"
	date = "2016-06-27"
	description = "BlackHole2 Exploit Kit Detection"
	hash0 = "926429bf5fe1fbd531eb100fc6e53524"
	hash1 = "7b6cdc67077fc3ca75a54dea0833afe3"
	hash2 = "82f108d4e6f997f8fc4cc02aad02629a"
	hash3 = "bd819c3714dffb5d4988d2f19d571918"
	hash4 = "9bc9f925f60bd8a7b632ae3a6147cb9e"
	hash0 = "926429bf5fe1fbd531eb100fc6e53524"
	hash2 = "82f108d4e6f997f8fc4cc02aad02629a"
	hash7 = "386cb76d46b281778c8c54ac001d72dc"
	hash8 = "0d95c666ea5d5c28fca5381bd54304b3"
	sample_filetype = "js-html"
	yaragenerator = "https://github.com/Xen0ph0n/YaraGenerator"
strings:
	$string0 = "words.dat"
	$string1 = "/icons/back.gif"
	$string2 = "data.dat"
	$string3 = "files.php"
	$string4 = "js.php"
	$string5 = "template.php"
	$string6 = "kcaptcha"
	$string7 = "/icons/blank.gif"
	$string8 = "java.dat"
condition:
	8 of them
}

rule blackhole2_htm5
{
meta:
	author = "Josh Berry"
	date = "2016-06-27"
	description = "BlackHole2 Exploit Kit Detection"
	hash0 = "fccb8f71663620a5a8b53dcfb396cfb5"
	hash1 = "a09bcf1a1bdabe4e6e7e52e7f8898012"
	hash2 = "40db66bf212dd953a169752ba9349c6a"
	hash3 = "25a87e6da4baa57a9d6a2cdcb2d43249"
	hash4 = "6f4c64a1293c03c9f881a4ef4e1491b3"
	hash0 = "fccb8f71663620a5a8b53dcfb396cfb5"
	hash2 = "40db66bf212dd953a169752ba9349c6a"
	hash7 = "4bdfff8de0bb5ea2d623333a4a82c7f9"
	hash8 = "b43b6a1897c2956c2a0c9407b74c4232"
	sample_filetype = "js-html"
	yaragenerator = "https://github.com/Xen0ph0n/YaraGenerator"
strings:
	$string0 = "ruleEdit.php"
	$string1 = "domains.php"
	$string2 = "menu.php"
	$string3 = "browsers_stat.php"
	$string4 = "Index of /library/templates"
	$string5 = "/icons/unknown.gif"
	$string6 = "browsers_bstat.php"
	$string7 = "oses_stat.php"
	$string8 = "exploits_bstat.php"
	$string9 = "block_config.php"
	$string10 = "threads_bstat.php"
	$string11 = "browsers_bstat.php"
	$string12 = "settings.php"
condition:
	12 of them
}

rule blackhole2_htm6
{
meta:
	author = "Josh Berry"
	date = "2016-06-27"
	description = "BlackHole2 Exploit Kit Detection"
	hash0 = "a5f94d7bdeb88b57be67132473e48286"
	hash1 = "2e72a317d07aa1603f8d138787a2c582"
	hash2 = "9440d49e1ed0794c90547758ef6023f7"
	hash3 = "58265fc893ed5a001e3a7c925441298c"
	hash2 = "9440d49e1ed0794c90547758ef6023f7"
	hash0 = "a5f94d7bdeb88b57be67132473e48286"
	hash2 = "9440d49e1ed0794c90547758ef6023f7"
	hash7 = "95c6462d0f21181c5003e2a74c8d3529"
	hash8 = "9236e7f96207253b4684f3497bcd2b3d"
	sample_filetype = "js-html"
	yaragenerator = "https://github.com/Xen0ph0n/YaraGenerator"
strings:
	$string0 = "uniq1.png"
	$string1 = "edit.png"
	$string2 = "left.gif"
	$string3 = "infin.png"
	$string4 = "outdent.gif"
	$string5 = "exploit.gif"
	$string6 = "sem_g.png"
	$string7 = "Index of /library/templates/img"
	$string8 = "uniq1.png"
condition:
	8 of them
}

rule blackhole2_htm8
{
meta:
	author = "Josh Berry"
	date = "2016-06-27"
	description = "BlackHole2 Exploit Kit Detection"
	hash0 = "3f47452c1e40f68160beff4bb2a3e5f4"
	hash1 = "1e2ba0176787088e3580dfce0245bc16"
	hash2 = "1c78d96bb8d8f8a71294bc1e6d374b0f"
	hash3 = "f5e16a6cd2c2ac71289aaf1c087224ee"
	hash2 = "1c78d96bb8d8f8a71294bc1e6d374b0f"
	hash0 = "3f47452c1e40f68160beff4bb2a3e5f4"
	hash2 = "1c78d96bb8d8f8a71294bc1e6d374b0f"
	hash7 = "6702efdee17e0cd6c29349978961d9fa"
	hash8 = "287dca9469c8f7f0cb6e5bdd9e2055cd"
	sample_filetype = "js-html"
	yaragenerator = "https://github.com/Xen0ph0n/YaraGenerator"
strings:
	$string0 = ">Description</a></th></tr><tr><th colspan"
	$string1 = ">Name</a></th><th><a href"
	$string2 = "main.js"
	$string3 = "datepicker.js"
	$string4 = "form.js"
	$string5 = "<address>Apache/2.2.15 (CentOS) Server at online-moo-viii.net Port 80</address>"
	$string6 = "wysiwyg.js"
condition:
	6 of them
}

rule blackhole2_jar
{
meta:
	author = "Josh Berry"
	date = "2016-06-27"
	description = "BlackHole2 Exploit Kit Detection"
	hash0 = "86946ec2d2031f2b456e804cac4ade6d"
	sample_filetype = "unknown"
	yaragenerator = "https://github.com/Xen0ph0n/YaraGenerator"
strings:
	$string0 = "k0/3;N"
	$string1 = "g:WlY0"
	$string2 = "(ww6Ou"
	$string3 = "SOUGX["
	$string4 = "7X2ANb"
	$string5 = "r8L<;zYH)"
	$string6 = "fbeatbea/fbeatbee.classPK"
	$string7 = "fbeatbea/fbeatbec.class"
	$string8 = "fbeatbea/fbeatbef.class"
	$string9 = "fbeatbea/fbeatbef.classPK"
	$string10 = "fbeatbea/fbeatbea.class"
	$string11 = "fbeatbea/fbeatbeb.classPK"
	$string12 = "nOJh-2"
	$string13 = "[af:Fr"
condition:
	13 of them
}

rule blackhole2_jar2
{
meta:
	author = "Josh Berry"
	date = "2016-06-27"
	description = "BlackHole2 Exploit Kit Detection"
	hash0 = "add1d01ba06d08818ff6880de2ee74e8"
	sample_filetype = "unknown"
	yaragenerator = "https://github.com/Xen0ph0n/YaraGenerator"
strings:
	$string0 = "6_O6d09"
	$string1 = "juqirvs.classPK"
	$string2 = "hw.classPK"
	$string3 = "a.classPK"
	$string4 = "w.classuS]w"
	$string5 = "w.classPK"
	$string6 = "YE}0vCZ"
	$string7 = "v)Q,Ff"
	$string8 = "%8H%t("
	$string9 = "hw.class"
	$string10 = "a.classmV"
	$string11 = "2CniYFU"
	$string12 = "juqirvs.class"
condition:
	12 of them
}

rule blackhole2_jar3
{
meta:
	author = "Josh Berry"
	date = "2016-06-27"
	description = "BlackHole2 Exploit Kit Detection"
	hash0 = "c7abd2142f121bd64e55f145d4b860fa"
	sample_filetype = "unknown"
	yaragenerator = "https://github.com/Xen0ph0n/YaraGenerator"
strings:
	$string0 = "69/sj]]o"
	$string1 = "GJk5Nd"
	$string2 = "vcs.classu"
	$string3 = "T<EssB"
	$string4 = "1vmQmQ"
	$string5 = "Kf1Ewr"
	$string6 = "c$WuuuKKu5"
	$string7 = "m.classPK"
	$string8 = "chcyih.classPK"
	$string9 = "hw.class"
	$string10 = "f';;;;{"
	$string11 = "vcs.classPK"
	$string12 = "Vbhf_6"
condition:
	12 of them
}

rule blackhole2_pdf
{
meta:
	author = "Josh Berry"
	date = "2016-06-27"
	description = "BlackHole2 Exploit Kit Detection"
	hash0 = "d1e2ff36a6c882b289d3b736d915a6cc"
	sample_filetype = "pdf"
	yaragenerator = "https://github.com/Xen0ph0n/YaraGenerator"
strings:
	$string0 = "/StructTreeRoot 5 0 R/Type/Catalog>>"
	$string1 = "0000036095 00000 n"
	$string2 = "http://www.xfa.org/schema/xfa-locale-set/2.1/"
	$string3 = "subform[0].ImageField1[0])/Subtype/Widget/TU(Image Field)/Parent 22 0 R/F 4/P 8 0 R/T<FEFF0049006D00"
	$string4 = "0000000026 65535 f"
	$string5 = "0000029039 00000 n"
	$string6 = "0000029693 00000 n"
	$string7 = "%PDF-1.6"
	$string8 = "27 0 obj<</Subtype/Type0/DescendantFonts 28 0 R/BaseFont/KLGNYZ"
	$string9 = "0000034423 00000 n"
	$string10 = "0000000010 65535 f"
	$string11 = ">stream"
	$string12 = "/Pages 2 0 R%/StructTreeRoot 5 0 R/Type/Catalog>>"
	$string13 = "19 0 obj<</Subtype/Type1C/Length 23094/Filter/FlateDecode>>stream"
	$string14 = "0000003653 00000 n"
	$string15 = "0000000023 65535 f"
	$string16 = "0000028250 00000 n"
	$string17 = "iceRGB>>>>/XStep 9.0/Type/Pattern/TilingType 2/YStep 9.0/BBox[0 0 9 9]>>stream"
	$string18 = "<</Root 1 0 R>>"
condition:
	18 of them
}

rule maldoc_indirect_function_call_1 : maldoc
{
    meta:
        author = "Didier Stevens (https://DidierStevens.com)"
    strings:
        $a = {FF 75 ?? FF 55 ??}
    condition:
        for any i in (1..#a): (uint8(@a[i] + 2) == uint8(@a[i] + 5))
}

rule maldoc_indirect_function_call_2 : maldoc
{
    meta:
        author = "Didier Stevens (https://DidierStevens.com)"
    strings:
        $a = {FF B5 ?? ?? ?? ?? FF 95 ?? ?? ?? ??}
    condition:
        for any i in (1..#a): ((uint8(@a[i] + 2) == uint8(@a[i] + 8)) and (uint8(@a[i] + 3) == uint8(@a[i] + 9)) and (uint8(@a[i] + 4) == uint8(@a[i] + 10)) and (uint8(@a[i] + 5) == uint8(@a[i] + 11)))
}

rule maldoc_indirect_function_call_3 : maldoc
{
    meta:
        author = "Didier Stevens (https://DidierStevens.com)"
    strings:
        $a = {FF B7 ?? ?? ?? ?? FF 57 ??}
    condition:
        $a
}

rule maldoc_find_kernel32_base_method_1 : maldoc
{
    meta:
        author = "Didier Stevens (https://DidierStevens.com)"
    strings:
        $a1 = {64 8B (05|0D|15|1D|25|2D|35|3D) 30 00 00 00}
        $a2 = {64 A1 30 00 00 00}
    condition:
        any of them
}

rule maldoc_find_kernel32_base_method_2 : maldoc
{
    meta:
        author = "Didier Stevens (https://DidierStevens.com)"
    strings:
        $a = {31 ?? ?? 30 64 8B ??}
    condition:
        for any i in (1..#a): ((uint8(@a[i] + 1) >= 0xC0) and (((uint8(@a[i] + 1) & 0x38) >> 3) == (uint8(@a[i] + 1) & 0x07)) and ((uint8(@a[i] + 2) & 0xF8) == 0xA0) and (uint8(@a[i] + 6) <= 0x3F) and (((uint8(@a[i] + 6) & 0x38) >> 3) != (uint8(@a[i] + 6) & 0x07)))
}

rule maldoc_find_kernel32_base_method_3 : maldoc
{
    meta:
        author = "Didier Stevens (https://DidierStevens.com)"
    strings:
        $a = {68 30 00 00 00 (58|59|5A|5B|5C|5D|5E|5F) 64 8B ??}
    condition:
        for any i in (1..#a): (((uint8(@a[i] + 5) & 0x07) == (uint8(@a[i] + 8) & 0x07)) and (uint8(@a[i] + 8) <= 0x3F) and (((uint8(@a[i] + 8) & 0x38) >> 3) != (uint8(@a[i] + 8) & 0x07)))
}

rule mwi_document: exploitdoc maldoc
{
    meta:
        description = "MWI generated document"
        author = "@Ydklijnsma"
        source = "http://blog.0x3a.com/post/117760824504/analysis-of-a-microsoft-word-intruder-sample"

      strings:
        $field_creation_tag = "{\\field{\\*\\fldinst { INCLUDEPICTURE"
        $mwistat_url = ".php?id="
        $field_closing_tag = "\\\\* MERGEFORMAT \\\\d}}{\\fldrslt}}"

    condition:
        all of them
}

rule macrocheck : maldoc
{
    meta:
        Author      = "Fireeye Labs"
        Date        = "2014/11/30" 
        Description = "Identify office documents with the MACROCHECK credential stealer in them.  It can be run against .doc files or VBA macros extraced from .docx files (vbaProject.bin files)."
        Reference   = "https://www.fireeye.com/blog/threat-research/2014/11/fin4_stealing_insid.html"

    strings:
        $PARAMpword = "pword=" ascii wide
        $PARAMmsg = "msg=" ascii wide
        $PARAMuname = "uname=" ascii
        $userform = "UserForm" ascii wide
        $userloginform = "UserLoginForm" ascii wide
        $invalid = "Invalid username or password" ascii wide
        $up1 = "uploadPOST" ascii wide
        $up2 = "postUpload" ascii wide
 
    condition:
        all of ($PARAM*) or (($invalid or $userloginform or $userform) and ($up1 or $up2))
}

rule Office_AutoOpen_Macro : maldoc {
	meta:
		description = "Detects an Microsoft Office file that contains the AutoOpen Macro function"
		author = "Florian Roth"
		date = "2015-05-28"
		score = 60
		hash1 = "4d00695d5011427efc33c9722c61ced2"
		hash2 = "63f6b20cb39630b13c14823874bd3743"
		hash3 = "66e67c2d84af85a569a04042141164e6"
		hash4 = "a3035716fe9173703941876c2bde9d98"
		hash5 = "7c06cab49b9332962625b16f15708345"
		hash6 = "bfc30332b7b91572bfe712b656ea8a0c"
		hash7 = "25285b8fe2c41bd54079c92c1b761381"
	strings:
		$s1 = "AutoOpen" ascii fullword
		$s2 = "Macros" wide fullword
	condition:
		uint32be(0) == 0xd0cf11e0 and all of ($s*) and filesize < 300000
}

rule Embedded_EXE_Cloaking : maldoc {
    meta:
        description = "Detects an embedded executable in a non-executable file"
        author = "Florian Roth"
        date = "2015/02/27"
        score = 80
    strings:
        $noex_png = { 89 50 4E 47 }
        $noex_pdf = { 25 50 44 46 }
        $noex_rtf = { 7B 5C 72 74 66 31 }
        $noex_jpg = { FF D8 FF E0 }
        $noex_gif = { 47 49 46 38 }
        $mz  = { 4D 5A }
        $a1 = "This program cannot be run in DOS mode"
        $a2 = "This program must be run under Win32"       
    condition:
        (
            ( $noex_png at 0 ) or
            ( $noex_pdf at 0 ) or
            ( $noex_rtf at 0 ) or
            ( $noex_jpg at 0 ) or
            ( $noex_gif at 0 )
        )
        and
        for any i in (1..#mz): ( @a1 < ( @mz[i] + 200 ) or @a2 < ( @mz[i] + 200 ) )
}
