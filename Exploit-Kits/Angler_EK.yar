/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as    long as you use it under this license.

*/
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
