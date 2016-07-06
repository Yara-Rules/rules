/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as    long as you use it under this license.

*/
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
rule blackhole_basic : exploit_kit
{
    strings:
        $a = /\.php\?\.*\?\:[a-zA-Z0-9\:]{6,}\&\.*\?\&/
    condition:
        $a
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
   $string7 = ">spn.jar</a></td><td align"
   $string8 = ">spn2.jar</a></td><td align"
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
