rule phoenix_html : EK
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
rule phoenix_html10 : EK
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
rule phoenix_html11 : EK
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
rule phoenix_html2 : EK
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
rule phoenix_html3 : EK
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
rule phoenix_html4 : EK
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
rule phoenix_html5 : EK
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
rule phoenix_html6 : EK
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
rule phoenix_html7 : EK
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
rule phoenix_html8 : EK
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
rule phoenix_html9 : EK
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
rule phoenix_jar : EK
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
rule phoenix_jar2 : EK
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
rule phoenix_jar3 : EK Jar
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
rule phoenix_pdf : EK PDF
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
rule phoenix_pdf2 : EK PDF
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
rule phoenix_pdf3 : EK PDF
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
