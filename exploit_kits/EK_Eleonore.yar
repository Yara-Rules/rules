rule eleonore_jar : EK
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
rule eleonore_jar2 : EK
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
rule eleonore_jar3 : EK
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
rule eleonore_js : EK
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
rule eleonore_js2 : EK
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
rule eleonore_js3 : EK
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
