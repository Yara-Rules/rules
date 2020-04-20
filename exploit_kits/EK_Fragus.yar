rule fragus_htm : EK
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
rule fragus_js : EK
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
rule fragus_js2 : EK
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
rule fragus_js_flash : EK
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
rule fragus_js_java : EK
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
rule fragus_js_quicktime : EK
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
rule fragus_js_vml : EK
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
