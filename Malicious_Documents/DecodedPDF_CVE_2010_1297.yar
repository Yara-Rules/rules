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
