/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as    long as you use it under this license.

*/
/*
   Yara Rule Set
   Author: Florian Roth
   Date: 2017-09-14
   Identifier: Detects malicious files in releation with CVE-2017-8759
   Reference: https://github.com/Voulnet/CVE-2017-8759-Exploit-sample
*/

private rule RTFFILE {
   meta:
      description = "Detects RTF files"
   condition:
      uint32be(0) == 0x7B5C7274
}

/* Rule Set ----------------------------------------------------------------- */

rule CVE_2017_8759_Mal_HTA {
   meta:
      description = "Detects malicious files related to CVE-2017-8759 - file cmd.hta"
      author = "Florian Roth"
      reference = "https://github.com/Voulnet/CVE-2017-8759-Exploit-sample"
      date = "2017-09-14"
      hash1 = "fee2ab286eb542c08fdfef29fabf7796a0a91083a0ee29ebae219168528294b5"
   strings:
      $x1 = "Error = Process.Create(\"powershell -nop cmd.exe /c" fullword ascii
   condition:
      ( uint16(0) == 0x683c and filesize < 1KB and all of them )
}

rule CVE_2017_8759_Mal_Doc {
   meta:
      description = "Detects malicious files related to CVE-2017-8759 - file Doc1.doc"
      author = "Florian Roth"
      reference = "https://github.com/Voulnet/CVE-2017-8759-Exploit-sample"
      date = "2017-09-14"
      hash1 = "6314c5696af4c4b24c3a92b0e92a064aaf04fd56673e830f4d339b8805cc9635"
   strings:
      $s1 = "soap:wsdl=http://" ascii wide nocase
      $s2 = "soap:wsdl=https://" ascii wide nocase

      $c1 = "Project.ThisDocument.AutoOpen" fullword wide
   condition:
      ( uint16(0) == 0xcfd0 and filesize < 500KB and 2 of them )
}

rule CVE_2017_8759_SOAP_via_JS {
   meta:
      description = "Detects SOAP WDSL Download via JavaScript"
      author = "Florian Roth"
      reference = "https://twitter.com/buffaloverflow/status/907728364278087680"
      date = "2017-09-14"
      score = 60
   strings:
      $s1 = "GetObject(\"soap:wsdl=https://" ascii wide nocase
      $s2 = "GetObject(\"soap:wsdl=http://" ascii wide nocase
   condition:
      ( filesize < 3KB and 1 of them )
}

rule CVE_2017_8759_SOAP_Excel {
   meta:
      description = "Detects malicious files related to CVE-2017-8759"
      author = "Florian Roth"
      reference = "https://twitter.com/buffaloverflow/status/908455053345869825"
      date = "2017-09-15"
   strings:
      $s1 = "|'soap:wsdl=" ascii wide nocase
   condition:
      ( filesize < 300KB and 1 of them )
}

rule CVE_2017_8759_SOAP_txt {
   meta:
      description = "Detects malicious file in releation with CVE-2017-8759 - file exploit.txt"
      author = "Florian Roth"
      reference = "https://github.com/Voulnet/CVE-2017-8759-Exploit-sample"
      date = "2017-09-14"
      hash1 = "840ad14e29144be06722aff4cc04b377364eeed0a82b49cc30712823838e2444"
   strings:
      $s1 = /<soap:address location="http[s]?:\/\/[^"]{8,140}.hta"/ ascii wide
      $s2 = /<soap:address location="http[s]?:\/\/[^"]{8,140}mshta.exe"/ ascii wide
   condition:
      ( filesize < 200KB and 1 of them )
}

rule CVE_2017_8759_WSDL_in_RTF {
   meta:
      description = "Detects malicious RTF file related CVE-2017-8759"
      author = "Security Doggo @xdxdxdxdoa"
      reference = "https://twitter.com/xdxdxdxdoa/status/908665278199996416"
      date = "2017-09-15"
   strings:
      $doc = "d0cf11e0a1b11ae1"
      $obj = "\\objupdate"
      $wsdl = "7700730064006c003d00" nocase
      $http1 = "68007400740070003a002f002f00" nocase
      $http2 = "680074007400700073003a002f002f00" nocase
      $http3 = "6600740070003a002f002f00" nocase
   condition:
      RTFFILE and $obj and $doc and $wsdl and 1 of ($http*)
}
