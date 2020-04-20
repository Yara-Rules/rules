/*
   Yara Rule Set
   Author: Colin Cowie
   Date: 2018-09-13
   Identifier: APT 10 (MenuPass)
   Reference: https://www.us-cert.gov/ncas/alerts/TA17-117A
*/

/* Rule Set ----------------------------------------------------------------- */

import "hash"

rule Maldoc_APT10_MenuPass {
   meta:
      description = "Detects APT10 MenuPass Phishing"
      author = "Colin Cowie"
      reference = "https://www.fireeye.com/blog/threat-research/2018/09/apt10-targeting-japanese-corporations-using-updated-ttps.html"
      date = "2018-09-13"
   strings:
      $s1 = "C:\\ProgramData\\padre1.txt"
      $s2 = "C:\\ProgramData\\padre2.txt"
      $s3 = "C:\\ProgramData\\padre3.txt"
      $s5 = "C:\\ProgramData\\libcurl.txt"
      $s6 = "C:\\ProgramData\\3F2E3AB9"
   condition:
      any of them or
      hash.md5(0, filesize) == "4f83c01e8f7507d23c67ab085bf79e97" or
      hash.md5(0, filesize) == "f188936d2c8423cf064d6b8160769f21" or
      hash.md5(0, filesize) == "cca227f70a64e1e7fcf5bccdc6cc25dd"
}
