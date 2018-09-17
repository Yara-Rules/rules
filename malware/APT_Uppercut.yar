import "hash"

rule APT_Uppercut {
  meta:
     description = "Detects APT10 MenuPass Uppercut"
     author = "Colin Cowie"
     reference = "https://www.fireeye.com/blog/threat-research/2018/09/apt10-targeting-japanese-corporations-using-updated-ttps.html"
     date = "2018-09-13"
  strings:
     $ip1 = "51.106.53.147"
     $ip2 = "153.92.210.208"
     $ip3 = "eservake.jetos.com"
     $c1 = "0x97A168D9697D40DD" wide
     $c2 = "0x7CF812296CCC68D5" wide
     $c3 = "0x652CB1CEFF1C0A00" wide
     $c4 = "0x27595F1F74B55278" wide
     $c5 = "0xD290626C85FB1CE3" wide
     $c6 = "0x409C7A89CFF0A727" wide
  condition:
     any of them or
     hash.md5(0, filesize) == "aa3f303c3319b14b4829fe2faa5999c1" or
     hash.md5(0, filesize) == "126067d634d94c45084cbe1d9873d895" or
     hash.md5(0, filesize) == "fce54b4886cac5c61eda1e7605483ca3"
}
