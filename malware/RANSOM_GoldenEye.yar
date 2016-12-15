/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as    long as you use it under this license.

*/

rule GoldenEye_Ransomware_XLS {
   meta:
      description = "GoldenEye XLS with Macro - file Schneider-Bewerbung.xls"
      author = "Florian Roth"
      reference = "https://goo.gl/jp2SkT"
      date = "2016-12-06"
      hash1 = "2320d4232ee80cc90bacd768ba52374a21d0773c39895b88cdcaa7782e16c441"
   strings:
      $x1 = "fso.GetTempName();tmp_path = tmp_path.replace('.tmp', '.exe')" fullword ascii
      $x2 = "var shell = new ActiveXObject('WScript.Shell');shell.run(t'" fullword ascii
   condition:
      ( uint16(0) == 0xcfd0 and filesize < 4000KB and 1 of them )
}

rule GoldenEyeRansomware_Dropper_MalformedZoomit {
   meta:
      description = "Auto-generated rule - file b5ef16922e2c76b09edd71471dd837e89811c5e658406a8495c1364d0d9dc690"
      author = "Florian Roth"
      reference = "https://goo.gl/jp2SkT"
      date = "2016-12-06"
      hash1 = "b5ef16922e2c76b09edd71471dd837e89811c5e658406a8495c1364d0d9dc690"
   strings:
      $s1 = "ZoomIt - Sysinternals: www.sysinternals.com" fullword ascii
      $n1 = "Mark Russinovich" wide
   condition:
      ( uint16(0) == 0x5a4d and filesize < 800KB and $s1 and not $n1 )
}
