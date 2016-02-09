/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as    long as you use it under this license.

*/
rule Adwind_JAR_PACKB {
 meta:
  author = "Vitaly Kamluk, Vitaly.Kamluk@kaspersky.com"
  reference = "https://securelist.com/securelist/files/2016/02/KL_AdwindPublicReport_2016.pdf"
  last_modified = "2015-11-30"
 strings:
  $c1 = "META-INF/MANIFEST.MF" ascii
  $c2 = "main/Start.class" ascii
  $a1 = "con g/con g.perl" ascii
  $b1 = "java/textito.isn" ascii
 condition:
  int16(0) == 0x4B50 and ($c1 and $c2 and ($a1 or $b1))
}
