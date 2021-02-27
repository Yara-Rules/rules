/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as long as you use it under this license.
*/

rule Maldoc_Suspicious_OLE_target {
  meta:
    description =  "Detects maldoc With Tartgeting Suspicuios OLE"
    author = "Donguk Seo"
    reference = "https://blog.malwarebytes.com/threat-analysis/2017/10/decoy-microsoft-word-document-delivers-malware-through-rat/"
    filetype = "Office documents"
    date = "2018-06-13"
  strings:
    $env1 = /oleObject".*Target=.*.http.*.doc"/
    $env2 = /oleObject".*Target=.*.http.*.ppt"/
    $env3 = /oleObject".*Target=.*.http.*.xlx"/
  condition:
    any of them
}
