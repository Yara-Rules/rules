/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as    long as you use it under this license.
*/

/*
  Description: None
  Priority: 5
  Scope: Against Email
  Tags: None
  Created in PhishMe's Triage on September 14, 2015 2:33 PM
*/

rule CryptoWall_Resume_phish : mail
{
  meta:
		Author = "http://phishme.com/"
		reference = "https://github.com/phishme/malware_analysis/blob/master/yara_rules/cryptowall.yar"
  strings:
    $hello2="my name is " nocase
    $file1="resume attached" nocase
    $file2="my resume is pdf file" nocase
    $file3="attached is my resume" nocase
    $sal1="I would appreciate your " nocase
    $sal2="I am looking forward to hearing from you" nocase
    $sal3="I look forward to your reply" nocase
    $sal4="Please message me back" nocase
    $sal5="our early reply will be appreciated" nocase
    $file4="attach is my resume" nocase
    $file5="PDF file is my resume" nocase
    $sal6="Looking forward to see your response" nocase

  condition:
    1 of ($hello*) and 1 of ($file*) and 1 of ($sal*)
}

/*
  Description: None
  Priority: 5
  Scope: Against Attachment
  Tags: None
  Created in PhishMe's Triage on September 14, 2015 2:35 PM
*/

rule docx_macro : mail
{
  strings:
    $header="PK" 
    $vbaStrings="word/vbaProject.bin" nocase

  condition:
    $header at 0 and $vbaStrings
}
