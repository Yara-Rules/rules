/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as    long as you use it under this license.
*/

/*
  Description: This rule keys on email headers that may have been sent from a malicious PHP script on a compromised webserver.
  Priority: 4
  Scope: Against Email
  Tags: None
  Author: P.Burbage
  Created in PhishMe's Triage on September 1, 2015 1:43 PM
*/

rule PM_Email_Sent_By_PHP_Script
{
  strings:
    $php1="X-PHP-Script" fullword
    $php2="X-PHP-Originating-Script" fullword
    $php3="/usr/bin/php" fullword

  condition:
    any of them
}

/*
  Description: Hits on ZIP attachments that contain *.js or *.jse - usually JS Dropper malware that has downloaded Kovter & Boaxee in the past.
  Priority: 5
  Scope: Against Attachment
  Tags: FileID
  Author: P.Burbage
  Created in PhishMe's Triage on September 1, 2015 1:43 PM
*/

rule PM_Zip_with_js
{
  strings:
    $hdr="PK" 
    $e1=".js" nocase
    $e2=".jse" nocase

  condition:
    $hdr at 0 and (($e1 in (filesize-100..filesize)) or ($e2 in (filesize-100..filesize)))
}
