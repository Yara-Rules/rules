/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or 
    organization, as long as you use it under this license.
*/

rule Email_quota_limit_warning : mail
{
  meta:
		Author = "Tyler Linne <@InfoSecTyler>"
		Description ="Rule to prevent against known email quota limit phishing campaign"
    
  strings:
    $eml_01 = "From:" //Added eml context
    $eml_02 = "To:"
    $eml_03 = "Subject:"
    $subject1={ 44 65 61 72 20 [0-11] 20 41 63 63 6f 75 6e 74 20 55 73 65 72 73 } // Range allows for different company names to be accepted
    $hello1={ 44 65 61 72 20 [0-11] 20 41 63 63 6f 75 6e 74 20 55 73 65 72 73 }
    $body1="You have exceded" nocase
    $body2={65 2d 6d 61 69 6c 20 61 63 63 6f 75 6e 74 20 6c 69 6d 69 74 20 71 75 6f 74 61 20 6f 66 } //Range allows for different quota "upgrade" sizes
    $body3="requested to expand it within 24 hours" nocase
    $body4="e-mail account will be disable from our database" nocase
    $body5="simply click with the complete information" nocase
    $body6="requested to expand your account quota" nocase
    $body7={54 68 61 6e 6b 20 79 6f 75 20 66 6f 72 20 75 73 69 6e 67 20 [0-11] 20 57 65 62 6d 61 69 6c } // Range allows for different company names to be accepted

  condition:
    all of ($eml_*) and
    1 of ($subject*) and 
    1 of ($hello*) and 
    4 of ($body*) 
}
