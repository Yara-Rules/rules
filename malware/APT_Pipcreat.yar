/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as    long as you use it under this license.

*/

rule APT_Win_Pipcreat : pe dll backdoor { 
  meta: 
    author = "chort (@chort0)"
    description = "APT backdoor Pipcreat"
    filetype = "pe,dll" 
    date = "2013-03"
    MD5 = "f09d832bea93cf320986b53fce4b8397" // (incorrectly?) identified as Hupigon by many AV on VT 
    Reference = "http://www.cyberengineeringservices.com/login-exe-analysis-trojan-pipcreat/"
    version = "1.0"
  strings: 
    $strA = "pip creat failed" wide fullword 
    $strB = "CraatePipe" ascii fullword 
    $strC = "are you there? " wide fullword 
    $strD = "success kill process ok" wide fullword 
    $strE = "Vista|08|Win7" wide fullword 
    $rut = "are you there!@#$%^&*()_+" ascii fullword 
    
  condition: 
    $rut or (2 of ($str*)) 
  }
