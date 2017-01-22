/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as    long as you use it under this license.

*/
/*
   Yara Rule Set
   Author: Florian Roth
   Date: 2017-01-08
   Identifier: ShadowBroker Screenshot Rules
*/

/* Rule Set ----------------------------------------------------------------- */

rule FVEY_ShadowBrokers_Jan17_Screen_Strings 
{

   meta:
      description = "Detects strings derived from the ShadowBroker's leak of Windows tools/exploits"
      author = "Florian Roth"
      reference = "https://bit.no.com:43110/theshadowbrokers.bit/post/message7/"
      date = "2017-01-08"

   strings:
      $x1 = "Danderspritz" ascii wide fullword
      $x2 = "DanderSpritz" ascii wide fullword
      $x3 = "PeddleCheap" ascii wide fullword
      $x4 = "ChimneyPool Addres" ascii wide fullword
      $a1 = "Getting remote time" fullword ascii
      $a2 = "RETRIEVED" fullword ascii
      $b1 = "Added Ops library to Python search path" fullword ascii
      $b2 = "target: z0.0.0.1" fullword ascii
      $c1 = "Psp_Avoidance" fullword ascii
      $c2 = "PasswordDump" fullword ascii
      $c3 = "InjectDll" fullword ascii
      $c4 = "EventLogEdit" fullword ascii
      $c5 = "ProcessModify" fullword ascii
      $d1 = "Mcl_NtElevation" fullword ascii wide
      $d2 = "Mcl_NtNativeApi" fullword ascii wide
      $d3 = "Mcl_ThreatInject" fullword ascii wide
      $d4 = "Mcl_NtMemory" fullword ascii wide

   condition:
      filesize < 2000KB and (1 of ($x*) or all of ($a*) or 1 of ($b*) or ( uint16(0) == 0x5a4d and 1 of ($c*) ) or 3 of ($c*) or ( uint16(0) == 0x5a4d and 3 of ($d*) ))
}

