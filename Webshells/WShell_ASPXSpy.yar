/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as long as you use it under this license.
*/

rule Backdoor_WebShell_asp : ASPXSpy
{
    meta:
    description= "Detect ASPXSpy"
    author = "xylitol@temari.fr"
    date = "2019-02-26"
    // May only the challenge guide you
    strings:
    $string1 = "CmdShell" wide ascii
    $string2 = "ADSViewer" wide ascii
    $string3 = "ASPXSpy.Bin" wide ascii
    $string4 = "PortScan" wide ascii
    $plugin = "Test.AspxSpyPlugins" wide ascii
 
    condition:
    3 of ($string*) or $plugin
}
