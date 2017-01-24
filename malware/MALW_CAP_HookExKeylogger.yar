/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as    long as you use it under this license.

*/

rule CAP_HookExKeylogger
{

meta:
    author = "Brian C. Bell -- @biebsmalwareguy"
    reference = "https://github.com/DFIRnotes/rules/blob/master/CAP_HookExKeylogger.yar"

    strings:
    $str_Win32hookapi = "SetWindowsHookEx" nocase
    $str_Win32llkey = "WH_KEYBOARD_LL" nocase
    $str_Win32key = "WH_KEYBOARD" nocase

    condition:
        2 of them
}
