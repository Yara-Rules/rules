/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as    long as you use it under this license.
*/

rule MSILStealer
{
    meta:
        description = "Detects strings from C#/VB Stealers and QuasarRat"
        reference = "https://github.com/quasar/QuasarRAT"
        author = "https://github.com/hwvs"
        last_modified = "2019-11-21"

    strings:
        $ = "Firefox does not have any profiles, has it ever been launched?" wide ascii
        $ = "Firefox is not installed, or the install path could not be located" wide ascii
        $ = "No installs of firefox recorded in its key." wide ascii
        $ = "{0}\\\\FileZilla\\\\recentservers.xml" wide ascii
        $ = "{1}{0}Cookie Name: {2}{0}Value: {3}{0}Path" wide ascii
        $ = "[PRIVATE KEY LOCATION: \\\"{0}\\\"]" wide ascii

    condition:
        1 of them
}
