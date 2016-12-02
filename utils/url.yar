/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as
    long as you use it under this license.
*/

rule url {
    meta:
        author = "Antonio S. <asanchez@plutec.net>"
    strings:
        $url_regex = /https?:\/\/([\w\.-]+)([\/\w \.-]*)/ wide ascii
    condition:
        $url_regex
}
