/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and 
    open to any user or organization, as long as you use it under this license.
*/

rule with_urls : mail {
	meta:
		author = "Antonio Sanchez <asanchez@hispasec.com>"
		reference = "http://laboratorio.blogs.hispasec.com/"
		description = "Rule to detect the presence of an or several urls"
	strings:
                $eml_01 = "From:"
                $eml_02 = "To:"
                $eml_03 = "Subject:"

		$url_regex = /https?:\/\/([\w\.-]+)([\/\w \.-]*)/
	condition:
		all of them
}

rule without_urls : mail {
	meta:
		author = "Antonio Sanchez <asanchez@hispasec.com>"
		reference = "http://laboratorio.blogs.hispasec.com/"
		description = "Rule to detect the no presence of any url"
	strings:
                $eml_01 = "From:"
                $eml_02 = "To:"
                $eml_03 = "Subject:"

		$url_regex = /https?:\/\/([\w\.-]+)([\/\w \.-]*)/
	condition:
                all of ( $eml_* ) and
		not $url_regex
}
