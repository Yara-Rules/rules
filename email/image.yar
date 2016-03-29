/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and 
    open to any user or organization, as long as you use it under this license.
*/

rule with_images : mail {
	meta:
		author = "Antonio Sanchez <asanchez@hispasec.com>"
		reference = "http://laboratorio.blogs.hispasec.com/"
		description = "Rule to detect the presence of an or several images"
	strings:
		$a = ".jpg" nocase
		$b = ".png" nocase
		$c = ".bmp" nocase
	condition:
		any of them
}

rule without_images : mail {
	meta:
		author = "Antonio Sanchez <asanchez@hispasec.com>"
		reference = "http://laboratorio.blogs.hispasec.com/"
		description = "Rule to detect the no presence of any image"
	strings:
		$a = ".jpg" nocase
		$b = ".png" nocase
		$c = ".bmp" nocase
	condition:
		not $a and not $b and not $c
}
