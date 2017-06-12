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
                $eml_01 = "From:"
                $eml_02 = "To:"
                $eml_03 = "Subject:"
		$img_a = ".jpg" nocase
		$img_b = ".png" nocase
		$img_c = ".bmp" nocase
	condition:
                all of ( $eml_* ) and
		any of ( $img_* )
}

rule without_images : mail {
	meta:
		author = "Antonio Sanchez <asanchez@hispasec.com>"
		reference = "http://laboratorio.blogs.hispasec.com/"
		description = "Rule to detect the no presence of any image"
	strings:
                $eml_01 = "From:"
                $eml_02 = "To:"
                $eml_03 = "Subject:"

		$a = ".jpg" nocase
		$b = ".png" nocase
		$c = ".bmp" nocase
	condition:
                all of ( $eml_* ) and
		not $a and not $b and not $c
}
