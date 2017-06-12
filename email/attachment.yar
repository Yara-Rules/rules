/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and 
    open to any user or organization, as long as you use it under this license.
*/

rule with_attachment : mail {
	meta:
		author = "Antonio Sanchez <asanchez@hispasec.com>"
		reference = "http://laboratorio.blogs.hispasec.com/"
		description = "Rule to detect the presence of an or several attachments"
	strings:
		$attachment_id = "X-Attachment-Id"
	condition:
		$attachment_id
}


rule without_attachments : mail {
	meta:
		author = "Antonio Sanchez <asanchez@hispasec.com>"
		reference = "http://laboratorio.blogs.hispasec.com/"
		description = "Rule to detect the no presence of any attachment"
	strings:
                $eml_01 = "From:"
                $eml_02 = "To:"
                $eml_03 = "Subject:"
		$attachment_id = "X-Attachment-Id"
                $mime_type = "Content-Type: multipart/mixed"
	condition:
                all of ( $eml_* ) and
		not $attachment_id and 
                not $mime_type
}

