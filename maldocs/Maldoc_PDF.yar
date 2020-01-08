/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as    long as you use it under this license.

*/

rule malicious_author : PDF raw
{
	meta:
		author = "Glenn Edwards (@hiddenillusion)"
		version = "0.1"
		weight = 5
		
	strings:
		$magic = { 25 50 44 46 }
		
		$reg0 = /Creator.?\(yen vaw\)/
		$reg1 = /Title.?\(who cis\)/
		$reg2 = /Author.?\(ser pes\)/
	condition:
		$magic in (0..1024) and all of ($reg*)
}

rule suspicious_version : PDF raw
{
	meta:
		author = "Glenn Edwards (@hiddenillusion)"
		version = "0.1"
		weight = 3
		
	strings:
		$magic = { 25 50 44 46 }
		$ver = /%PDF-1.\d{1}/
	condition:
		$magic in (0..1024) and not $ver
}

rule suspicious_creation : PDF raw
{
	meta:
		author = "Glenn Edwards (@hiddenillusion)"
		version = "0.1"
		weight = 2
		
	strings:
		$magic = { 25 50 44 46 }
		$header = /%PDF-1\.(3|4|6)/
		
		$create0 = /CreationDate \(D:20101015142358\)/
		$create1 = /CreationDate \(2008312053854\)/
	condition:
		$magic in (0..1024) and $header and 1 of ($create*)
}

rule multiple_filtering : PDF raw
{
meta: 
author = "Glenn Edwards (@hiddenillusion)"
version = "0.2"
weight = 3

    strings:
            $magic = { 25 50 44 46 }
            $attrib = /\/Filter.*(\/ASCIIHexDecode\W+|\/LZWDecode\W+|\/ASCII85Decode\W+|\/FlateDecode\W+|\/RunLengthDecode){2}/ 
            // left out: /CCITTFaxDecode, JBIG2Decode, DCTDecode, JPXDecode, Crypt

    condition: 
            $magic in (0..1024) and $attrib
}

rule suspicious_title : PDF raw
{
	meta:
		author = "Glenn Edwards (@hiddenillusion)"
		version = "0.1"
		weight = 4
		
	strings:
		$magic = { 25 50 44 46 }
		$header = /%PDF-1\.(3|4|6)/
		
		$title0 = "who cis"
		$title1 = "P66N7FF"
		$title2 = "Fohcirya"
	condition:
		$magic in (0..1024) and $header and 1 of ($title*)
}

rule suspicious_author : PDF raw
{
	meta:
		author = "Glenn Edwards (@hiddenillusion)"
		version = "0.1"
		weight = 4
		
	strings:
		$magic = { 25 50 44 46 }
		$header = /%PDF-1\.(3|4|6)/

		$author0 = "Ubzg1QUbzuzgUbRjvcUb14RjUb1"
		$author1 = "ser pes"
		$author2 = "Miekiemoes"
		$author3 = "Nsarkolke"
	condition:
		$magic in (0..1024) and $header and 1 of ($author*)
}

rule suspicious_producer : PDF raw 
{
	meta:
		author = "Glenn Edwards (@hiddenillusion)"
		version = "0.1"
		weight = 2
		
	strings:
		$magic = { 25 50 44 46 }
		$header = /%PDF-1\.(3|4|6)/
		
		$producer0 = /Producer \(Scribus PDF Library/
		$producer1 = "Notepad"
	condition:
		$magic in (0..1024) and $header and 1 of ($producer*)
}

rule suspicious_creator : PDF raw
{
	meta:
		author = "Glenn Edwards (@hiddenillusion)"
		version = "0.1"
		weight = 3
		
	strings:
		$magic = { 25 50 44 46 }
		$header = /%PDF-1\.(3|4|6)/
		
		$creator0 = "yen vaw"
		$creator1 = "Scribus"
		$creator2 = "Viraciregavi"
	condition:
		$magic in (0..1024) and $header and 1 of ($creator*)
}

rule possible_exploit : PDF raw
{
	meta:
		author = "Glenn Edwards (@hiddenillusion)"
		version = "0.1"
		weight = 3
		
	strings:
		$magic = { 25 50 44 46 }
		
		$attrib0 = /\/JavaScript /
		$attrib3 = /\/ASCIIHexDecode/
		$attrib4 = /\/ASCII85Decode/

		$action0 = /\/Action/
		$action1 = "Array"
		$shell = "A"
		$cond0 = "unescape"
		$cond1 = "String.fromCharCode"
		
		$nop = "%u9090%u9090"
	condition:
		$magic in (0..1024) and (2 of ($attrib*)) or ($action0 and #shell > 10 and 1 of ($cond*)) or ($action1 and $cond0 and $nop)
}

rule shellcode_blob_metadata : PDF raw
{
        meta:
                author = "Glenn Edwards (@hiddenillusion)"
                version = "0.1"
                description = "When there's a large Base64 blob inserted into metadata fields it often indicates shellcode to later be decoded"
                weight = 4
        strings:
                $magic = { 25 50 44 46 }

                $reg_keyword = /\/Keywords.?\(([a-zA-Z0-9]{200,})/ //~6k was observed in BHEHv2 PDF exploits holding the shellcode
                $reg_author = /\/Author.?\(([a-zA-Z0-9]{200,})/
                $reg_title = /\/Title.?\(([a-zA-Z0-9]{200,})/
                $reg_producer = /\/Producer.?\(([a-zA-Z0-9]{200,})/
                $reg_creator = /\/Creator.?\(([a-zA-Z0-9]{300,})/
                $reg_create = /\/CreationDate.?\(([a-zA-Z0-9]{200,})/

        condition:
                $magic in (0..1024) and 1 of ($reg*)
}

rule suspicious_js : PDF raw
{
	meta:
		author = "Glenn Edwards (@hiddenillusion)"
		version = "0.1"
		weight = 3
		
	strings:
		$magic = { 25 50 44 46 }
		
		$attrib0 = /\/OpenAction /
		$attrib1 = /\/JavaScript /

		$js0 = "eval"
		$js1 = "Array"
		$js2 = "String.fromCharCode"
		
	condition:
		$magic in (0..1024) and all of ($attrib*) and 2 of ($js*)
}

rule suspicious_launch_action : PDF raw
{
	meta:
		author = "Glenn Edwards (@hiddenillusion)"
		version = "0.1"
		weight = 2
		
	strings:
		$magic = { 25 50 44 46 }
		
		$attrib0 = /\/Launch/
		$attrib1 = /\/URL /
		$attrib2 = /\/Action/
		$attrib3 = /\/OpenAction/
		$attrib4 = /\/F /

	condition:
		$magic in (0..1024) and 3 of ($attrib*)
}

rule suspicious_embed : PDF raw
{
	meta:
		author = "Glenn Edwards (@hiddenillusion)"
		version = "0.1"
		ref = "https://feliam.wordpress.com/2010/01/13/generic-pdf-exploit-hider-embedpdf-py-and-goodbye-av-detection-012010/"
		weight = 2
		
	strings:
		$magic = { 25 50 44 46 }
		
		$meth0 = /\/Launch/
		$meth1 = /\/GoTo(E|R)/ //means go to embedded or remote
		$attrib0 = /\/URL /
		$attrib1 = /\/Action/
		$attrib2 = /\/Filespec/
		
	condition:
		$magic in (0..1024) and 1 of ($meth*) and 2 of ($attrib*)
}

rule suspicious_obfuscation : PDF raw
{
	meta:
		author = "Glenn Edwards (@hiddenillusion)"
		version = "0.1"
		weight = 2
		
	strings:
		$magic = { 25 50 44 46 }
		$reg = /\/\w#[a-zA-Z0-9]{2}#[a-zA-Z0-9]{2}/
		
	condition:
		$magic in (0..1024) and #reg > 5
}

rule invalid_XObject_js : PDF raw
{
	meta:
		author = "Glenn Edwards (@hiddenillusion)"
		description = "XObject's require v1.4+"
		ref = "https://blogs.adobe.com/ReferenceXObjects/"
		version = "0.1"
		weight = 2
		
	strings:
		$magic = { 25 50 44 46 }
		$ver = /%PDF-1\.[4-9]/
		
		$attrib0 = /\/XObject/
		$attrib1 = /\/JavaScript/
		
	condition:
		$magic in (0..1024) and not $ver and all of ($attrib*)
}

rule invalid_trailer_structure : PDF raw
{
	meta:
		author = "Glenn Edwards (@hiddenillusion)"
		version = "0.1"
		weight = 1
		
        strings:
                $magic = { 25 50 44 46 }
				// Required for a valid PDF
                $reg0 = /trailer\r?\n?.*\/Size.*\r?\n?\.*/
                $reg1 = /\/Root.*\r?\n?.*startxref\r?\n?.*\r?\n?%%EOF/

        condition:
                $magic in (0..1024) and not $reg0 and not $reg1
}

rule multiple_versions : PDF raw
{
	meta:
		author = "Glenn Edwards (@hiddenillusion)"
		version = "0.1"
        description = "Written very generically and doesn't hold any weight - just something that might be useful to know about to help show incremental updates to the file being analyzed"		
		weight = 1
		
        strings:
                $magic = { 25 50 44 46 }
                $s0 = "trailer"
                $s1 = "%%EOF"

        condition:
                $magic in (0..1024) and #s0 > 1 and #s1 > 1
}

rule js_wrong_version : PDF raw
{
	meta:
		author = "Glenn Edwards (@hiddenillusion)"
		description = "JavaScript was introduced in v1.3"
		ref = "http://wwwimages.adobe.com/www.adobe.com/content/dam/Adobe/en/devnet/pdf/pdfs/pdf_reference_1-7.pdf"
		version = "0.1"
		weight = 2
		
        strings:
                $magic = { 25 50 44 46 }
				$js = /\/JavaScript/
				$ver = /%PDF-1\.[3-9]/

        condition:
                $magic in (0..1024) and $js and not $ver
}

rule JBIG2_wrong_version : PDF raw
{
	meta:
		author = "Glenn Edwards (@hiddenillusion)"
		description = "JBIG2 was introduced in v1.4"
		ref = "http://wwwimages.adobe.com/www.adobe.com/content/dam/Adobe/en/devnet/pdf/pdfs/pdf_reference_1-7.pdf"
		version = "0.1"
		weight = 1
		
        strings:
                $magic = { 25 50 44 46 }
				$js = /\/JBIG2Decode/
				$ver = /%PDF-1\.[4-9]/

        condition:
                $magic in (0..1024) and $js and not $ver
}

rule FlateDecode_wrong_version : PDF raw
{
	meta:
		author = "Glenn Edwards (@hiddenillusion)"
		description = "Flate was introduced in v1.2"
		ref = "http://wwwimages.adobe.com/www.adobe.com/content/dam/Adobe/en/devnet/pdf/pdfs/pdf_reference_1-7.pdf"
		version = "0.1"
		weight = 1
		
        strings:
                $magic = { 25 50 44 46 }
				$js = /\/FlateDecode/
				$ver = /%PDF-1\.[2-9]/

        condition:
                $magic in (0..1024) and $js and not $ver
}

rule embed_wrong_version : PDF raw
{
	meta:
		author = "Glenn Edwards (@hiddenillusion)"
		description = "EmbeddedFiles were introduced in v1.3"
		ref = "http://wwwimages.adobe.com/www.adobe.com/content/dam/Adobe/en/devnet/pdf/pdfs/pdf_reference_1-7.pdf"
		version = "0.1"
		weight = 1
		
        strings:
                $magic = { 25 50 44 46 }
				$embed = /\/EmbeddedFiles/
				$ver = /%PDF-1\.[3-9]/

        condition:
                $magic in (0..1024) and $embed and not $ver
}

rule invalid_xref_numbers : PDF raw
{
        meta:
			author = "Glenn Edwards (@hiddenillusion)"
			version = "0.1"
			description = "The first entry in a cross-reference table is always free and has a generation number of 65,535"
			notes = "This can be also be in a stream..."
			weight = 1
		
        strings:
                $magic = { 25 50 44 46 }
                $reg0 = /xref\r?\n?.*\r?\n?.*65535\sf/
                $reg1 = /endstream.*\r?\n?endobj.*\r?\n?startxref/
        condition:
                $magic in (0..1024) and not $reg0 and not $reg1
}

rule js_splitting : PDF raw
{
        meta:
                author = "Glenn Edwards (@hiddenillusion)"
                version = "0.1"
                description = "These are commonly used to split up JS code"
                weight = 2
                
        strings:
                $magic = { 25 50 44 46 }
				$js = /\/JavaScript/
                $s0 = "getAnnots"
                $s1 = "getPageNumWords"
                $s2 = "getPageNthWord"
                $s3 = "this.info"
                                
        condition:
                $magic in (0..1024) and $js and 1 of ($s*)
}

rule header_evasion : PDF raw
{
        meta:
                author = "Glenn Edwards (@hiddenillusion)"
                description = "3.4.1, 'File Header' of Appendix H states that ' Acrobat viewers require only that the header appear somewhere within the first 1024 bytes of the file.'  Therefore, if you see this trigger then any other rule looking to match the magic at 0 won't be applicable"
                ref = "http://wwwimages.adobe.com/www.adobe.com/content/dam/Adobe/en/devnet/pdf/pdfs/pdf_reference_1-7.pdf"
                version = "0.1"
                weight = 3

        strings:
                $magic = { 25 50 44 46 }
        condition:
                $magic in (5..1024) and #magic == 1
}

rule BlackHole_v2 : PDF raw
{
	meta:
		author = "Glenn Edwards (@hiddenillusion)"
		version = "0.1"
		ref = "http://fortknoxnetworks.blogspot.no/2012/10/blackhhole-exploit-kit-v-20-url-pattern.html"
		weight = 3
		
	strings:
		$magic = { 25 50 44 46 }
		$content = "Index[5 1 7 1 9 4 23 4 50"
		
	condition:
		$magic in (0..1024) and $content
}


rule XDP_embedded_PDF : PDF raw
{
	meta:
		author = "Glenn Edwards (@hiddenillusion)"
		version = "0.1"
		ref = "http://blog.9bplus.com/av-bypass-for-malicious-pdfs-using-xdp"
        weight = 1		

	strings:
		$s1 = "<pdf xmlns="
		$s2 = "<chunk>"
		$s3 = "</pdf>"
		$header0 = "%PDF"
		$header1 = "JVBERi0"

	condition:
		all of ($s*) and 1 of ($header*)
}

rule PDF_Embedded_Exe : PDF
{
	meta:
		ref = "https://github.com/jacobsoo/Yara-Rules/blob/master/PDF_Embedded_Exe.yar"
	strings:
    	$header = {25 50 44 46}
    	$Launch_Action = {3C 3C 2F 53 2F 4C 61 75 6E 63 68 2F 54 79 70 65 2F 41 63 74 69 6F 6E 2F 57 69 6E 3C 3C 2F 46}
        $exe = {3C 3C 2F 45 6D 62 65 64 64 65 64 46 69 6C 65 73}
    condition:
    	$header at 0 and $Launch_Action and $exe
}
