/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as long as you use it under this license.
*/

rule Word_2007_XML_Flat_OPC : maldoc
{
	meta:
		author = "Martin Willing (https://evild3ad.com)"
		description = "Detect Word 2007 XML Document in the Flat OPC format w/ embedded Microsoft Office 2007+ document"
		date = "2018-04-29"
		reference = "https://blogs.msdn.microsoft.com/ericwhite/2008/09/29/the-flat-opc-format/"
		hash1 = "060c036ce059b465a05c42420efa07bf"
		hash2 = "2af21d35bb909a0ac081c2399d0939b1"
		hash3 = "72ffa688c228b0b833e69547885650fe"
		filetype = "Office documents"
		
	strings:
		$xml = "<?xml" // XML declaration
		$WordML = "<?mso-application progid=\"Word.Document\"?>" // XML processing instruction => A Windows OS with Microsoft Office installed will recognize the file as a MS Word document.
		$OPC = "<pkg:package" // Open XML Package
		$xmlns = "http://schemas.microsoft.com/office/2006/xmlPackage" // XML namespace => Microsoft Office 2007 XML Schema Reference
		$binaryData = "<pkg:binaryData>0M8R4KGxGuE" // Binary Part (Microsoft Office 2007+ document encoded in a Base64 string, broken into lines of 76 characters) => D0 CF 11 E0 A1 B1 1A E1 (vbaProject.bin / DOCM)
		$docm = "pkg:name=\"/word/vbaProject.bin\"" // Binary Object
		
	condition:
	 	$xml at 0 and $WordML and $OPC and $xmlns and $binaryData and $docm
}