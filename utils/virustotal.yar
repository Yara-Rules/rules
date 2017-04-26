//Rule to Catch Intelligence files in the meta of files uploaded. Current rule looks for NSA and MOSAD in meta of samples.

rule catch_intelligence_files
{
meta:
	author = "@abhinavbom"
	maltype = "NA"
	version = "0.1"
	date = "21/09/2015"
    description = "catch files"
strings:
    $meta1 = "National Security Agency"
    $meta3 = "Israeli Secret Intelligence"
    $tag1 = "docx"
	$tag2 = "doc"
	$tag3 = "xls"
	$tag4 = "xlxs"
	$tag5 = "pdf"
	$tag6 = "zip"
	$tag7 = "rar"
    	$tag8 = "xlsb"

condition:
    any of ($meta*) and any of ($tag*)
}

//Rule to pick up all the pcaps uploaded to Virustotal. This rule can be very noisy. 

rule FE_PCAPs
{
meta:
	author = "@abhinavbom"
	maltype = "NA"
	version = "0.1"
	description = "All pcaps uploaded to VT"
	date = "29/07/2015"
strings:
	$magic = {D4 C3 B2 A1}
condition:
	$magic at 0
}

//Rule to detect all pcap uploads to Virustotal with +3 detection.

rule pcap_positives
{
meta:
	author = "@abhinavbom"
	maltype = "NA"
	version = "0.1"
	description = "All pcaps uploaded to VT with +3 detection rate"
	date = "21/06/2015"
strings:
	$magic = {D4 C3 B2 A1}
condition:
	$magic at 0 and positives > 3
}

//Rule to detect All pcaps submitted to VT and tagged as Exploit kits.

rule ek_submissions				
{
meta:
	author = "@abhinavbom"
	maltype = "NA"
	version = "0.1"
	description = "Detects pcaps uploaded to VT and matches IDS detections for Exploit kits"
	date = "23/06/2015"
strings:
	$magic = {D4 C3 B2 A1}
condition:
	$magic at 0 and tags contains "exploit-kit"
}

//EK detection in VT for +3 positive engine detections

rule ek_submissions_2				
{
meta:
	author = "@abhinavbom"
	maltype = "NA"
	version = "0.1"
	description = "Detects pcaps uploaded to VT and matches IDS detections for Exploit kits"
	date = "23/06/2015"
strings:
	$magic = {D4 C3 B2 A1}
condition:
	$magic at 0 and tags contains "exploit-kit" and positives >3
}
