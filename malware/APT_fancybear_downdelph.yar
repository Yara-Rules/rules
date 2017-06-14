rule APT_fancybear_Downdelph_magic : Bootkit{
	meta:
		author = "Marc Salinas @Bondey_m"
		description = "APT28 downdelph magic string"
		reference = "https://www.threatminer.org/_reports/2016/eset-sednit-part3%20-%20ESET.pdf#viewer.action=download"
	strings:
		$str1 = " :3 "
	condition:
		$str1 at 0
}



rule APT_fancybear_Downdelph_MBR : Bootkit{
	meta:
		author = "Marc Salinas @Bondey_m"
		description = "APT28 downdelph string on MBR (get your MBR with BOOTICE on Win or #dd if=/dev/sda of=./sda.mbr bs=512 count=1"
		reference = "https://www.threatminer.org/_reports/2016/eset-sednit-part3%20-%20ESET.pdf#viewer.action=download"
	strings:
		$s1 = { 20 3A 33 20 } //string " :3 "
	condition:
		$s1 at 411  //posición 0x19b
}