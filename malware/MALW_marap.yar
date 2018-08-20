rule marap 
{

    meta:
        author = " J from THL <j@techhelplist.com>"
        date = "2018-08-19"
        reference1 = "https://www.virustotal.com/#/file/61dfc4d535d86359c2f09dbdd8f14c0a2e6367e5bb7377812f323a94d32341ba/detection"
        reference2 = "https://www.virustotal.com/#/file/c0c85f93a4f425a23c2659dce11e3b1c8b9353b566751b32fcb76b3d8b723b94/detection"
        reference3 = "https://threatpost.com/highly-flexible-marap-malware-enters-the-financial-scene/136623/"
        reference4 = "https://www.bleepingcomputer.com/news/security/necurs-botnet-pushing-new-marap-malware/"
        version = 1
        maltype = "Downloader"
        filetype = "memory"

    strings:
        $text01 = "%02X-%02X-%02X-%02X-%02X-%02X" wide
        $text02 = "%s, base=0x%p" wide
        $text03 = "pid=%d" wide
        $text04 = "%s %s" wide
        $text05 = "%d|%d|%s|%s|%s" wide
        $text06 = "%s|1|%d|%d|%d|%d|%d|%s" wide
        $text07 = "%d#%s#%s#%s#%d#%s#%s#%d#%s#%s#%s#%s#%d" wide
        $text08 = "%s|1|%d|%d|%d|%d|%d|%s#%s#%s#%s#%d#%d#%d" wide
        $text09 = "%s|0|%d" wide
        $text10 = "%llx" wide
        $text11 = "%s -a" wide

    condition:
        7 of them
}
