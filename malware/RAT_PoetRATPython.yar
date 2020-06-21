rule PoetRat_Python
{
    meta:
        Author = "Nishan Maharjan"
        Description = "A yara rule to catch PoetRat python scripts"
        Data = "6th May 2020"
    strings:

        // Any of the strings that stand out in the files, these are for the multiple python files, not just for a single file
        $encrptionFunction = "Affine"
        $commands = /version|ls|cd|sysinfo|download|upload|shot|cp|mv|link|register|hid|compress|jobs|exit|tasklist|taskkill/
        $domain = "dellgenius.hopto.org"
        $grammer_massacre = /BADD|Bad Error Happened|/
        $mayBePresent = /self\.DIE|THE_GUID_KEY/
        $pipe_out = "Abibliophobia23"
        $shot = "shot_{0}_{1}.png"
    condition:
        3 of them        
}
