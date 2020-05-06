rule PoetRat
{
    meta:
        Author = "Nishan Maharjan"
        Description = "A yara rule to catch PoetRat python scripts"
        Data = "6th May 2020"
    strings:
        $encrptionFunction = "Affine"
        $commands = /version|ls|cd|sysinfo|download|upload|shot|cp|mv|link|register|hid|compress|jobs|exit|tasklist|taskkill/
        $domain = "dellgenius.hopto.org"
        $grammer_massacre = /BADD|Bad Error Happened|/
        $mayBePresent = /self\.DIE|THE_GUID_KEY/
    condition:
    any of them        
}