rule EliseLotusBlossom
{

meta:
    author = "Jose Ramon Palanco"
    date = "2015-06-23"
    description = "Elise Backdoor Trojan"
    ref = "https://www.paloaltonetworks.com/resources/research/unit42-operation-lotus-blossom.html"

strings:
    $magic = { 4d 5a }
    $s1 = "\",Update" wide
    $s2 = "LoaderDLL.dll"
    $s3 = "Kernel32.dll"
    $s4 = "{5947BACD-63BF-4e73-95D7-0C8A98AB95F2}"
    $s5 = "\\Network\\" wide
    $s6 = "0SSSSS"
    $s7 = "441202100205"
    $s8 = "0WWWWW"

condition:
    $magic at 0 and all of ($s*)    
}
