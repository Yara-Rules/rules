rule Ransom : Crypren{
    meta:
        weight = 1
        Author = "@pekeinfo"
        reference = "https://github.com/pekeinfo/DecryptCrypren"
    strings: 
        $a = "won't be able to recover your files anymore.</p>"
        $b = {6A 03 68 ?? ?? ?? ?? B9 74 F1 AE 00 E8 ?? ?? ?? ?? E8 ?? ?? ?? ?? 68 98 3A 00 00 FF D6 6A 00 68 ?? ?? ?? ?? 68 ?? ?? ?? ??}
        $c = "Please restart your computer and wait for instructions for decrypting your files"
    condition:
        any of them
}
