/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as    long as you use it under this license.
*/

rule MacGyverCap : MacGyver
{
    meta:
        description = "Generic rule for MacGyver.cap"
        author = "xylitol@temari.fr"
        date = "2021-05-11"
        reference = "https://github.com/fboldewin/MacGyver-s-return---An-EMV-Chip-cloning-case/blob/master/MacGyver's%20return%20-%20An%20EMV%20Chip%20cloning%20case.pdf"
        // May only the challenge guide you
		hash1 = "9dc70002e82c78ee34c813597925c6cf8aa8d68b7e9ce5bcc70ea9bcab9dbf4a"		
    strings:
        $string1 = "src/MacGyver/javacard/Header.cap" ascii wide
        $string2 = "src/MacGyver/javacard/Directory.cap" ascii wide
		$string3 = "src/MacGyver/javacard/Applet.cap" ascii wide
		$string4 = "src/MacGyver/javacard/Import.cap" ascii wide
		$string5 = "src/MacGyver/javacard/ConstantPool.cap" ascii wide
		$string6 = "src/MacGyver/javacard/Class.cap" ascii wide
		$string7 = "src/MacGyver/javacard/Method.cap" ascii wide
    condition:  
         all of them
}

rule MacGyverCapInstaller : MacGyvercap Installer
{
    meta:
        description = "Generic rule for Hacktool:Win32/EMVSoft who install MacGyver.cap"
        author = "xylitol@temari.fr"
        date = "2021-05-11"
        reference = "https://github.com/fboldewin/MacGyver-s-return---An-EMV-Chip-cloning-case/blob/master/MacGyver's%20return%20-%20An%20EMV%20Chip%20cloning%20case.pdf"
        // May only the challenge guide you
		hash1 = "bb828eb0bbebabbcb51f490f4a0c08dd798b1f350dddddb6c00abcb6f750069f"
		hash2 = "04f0c9904675c7cf80ff1962bec5ef465ccf8c29e668f3158ec262414a6cc6eb"
		hash3 = "7335cd56a9ac08c200cca7e25b939e9c4ffa4d508207e68bee01904bf20a6528"
		hash4 = "af542ccb415647dbd80df902858a3d150a85f37992a35f29999eed76ac01a12b"
		hash5 = "247484124f4879bfacaae73ea32267e2c1e89773986df70a5f3456b1fb944c58"
		hash6 = "1cc8a2f3ce12f4b8356bda8b4aaf61d510d1078112af1c14cf4583090e062fbe"
		hash7 = "c23411deeec790e2dba37f4c49c7ecac3c867b7012431c9281ed748519eda65c"
		hash8 = "c0d11ed2eed0fef8d2f53920a1e12f667e03eafdb2d2941473d120e9e6f0e657"
		hash9 = "1ecfd3755eba578108363c0705c6ec205972080739ed0fbd17439f8139ba7e08" 
		hash10 = "87678c6dcf0065ffc487a284b9f79bd8c0815c5c621fc92f83df24393bfcc660"
    strings:
        $string1 = "delete -AID 315041592e5359532e4444463031" ascii wide
        $string2 = "install -file MacGyver.cap -nvDataLimit 1000 -instParam 00 -priv 4" ascii wide
		$string3 = "-mac_key 404142434445464748494a4b4c4d4e4f" ascii wide
		$string4 = "-enc_key 404142434445464748494a4b4c4d4e4f" ascii wide
    condition:  
         all of them
}