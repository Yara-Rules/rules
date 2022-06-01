/*This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as long as you use it under this license.*/

rule md5_hashed_default_creds_schneider_premiumftp
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for schneider_premiumftp. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="4c8ce3a1e02483869495ebf94802fa42"
    $a1="91f9d6ca2c1695bf22a22b2cb6a54489"
condition:
    ($a0 and $a1)
}

rule sha1_hashed_default_creds_schneider_premiumftp
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for schneider_premiumftp. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="ad9a978fec29fc8a566a4aca31b197f6c9f2c1ca"
    $a1="3c3e51590a3678f06e867bc4a8dab221fc45f2e8"
condition:
    ($a0 and $a1)
}

rule sha384_hashed_default_creds_schneider_premiumftp
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for schneider_premiumftp. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="0e69d9669ab0fe4989553c463d738a416237eed0e502bbd4411a7d55f1284b21d407e087e837042ac27cae5e3651840f"
    $a1="4c31fa9f2233521784230faef6e76e1ad97eebd300ef2675ab55ef8dda8b0564ad3a562939020d4ed678ac5201d75845"
condition:
    ($a0 and $a1)
}

rule sha224_hashed_default_creds_schneider_premiumftp
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for schneider_premiumftp. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="f308d01316af4e6b9b0a766f5b328f00723fdc1b97c2859f07bb1114"
    $a1="ee2d93e39d51298022af4b5d1df8a3be22a455beb4bb3e18c539d0bb"
condition:
    ($a0 and $a1)
}

rule sha512_hashed_default_creds_schneider_premiumftp
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for schneider_premiumftp. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="6162eb4b9377a7c411410c77e310652d31da64a51df77d3b5713f4b9291923fac30c67b26e9f544643957c7ebc5424edbf44a9b563e05ef74917d39ce3d4529a"
    $a1="e36ac69210f52ff081cf7e811a791f766e6d56a960ef58ad08447ff60fe9c6ee58bccea8dedb04f4bb30c2d4c26dea2a43908970d1d5968aa1555626d0c66c1e"
condition:
    ($a0 and $a1)
}

rule sha256_hashed_default_creds_schneider_premiumftp
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for schneider_premiumftp. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="23a1d40404715c2a6970c6350b01920ec417bdb3f1f6f399ecb3f073542b58eb"
    $a1="7ab18fd7a14d6d731de6eb91fb5bdb2123e705af7fe2442139198f06b7948feb"
condition:
    ($a0 and $a1)
}

rule blake2b_hashed_default_creds_schneider_premiumftp
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for schneider_premiumftp. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="4548f269ecb8d41644522baed22de8734e3499897742b59ac51cd442e8fbfbc3d19866cdbd7a917e85fa99440e3c5dae7633a78433ecc39b97510fc21ee1c522"
    $a1="1eb32b2f1ce876fac529b7928657c1b8f885d75663eb082bd07d212ccfd7ea5dc890beacc5d26f47fe2ade13b45cbbc6be0f3b0614e83dd5ec8daf0b8b6bc29a"
condition:
    ($a0 and $a1)
}

rule blake2s_hashed_default_creds_schneider_premiumftp
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for schneider_premiumftp. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="f901bf102a696e8e217c3d7c3ff8943208fa34cedba1edb459d56000bc67083f"
    $a1="4c7d8db1c3f3fcd06f80159186f42455496cfc4a9335429199ff41a0902d5e24"
condition:
    ($a0 and $a1)
}

rule sha3_224_hashed_default_creds_schneider_premiumftp
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for schneider_premiumftp. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="a4d6b17f5d20ce6223a308d938b07a9f3ec093233757eb9e387c963a"
    $a1="eca1b37497244881579be9058e9b7211159de6f1df36b55d22cef8d3"
condition:
    ($a0 and $a1)
}

rule sha3_256_hashed_default_creds_schneider_premiumftp
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for schneider_premiumftp. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="ee372019b48bff763cdab6b666d63d413b6bab26429d03f66406dbef07b978d8"
    $a1="fec3572a226527ba9a636836222a7231362a9f348b1a4caf2cbfef230a703aea"
condition:
    ($a0 and $a1)
}

rule sha3_384_hashed_default_creds_schneider_premiumftp
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for schneider_premiumftp. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="46d4665406a2b67de50adfa819779a33d776eb80884c016b31f2d9d12bc3f584f8d1ad18f9da4efd4618b6f18dd6ebdd"
    $a1="1982f42589842b2044a81748873969acbc6ab0b28305259651b29c6a3dbe9e17515dd60ea81dd506ad0a6df96e048726"
condition:
    ($a0 and $a1)
}

rule sha3_512_hashed_default_creds_schneider_premiumftp
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for schneider_premiumftp. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="cb3b953d592297d5ca7659f59e3c0dc1c7a273b851446855dd90854e14606e96b355d9b419766493a56cd06e28d6bf49849bf33951787d00af188f2663e18df8"
    $a1="6fc99f5ae5ba7605fd6ae2d3d2b5c56821ffb0a9e1f257ed31eaee5bc374919bd8aa81fdb7ab9cfae9d0a7de7cd98f2ec45c5fa9998eb04ddfdc01e754f6411a"
condition:
    ($a0 and $a1)
}

rule base64_hashed_default_creds_schneider_premiumftp
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for schneider_premiumftp. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="c3lzZGlhZw=="
    $a1="ZmFjdG9yeWNhc3RAc2NobmVpZGVy"
condition:
    ($a0 and $a1)
}

