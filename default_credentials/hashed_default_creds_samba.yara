/*This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as long as you use it under this license.*/

rule md5_hashed_default_creds_samba
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for samba. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="ed36a1ef76a59ee3f15180e0441188ad"
    $a1="ed36a1ef76a59ee3f15180e0441188ad"
condition:
    ($a0 and $a1)
}

rule sha1_hashed_default_creds_samba
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for samba. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="322444d3bb52c341f429ca0454f292dc242f315b"
    $a1="322444d3bb52c341f429ca0454f292dc242f315b"
condition:
    ($a0 and $a1)
}

rule sha384_hashed_default_creds_samba
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for samba. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="66d1998530f9c3e73cfa60eca4f14ea04ce7e11b9420fd614c6759c304f5610490dac7df7d7f0a49d73bb9bca238da71"
    $a1="66d1998530f9c3e73cfa60eca4f14ea04ce7e11b9420fd614c6759c304f5610490dac7df7d7f0a49d73bb9bca238da71"
condition:
    ($a0 and $a1)
}

rule sha224_hashed_default_creds_samba
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for samba. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="2cdc069c1b6c826781363e8277957d71cf5e8250032d2d80babc7476"
    $a1="2cdc069c1b6c826781363e8277957d71cf5e8250032d2d80babc7476"
condition:
    ($a0 and $a1)
}

rule sha512_hashed_default_creds_samba
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for samba. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="4e83b7fe1803c622124721a2e4643172a45874fd040092eaf92abb28f2a3b043c8ceabeb78679994fc15413412742ff9979d97e31d7241d81a9bfbb21b3dcad8"
    $a1="4e83b7fe1803c622124721a2e4643172a45874fd040092eaf92abb28f2a3b043c8ceabeb78679994fc15413412742ff9979d97e31d7241d81a9bfbb21b3dcad8"
condition:
    ($a0 and $a1)
}

rule sha256_hashed_default_creds_samba
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for samba. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="2b505597daa736f13c2910c260e8deb1af3b20ffe375eb5e01a003e92f541db9"
    $a1="2b505597daa736f13c2910c260e8deb1af3b20ffe375eb5e01a003e92f541db9"
condition:
    ($a0 and $a1)
}

rule blake2b_hashed_default_creds_samba
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for samba. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="bfdac9ce1773da6d763d9a76e0d4e74b0f284e9df7f1a04d9145d04ac1117fee14b6a54e1574c7834604e3b60b122f4674e5f0d1535740a0b612b60abd67e7cf"
    $a1="bfdac9ce1773da6d763d9a76e0d4e74b0f284e9df7f1a04d9145d04ac1117fee14b6a54e1574c7834604e3b60b122f4674e5f0d1535740a0b612b60abd67e7cf"
condition:
    ($a0 and $a1)
}

rule blake2s_hashed_default_creds_samba
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for samba. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="e5b3fd72350137e302475ed0363d8f4d7c2313aceb9f31d2a0aa45509de7c8c7"
    $a1="e5b3fd72350137e302475ed0363d8f4d7c2313aceb9f31d2a0aa45509de7c8c7"
condition:
    ($a0 and $a1)
}

rule sha3_224_hashed_default_creds_samba
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for samba. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="a7958fb4bf861c0de89ee4fbc7e08e6a85679ea81cbd8de2181703ad"
    $a1="a7958fb4bf861c0de89ee4fbc7e08e6a85679ea81cbd8de2181703ad"
condition:
    ($a0 and $a1)
}

rule sha3_256_hashed_default_creds_samba
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for samba. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="951d867bf1ede717ac94254d5fd45b6133471ebe860eb8583648ca3f89c8ed79"
    $a1="951d867bf1ede717ac94254d5fd45b6133471ebe860eb8583648ca3f89c8ed79"
condition:
    ($a0 and $a1)
}

rule sha3_384_hashed_default_creds_samba
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for samba. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="58cfccd6944bcc1b58986ea78c313b6891b1767b1f292a678ddb604c8a5be59ddcb6f6de45594db2355ac2e205947cb5"
    $a1="58cfccd6944bcc1b58986ea78c313b6891b1767b1f292a678ddb604c8a5be59ddcb6f6de45594db2355ac2e205947cb5"
condition:
    ($a0 and $a1)
}

rule sha3_512_hashed_default_creds_samba
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for samba. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="f28ebf2dd4962b4cdac27b3156c47853669d9acbf5727bb156a090fb1520d6e685e9356cc2d6b53361bfb885f18727d31596cf2052c139626ffd5299b3d2e0b8"
    $a1="f28ebf2dd4962b4cdac27b3156c47853669d9acbf5727bb156a090fb1520d6e685e9356cc2d6b53361bfb885f18727d31596cf2052c139626ffd5299b3d2e0b8"
condition:
    ($a0 and $a1)
}

rule base64_hashed_default_creds_samba
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for samba. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="QW55"
    $a1="QW55"
condition:
    ($a0 and $a1)
}

