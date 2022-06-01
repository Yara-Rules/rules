/*This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as long as you use it under this license.*/

rule md5_hashed_default_creds_warracorp
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for warracorp. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="6cd357a673573da8c6e9608d87c77af2"
    $a1="6cd357a673573da8c6e9608d87c77af2"
condition:
    ($a0 and $a1)
}

rule sha1_hashed_default_creds_warracorp
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for warracorp. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="7631047c2fb847aaf4962e7b895429056ffaf91b"
    $a1="7631047c2fb847aaf4962e7b895429056ffaf91b"
condition:
    ($a0 and $a1)
}

rule sha384_hashed_default_creds_warracorp
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for warracorp. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="64c9b548de7347c89fe02e858c0d26fff14b95da8f4ed74c3159446d3748d98eaf7a8a44b7a262a20a8112729b5dbe45"
    $a1="64c9b548de7347c89fe02e858c0d26fff14b95da8f4ed74c3159446d3748d98eaf7a8a44b7a262a20a8112729b5dbe45"
condition:
    ($a0 and $a1)
}

rule sha224_hashed_default_creds_warracorp
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for warracorp. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="15f5bc8fd57b7ab48a8666a44b337bfceba30e74b6443b17c8ae6e32"
    $a1="15f5bc8fd57b7ab48a8666a44b337bfceba30e74b6443b17c8ae6e32"
condition:
    ($a0 and $a1)
}

rule sha512_hashed_default_creds_warracorp
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for warracorp. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="1e055d249efc8f9381537a966433b628b8f54cd85e129386d0c5186a8d54a0c079381800d236ae2f26cbb125d7ecdc859761a9a7cb142fd608f8212764574e04"
    $a1="1e055d249efc8f9381537a966433b628b8f54cd85e129386d0c5186a8d54a0c079381800d236ae2f26cbb125d7ecdc859761a9a7cb142fd608f8212764574e04"
condition:
    ($a0 and $a1)
}

rule sha256_hashed_default_creds_warracorp
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for warracorp. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="22e92e460fdd489baa65df3aa9edefc18fa1ee999d269fd1ce869274727a5fd0"
    $a1="22e92e460fdd489baa65df3aa9edefc18fa1ee999d269fd1ce869274727a5fd0"
condition:
    ($a0 and $a1)
}

rule blake2b_hashed_default_creds_warracorp
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for warracorp. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="9ee98fd2f70bf0e7502a2fe399557fe972b48ed8e217b4cc345ae12963fe5c62dea6fd72f8413d0d4a8b4ffaa998e343375e72aae4963232cdc6ef3d92ef2948"
    $a1="9ee98fd2f70bf0e7502a2fe399557fe972b48ed8e217b4cc345ae12963fe5c62dea6fd72f8413d0d4a8b4ffaa998e343375e72aae4963232cdc6ef3d92ef2948"
condition:
    ($a0 and $a1)
}

rule blake2s_hashed_default_creds_warracorp
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for warracorp. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="208472508b6b56aad845ee6393d6afd784a3bef2951b1ed3406e810f36cf5e30"
    $a1="208472508b6b56aad845ee6393d6afd784a3bef2951b1ed3406e810f36cf5e30"
condition:
    ($a0 and $a1)
}

rule sha3_224_hashed_default_creds_warracorp
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for warracorp. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="0cf3b0f9237e10b42f97606d2bfe8b21b136f8205ae54cca3e12f581"
    $a1="0cf3b0f9237e10b42f97606d2bfe8b21b136f8205ae54cca3e12f581"
condition:
    ($a0 and $a1)
}

rule sha3_256_hashed_default_creds_warracorp
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for warracorp. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="17d6d9d78055897a483b8bf93a53a8392cb40aad78f636108bd5f1aa5993a667"
    $a1="17d6d9d78055897a483b8bf93a53a8392cb40aad78f636108bd5f1aa5993a667"
condition:
    ($a0 and $a1)
}

rule sha3_384_hashed_default_creds_warracorp
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for warracorp. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="880e8961beb1ef919ec0a96cf44c1b23556c899a8428aa46a26c765db36c488d6468d1776839e7857705198871018836"
    $a1="880e8961beb1ef919ec0a96cf44c1b23556c899a8428aa46a26c765db36c488d6468d1776839e7857705198871018836"
condition:
    ($a0 and $a1)
}

rule sha3_512_hashed_default_creds_warracorp
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for warracorp. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="839842bae789f42e3dba9f83709c02dc8c4f375e1ccb8bd5bd97c84ccda17c02e916d7a8d99f660a0cb78e6a338d1597e27ea07516ee1bf0cf412ea0c56fa41d"
    $a1="839842bae789f42e3dba9f83709c02dc8c4f375e1ccb8bd5bd97c84ccda17c02e916d7a8d99f660a0cb78e6a338d1597e27ea07516ee1bf0cf412ea0c56fa41d"
condition:
    ($a0 and $a1)
}

rule base64_hashed_default_creds_warracorp
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for warracorp. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="cGVwaW5v"
    $a1="cGVwaW5v"
condition:
    ($a0 and $a1)
}

