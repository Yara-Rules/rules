/*This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as long as you use it under this license.*/

rule md5_hashed_default_creds_andover_controls
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for andover_controls. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="1673448ee7064c989d02579c534f6b66"
    $a1="1673448ee7064c989d02579c534f6b66"
condition:
    ($a0 and $a1)
}

rule sha1_hashed_default_creds_andover_controls
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for andover_controls. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="5e942a2261672f81ad3519b878a9265eb44fdeba"
    $a1="5e942a2261672f81ad3519b878a9265eb44fdeba"
condition:
    ($a0 and $a1)
}

rule sha384_hashed_default_creds_andover_controls
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for andover_controls. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="97fd73987136fc80b8984660725d4fa12c25d6ccd071fa888eaa6e41a77b397c48d77555a642cdf71b6e4f1f549c96f0"
    $a1="97fd73987136fc80b8984660725d4fa12c25d6ccd071fa888eaa6e41a77b397c48d77555a642cdf71b6e4f1f549c96f0"
condition:
    ($a0 and $a1)
}

rule sha224_hashed_default_creds_andover_controls
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for andover_controls. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="54308b1092557ded034750909b7736cc6784e146156ef8981329bbab"
    $a1="54308b1092557ded034750909b7736cc6784e146156ef8981329bbab"
condition:
    ($a0 and $a1)
}

rule sha512_hashed_default_creds_andover_controls
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for andover_controls. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="653c12e21fbda7116eb0373d0c185c3cd1873bdeddac6813f84d3e6d7b9370f825a35ec97d99925e4525828570e0a62a94e639109e8a23b55f397565bb068878"
    $a1="653c12e21fbda7116eb0373d0c185c3cd1873bdeddac6813f84d3e6d7b9370f825a35ec97d99925e4525828570e0a62a94e639109e8a23b55f397565bb068878"
condition:
    ($a0 and $a1)
}

rule sha256_hashed_default_creds_andover_controls
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for andover_controls. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="414322309db5c06d090a2e922ccc3e00708c993b9b96405de127b7fd8da2dd21"
    $a1="414322309db5c06d090a2e922ccc3e00708c993b9b96405de127b7fd8da2dd21"
condition:
    ($a0 and $a1)
}

rule blake2b_hashed_default_creds_andover_controls
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for andover_controls. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="5210a3baf71239ceb36cb753f693c9257c34ae9bf1daf93ab4ff29a770725a1fb69d5ddf7e792076db1d2b0cf4f002fc3314d7d5711c671fa58114e361ff5e96"
    $a1="5210a3baf71239ceb36cb753f693c9257c34ae9bf1daf93ab4ff29a770725a1fb69d5ddf7e792076db1d2b0cf4f002fc3314d7d5711c671fa58114e361ff5e96"
condition:
    ($a0 and $a1)
}

rule blake2s_hashed_default_creds_andover_controls
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for andover_controls. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="723c2dd12aab4a510924e50f1ec63d4de287ca94798598d92dd88c649de3023d"
    $a1="723c2dd12aab4a510924e50f1ec63d4de287ca94798598d92dd88c649de3023d"
condition:
    ($a0 and $a1)
}

rule sha3_224_hashed_default_creds_andover_controls
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for andover_controls. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="0fcd24791c977c94bbb263ff548cb08b4d6689bc839ea03c005aac4d"
    $a1="0fcd24791c977c94bbb263ff548cb08b4d6689bc839ea03c005aac4d"
condition:
    ($a0 and $a1)
}

rule sha3_256_hashed_default_creds_andover_controls
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for andover_controls. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="70848d95a6a227c06655ca3acf2dc0883983f0af894b321838466ddbf871c054"
    $a1="70848d95a6a227c06655ca3acf2dc0883983f0af894b321838466ddbf871c054"
condition:
    ($a0 and $a1)
}

rule sha3_384_hashed_default_creds_andover_controls
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for andover_controls. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="227f41d812305a1e02c2991c283019bab3a5283c489a2b8d26becbcf81c7b33d3856a3816bf8ba2e9a9c1e4156fe5fd2"
    $a1="227f41d812305a1e02c2991c283019bab3a5283c489a2b8d26becbcf81c7b33d3856a3816bf8ba2e9a9c1e4156fe5fd2"
condition:
    ($a0 and $a1)
}

rule sha3_512_hashed_default_creds_andover_controls
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for andover_controls. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="59913bcd65ed47fd2d61230418be7e92b0574e52ab186055ea99ffe68d39dc0b449fc12e627f34550770b0f748ee6e32cc420cd0005f7597a7d94d5404f74f06"
    $a1="59913bcd65ed47fd2d61230418be7e92b0574e52ab186055ea99ffe68d39dc0b449fc12e627f34550770b0f748ee6e32cc420cd0005f7597a7d94d5404f74f06"
condition:
    ($a0 and $a1)
}

rule base64_hashed_default_creds_andover_controls
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for andover_controls. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="YWNj"
    $a1="YWNj"
condition:
    ($a0 and $a1)
}

