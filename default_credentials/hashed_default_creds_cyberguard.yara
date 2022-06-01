/*This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as long as you use it under this license.*/

rule md5_hashed_default_creds_cyberguard
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for cyberguard. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="ee39dd49b6477fd99d9f356dcba3ad12"
    $a1="ee39dd49b6477fd99d9f356dcba3ad12"
condition:
    ($a0 and $a1)
}

rule sha1_hashed_default_creds_cyberguard
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for cyberguard. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="fb697ebda3a3b555e0e28f9801624b2dcc25f4f6"
    $a1="fb697ebda3a3b555e0e28f9801624b2dcc25f4f6"
condition:
    ($a0 and $a1)
}

rule sha384_hashed_default_creds_cyberguard
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for cyberguard. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="791dc4ce6a74829f9d76b2675e04c10b2fee20a60d2ac4ee302fc410107cc36f4690a39dd05b15a42c7f9b0b84ea720d"
    $a1="791dc4ce6a74829f9d76b2675e04c10b2fee20a60d2ac4ee302fc410107cc36f4690a39dd05b15a42c7f9b0b84ea720d"
condition:
    ($a0 and $a1)
}

rule sha224_hashed_default_creds_cyberguard
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for cyberguard. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="00a907bed6ab2911537c2d24eb3cab299679a29b4cbcb25757adfb90"
    $a1="00a907bed6ab2911537c2d24eb3cab299679a29b4cbcb25757adfb90"
condition:
    ($a0 and $a1)
}

rule sha512_hashed_default_creds_cyberguard
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for cyberguard. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="4af4b2778016485290c3a133986c08e30b2cd96ef70bc68a4add3c804fb58f652663c5ca863f03fb1d11c644b9a81a1c0bf998ff40702bbfd6c48c4e49380434"
    $a1="4af4b2778016485290c3a133986c08e30b2cd96ef70bc68a4add3c804fb58f652663c5ca863f03fb1d11c644b9a81a1c0bf998ff40702bbfd6c48c4e49380434"
condition:
    ($a0 and $a1)
}

rule sha256_hashed_default_creds_cyberguard
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for cyberguard. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="9d13f712ce4df1ed57a45273c72b40466e9006a6a2092c7eed7f8c76ce586502"
    $a1="9d13f712ce4df1ed57a45273c72b40466e9006a6a2092c7eed7f8c76ce586502"
condition:
    ($a0 and $a1)
}

rule blake2b_hashed_default_creds_cyberguard
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for cyberguard. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="ccf3cd03e24af503eaa93c3cc00fb3fdddc663b5d3f31aeb74541a36f59881d067e84c9662ad6fcaceb8d954d87709f923a1108f71fcca030c16d4a2b8cd3415"
    $a1="ccf3cd03e24af503eaa93c3cc00fb3fdddc663b5d3f31aeb74541a36f59881d067e84c9662ad6fcaceb8d954d87709f923a1108f71fcca030c16d4a2b8cd3415"
condition:
    ($a0 and $a1)
}

rule blake2s_hashed_default_creds_cyberguard
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for cyberguard. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="3c1897f0651666ab1d2fe4bdf089f76ff072d748fd1c401c0d8291643e7b6bba"
    $a1="3c1897f0651666ab1d2fe4bdf089f76ff072d748fd1c401c0d8291643e7b6bba"
condition:
    ($a0 and $a1)
}

rule sha3_224_hashed_default_creds_cyberguard
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for cyberguard. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="6ef25d492b513ea0bf97ab6a1ab1d72b6ecc938fe9874b8c498f112e"
    $a1="6ef25d492b513ea0bf97ab6a1ab1d72b6ecc938fe9874b8c498f112e"
condition:
    ($a0 and $a1)
}

rule sha3_256_hashed_default_creds_cyberguard
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for cyberguard. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="d5e45898eda7cc4ee72bd501fae366cd68d0a6761c9a505fc9efc5634abfbff6"
    $a1="d5e45898eda7cc4ee72bd501fae366cd68d0a6761c9a505fc9efc5634abfbff6"
condition:
    ($a0 and $a1)
}

rule sha3_384_hashed_default_creds_cyberguard
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for cyberguard. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="3852a045d1e81718f011eb6514c88348c07ce1acbd3e42c4dd7e9c1dfe1277b7db8ce12118ceca2174a4587bd097ebef"
    $a1="3852a045d1e81718f011eb6514c88348c07ce1acbd3e42c4dd7e9c1dfe1277b7db8ce12118ceca2174a4587bd097ebef"
condition:
    ($a0 and $a1)
}

rule sha3_512_hashed_default_creds_cyberguard
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for cyberguard. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="0b180290c6f9e27fad41aa16333dce831e0f191e265d2523a5d40327fea05e72e45f3f042b82acf0c54b8ce530465cc94cf6e323a24046b03a28fd25053fa356"
    $a1="0b180290c6f9e27fad41aa16333dce831e0f191e265d2523a5d40327fea05e72e45f3f042b82acf0c54b8ce530465cc94cf6e323a24046b03a28fd25053fa356"
condition:
    ($a0 and $a1)
}

rule base64_hashed_default_creds_cyberguard
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for cyberguard. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="Y2dhZG1pbg=="
    $a1="Y2dhZG1pbg=="
condition:
    ($a0 and $a1)
}

