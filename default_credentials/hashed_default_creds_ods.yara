/*This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as long as you use it under this license.*/

rule md5_hashed_default_creds_ods
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for ods. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="ef1817547dffab0331a27d6733b49538"
    $a1="ef1817547dffab0331a27d6733b49538"
condition:
    ($a0 and $a1)
}

rule sha1_hashed_default_creds_ods
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for ods. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="86de42e9188ea20f00e068706a6f6c40ea22fec4"
    $a1="86de42e9188ea20f00e068706a6f6c40ea22fec4"
condition:
    ($a0 and $a1)
}

rule sha384_hashed_default_creds_ods
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for ods. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="30b5916dad58154ee7a056d6abe0e059c0f5fc2443ba9367ee5619a86c2cf2d450d16781f733e758ac9862fee208c835"
    $a1="30b5916dad58154ee7a056d6abe0e059c0f5fc2443ba9367ee5619a86c2cf2d450d16781f733e758ac9862fee208c835"
condition:
    ($a0 and $a1)
}

rule sha224_hashed_default_creds_ods
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for ods. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="155510e79e6b0637165ef3a3b90465a4a04f7e7c1237a9f68059e631"
    $a1="155510e79e6b0637165ef3a3b90465a4a04f7e7c1237a9f68059e631"
condition:
    ($a0 and $a1)
}

rule sha512_hashed_default_creds_ods
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for ods. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="e1f889cb47eac435713ad436f4d32c9efa44b4c98ba3cc952bf7acc4a3bb9be3fce18a1a8a2d59d29899c96d6038b1e293c3153c65ab561e967b18049ab65b2b"
    $a1="e1f889cb47eac435713ad436f4d32c9efa44b4c98ba3cc952bf7acc4a3bb9be3fce18a1a8a2d59d29899c96d6038b1e293c3153c65ab561e967b18049ab65b2b"
condition:
    ($a0 and $a1)
}

rule sha256_hashed_default_creds_ods
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for ods. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="96650eeb783b6ef504e6011c460f8bd9d64ff57c15d162cc5ad2be4f473059db"
    $a1="96650eeb783b6ef504e6011c460f8bd9d64ff57c15d162cc5ad2be4f473059db"
condition:
    ($a0 and $a1)
}

rule blake2b_hashed_default_creds_ods
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for ods. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="0beb24701b62b7f6cc14cafd06c56aa727b89892415fb14663d456e8c4dc02a0fc78fd8badf46a0950eddb392616044178ad63f9436c50f5145ef689547bf5f4"
    $a1="0beb24701b62b7f6cc14cafd06c56aa727b89892415fb14663d456e8c4dc02a0fc78fd8badf46a0950eddb392616044178ad63f9436c50f5145ef689547bf5f4"
condition:
    ($a0 and $a1)
}

rule blake2s_hashed_default_creds_ods
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for ods. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="d48e393b84f223bdd2157117f40a4156b3950a79c9ca8916f0a683cd2d16d203"
    $a1="d48e393b84f223bdd2157117f40a4156b3950a79c9ca8916f0a683cd2d16d203"
condition:
    ($a0 and $a1)
}

rule sha3_224_hashed_default_creds_ods
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for ods. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="b59f01d5cc9f7123513c720ec13f9ec2f41e899bc68a030ee880aa4b"
    $a1="b59f01d5cc9f7123513c720ec13f9ec2f41e899bc68a030ee880aa4b"
condition:
    ($a0 and $a1)
}

rule sha3_256_hashed_default_creds_ods
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for ods. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="9119c469783921fe3b564c0f3d4dd02e004d470e48a3b4bf3457fe2ec1ceaefe"
    $a1="9119c469783921fe3b564c0f3d4dd02e004d470e48a3b4bf3457fe2ec1ceaefe"
condition:
    ($a0 and $a1)
}

rule sha3_384_hashed_default_creds_ods
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for ods. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="ab3a37064c5a03d15eea29ebf71834a9abae7680763863b30e0f98f068d99276404f68f72bd6954b10e92bfd48f55ced"
    $a1="ab3a37064c5a03d15eea29ebf71834a9abae7680763863b30e0f98f068d99276404f68f72bd6954b10e92bfd48f55ced"
condition:
    ($a0 and $a1)
}

rule sha3_512_hashed_default_creds_ods
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for ods. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="52f485fd1daa838ce4220e8803a15c3dfefd90266dcf360b8219f481ef6e8c293067c35f97b15901240c264a6513070fb7a31241f8aaa2120ded3f9ecdf5ded3"
    $a1="52f485fd1daa838ce4220e8803a15c3dfefd90266dcf360b8219f481ef6e8c293067c35f97b15901240c264a6513070fb7a31241f8aaa2120ded3f9ecdf5ded3"
condition:
    ($a0 and $a1)
}

rule base64_hashed_default_creds_ods
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for ods. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="b2Rz"
    $a1="b2Rz"
condition:
    ($a0 and $a1)
}

