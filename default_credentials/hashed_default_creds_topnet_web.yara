/*This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as long as you use it under this license.*/

rule md5_hashed_default_creds_topnet_web
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for topnet_web. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="9205cc0e701acd8d6934c1f3c0d0dce6"
    $a1="9205cc0e701acd8d6934c1f3c0d0dce6"
condition:
    ($a0 and $a1)
}

rule sha1_hashed_default_creds_topnet_web
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for topnet_web. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="71a4cf7b2d419359238da66116d3f94d15679586"
    $a1="71a4cf7b2d419359238da66116d3f94d15679586"
condition:
    ($a0 and $a1)
}

rule sha384_hashed_default_creds_topnet_web
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for topnet_web. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="193b2c46210c4b2f5c97eb8a54f9b6ee5766c0c86a960e2d3ddf34a732da69b51f1e59e9c3e3584df1a90e9357d14014"
    $a1="193b2c46210c4b2f5c97eb8a54f9b6ee5766c0c86a960e2d3ddf34a732da69b51f1e59e9c3e3584df1a90e9357d14014"
condition:
    ($a0 and $a1)
}

rule sha224_hashed_default_creds_topnet_web
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for topnet_web. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="5c8c2e41babb381c99042fb932fd8de90ca83d6db8c8b2d3657f3ef2"
    $a1="5c8c2e41babb381c99042fb932fd8de90ca83d6db8c8b2d3657f3ef2"
condition:
    ($a0 and $a1)
}

rule sha512_hashed_default_creds_topnet_web
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for topnet_web. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="67df429921ac339e71aeae3b5278b725fdf191f20b4e79f631549803faa05f557c112e5dfc61995e7ac20fe39687b02bb9105298b91fa8a82303f87fb50c4fe9"
    $a1="67df429921ac339e71aeae3b5278b725fdf191f20b4e79f631549803faa05f557c112e5dfc61995e7ac20fe39687b02bb9105298b91fa8a82303f87fb50c4fe9"
condition:
    ($a0 and $a1)
}

rule sha256_hashed_default_creds_topnet_web
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for topnet_web. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="99351f88dd917f353be0e11ad19409d647c30c6b3cc2d4075e2127e011b4a3b0"
    $a1="99351f88dd917f353be0e11ad19409d647c30c6b3cc2d4075e2127e011b4a3b0"
condition:
    ($a0 and $a1)
}

rule blake2b_hashed_default_creds_topnet_web
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for topnet_web. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="131dccea634c42c5c371f024f112af7b9f687384ddfd6a7c48e995fae207f9eb4781d6b987df3ed481fd3cbffddf8c8e7d8f3095077cbfcba470083821014046"
    $a1="131dccea634c42c5c371f024f112af7b9f687384ddfd6a7c48e995fae207f9eb4781d6b987df3ed481fd3cbffddf8c8e7d8f3095077cbfcba470083821014046"
condition:
    ($a0 and $a1)
}

rule blake2s_hashed_default_creds_topnet_web
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for topnet_web. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="68a5d0346f0f4b06ff6db7eeba6092049e4f8d5b58dd4d444c4aa9d2fdac733a"
    $a1="68a5d0346f0f4b06ff6db7eeba6092049e4f8d5b58dd4d444c4aa9d2fdac733a"
condition:
    ($a0 and $a1)
}

rule sha3_224_hashed_default_creds_topnet_web
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for topnet_web. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="83419e289fb74bd02547f5f0dbf0acc554967be5a4e9e42cd4ebf9b1"
    $a1="83419e289fb74bd02547f5f0dbf0acc554967be5a4e9e42cd4ebf9b1"
condition:
    ($a0 and $a1)
}

rule sha3_256_hashed_default_creds_topnet_web
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for topnet_web. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="915e23ffde9980f2b7ac38bbdcc40dacf01de5fedbd9744324873b22e1b38dc6"
    $a1="915e23ffde9980f2b7ac38bbdcc40dacf01de5fedbd9744324873b22e1b38dc6"
condition:
    ($a0 and $a1)
}

rule sha3_384_hashed_default_creds_topnet_web
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for topnet_web. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="27681473ca9f5a75fb7ee8d50bbbcdc38650bb5133641d9fb50f864faaa2949144144a5dbb817bf7c0b92f7eb4996744"
    $a1="27681473ca9f5a75fb7ee8d50bbbcdc38650bb5133641d9fb50f864faaa2949144144a5dbb817bf7c0b92f7eb4996744"
condition:
    ($a0 and $a1)
}

rule sha3_512_hashed_default_creds_topnet_web
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for topnet_web. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="70ff103a2896a268b929142685f7aff5e30c064ded1519f9d05ddbace488e3d8659f0a9ec917b478f1871f768e7d55685cddecec29d50da14f3793f59b3cee08"
    $a1="70ff103a2896a268b929142685f7aff5e30c064ded1519f9d05ddbace488e3d8659f0a9ec917b478f1871f768e7d55685cddecec29d50da14f3793f59b3cee08"
condition:
    ($a0 and $a1)
}

rule base64_hashed_default_creds_topnet_web
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for topnet_web. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="dG9wYWRtaW4="
    $a1="dG9wYWRtaW4="
condition:
    ($a0 and $a1)
}

