/*This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as long as you use it under this license.*/

rule md5_hashed_default_creds_tert
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for tert. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="b4cc344d25a2efe540adbf2678e2304c"
    $a1="b4cc344d25a2efe540adbf2678e2304c"
condition:
    ($a0 and $a1)
}

rule sha1_hashed_default_creds_tert
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for tert. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="474ba67bdb289c6263b36dfd8a7bed6c85b04943"
    $a1="474ba67bdb289c6263b36dfd8a7bed6c85b04943"
condition:
    ($a0 and $a1)
}

rule sha384_hashed_default_creds_tert
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for tert. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="dc4e750d0525009efdc9e0f4af26ae723a597f8ed353712f800c66cc8a1c9fc97cf75ed14dfab17f61098ed6153bc5ae"
    $a1="dc4e750d0525009efdc9e0f4af26ae723a597f8ed353712f800c66cc8a1c9fc97cf75ed14dfab17f61098ed6153bc5ae"
condition:
    ($a0 and $a1)
}

rule sha224_hashed_default_creds_tert
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for tert. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="6938dc9409850a18399fff08d3c01fa25aec807541d25b3b826b16c9"
    $a1="6938dc9409850a18399fff08d3c01fa25aec807541d25b3b826b16c9"
condition:
    ($a0 and $a1)
}

rule sha512_hashed_default_creds_tert
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for tert. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="625f7fdb99de7de358ab119ead94c29b436764e1bffb3af4f1ca715b692cf155e62007572ce4101fef09a98130369de7a06ccd57903b4c5a9104d1444a02f4a2"
    $a1="625f7fdb99de7de358ab119ead94c29b436764e1bffb3af4f1ca715b692cf155e62007572ce4101fef09a98130369de7a06ccd57903b4c5a9104d1444a02f4a2"
condition:
    ($a0 and $a1)
}

rule sha256_hashed_default_creds_tert
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for tert. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="119c9ae6f9ca741bd0a76f87fba0b22cab5413187afb2906aa2875c38e213603"
    $a1="119c9ae6f9ca741bd0a76f87fba0b22cab5413187afb2906aa2875c38e213603"
condition:
    ($a0 and $a1)
}

rule blake2b_hashed_default_creds_tert
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for tert. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="11f84c78d500a6c208a0360ed639feca07de49affe51ebe659ade560788f1b312399f55230c90a718f7072985d4e6adb934ec835a431a10a776ebcbc437f59a6"
    $a1="11f84c78d500a6c208a0360ed639feca07de49affe51ebe659ade560788f1b312399f55230c90a718f7072985d4e6adb934ec835a431a10a776ebcbc437f59a6"
condition:
    ($a0 and $a1)
}

rule blake2s_hashed_default_creds_tert
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for tert. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="5c3e17158535a9b5b4b4dbb0c4ffbd9085ec3513ff7d1cf8454ddad70d3a72e5"
    $a1="5c3e17158535a9b5b4b4dbb0c4ffbd9085ec3513ff7d1cf8454ddad70d3a72e5"
condition:
    ($a0 and $a1)
}

rule sha3_224_hashed_default_creds_tert
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for tert. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="c08c456cda7d5743cb89daf81d5a58b846fa0067a11635ec010602a7"
    $a1="c08c456cda7d5743cb89daf81d5a58b846fa0067a11635ec010602a7"
condition:
    ($a0 and $a1)
}

rule sha3_256_hashed_default_creds_tert
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for tert. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="0bcf781af72ceec4b7721e3d698f271bb7e74ddb71c9092520ff939b70029198"
    $a1="0bcf781af72ceec4b7721e3d698f271bb7e74ddb71c9092520ff939b70029198"
condition:
    ($a0 and $a1)
}

rule sha3_384_hashed_default_creds_tert
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for tert. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="24517746773eb352524f1250fa025cebeaa2baa050e81550b40220e48497e7448315d454ae790f23ea217bb1a74083f8"
    $a1="24517746773eb352524f1250fa025cebeaa2baa050e81550b40220e48497e7448315d454ae790f23ea217bb1a74083f8"
condition:
    ($a0 and $a1)
}

rule sha3_512_hashed_default_creds_tert
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for tert. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="c22e1905fbc76858f0fe0ea293ca8a146c0b609ced05cd308eb4d4b8272e37324a8b98d0a91dcc18ce596e4e9ef7320971756a93a4cedc5c0a5c92345f2bba68"
    $a1="c22e1905fbc76858f0fe0ea293ca8a146c0b609ced05cd308eb4d4b8272e37324a8b98d0a91dcc18ce596e4e9ef7320971756a93a4cedc5c0a5c92345f2bba68"
condition:
    ($a0 and $a1)
}

rule base64_hashed_default_creds_tert
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for tert. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="amFtZXM="
    $a1="amFtZXM="
condition:
    ($a0 and $a1)
}

