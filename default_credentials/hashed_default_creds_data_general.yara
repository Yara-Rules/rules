/*This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as long as you use it under this license.*/

rule md5_hashed_default_creds_data_general
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for data_general. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="4b583376b2767b923c3e1da60d10de59"
    $a1="4b583376b2767b923c3e1da60d10de59"
    $a2="11d8c28a64490a987612f2332502467f"
    $a3="11d8c28a64490a987612f2332502467f"
    $a4="11d8c28a64490a987612f2332502467f"
    $a5="4b583376b2767b923c3e1da60d10de59"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}

rule sha1_hashed_default_creds_data_general
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for data_general. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="fe96dd39756ac41b74283a9292652d366d73931f"
    $a1="fe96dd39756ac41b74283a9292652d366d73931f"
    $a2="824f601c2a81ee6bab79ccd4792304c738d17630"
    $a3="824f601c2a81ee6bab79ccd4792304c738d17630"
    $a4="824f601c2a81ee6bab79ccd4792304c738d17630"
    $a5="fe96dd39756ac41b74283a9292652d366d73931f"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}

rule sha384_hashed_default_creds_data_general
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for data_general. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="22bd82ebe292d19f24ff56b1055ce899a27cd563698c8c8c0cb51e7920965370a5d6204f021546d40359f815a808c010"
    $a1="22bd82ebe292d19f24ff56b1055ce899a27cd563698c8c8c0cb51e7920965370a5d6204f021546d40359f815a808c010"
    $a2="02881c83829f230781da1515a61c5f0ef2783475b2ff7f5cf17f99b4c2df3993bb3182b176b68086da73b6231addc824"
    $a3="02881c83829f230781da1515a61c5f0ef2783475b2ff7f5cf17f99b4c2df3993bb3182b176b68086da73b6231addc824"
    $a4="02881c83829f230781da1515a61c5f0ef2783475b2ff7f5cf17f99b4c2df3993bb3182b176b68086da73b6231addc824"
    $a5="22bd82ebe292d19f24ff56b1055ce899a27cd563698c8c8c0cb51e7920965370a5d6204f021546d40359f815a808c010"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}

rule sha224_hashed_default_creds_data_general
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for data_general. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="f287cef4d4cd13b203a0d9e0d9be0b76532f55fb302aeda5e68a99f4"
    $a1="f287cef4d4cd13b203a0d9e0d9be0b76532f55fb302aeda5e68a99f4"
    $a2="a15a0e248f57af4cf585375f3c24fb3e790d5983f23993cbb97bfb83"
    $a3="a15a0e248f57af4cf585375f3c24fb3e790d5983f23993cbb97bfb83"
    $a4="a15a0e248f57af4cf585375f3c24fb3e790d5983f23993cbb97bfb83"
    $a5="f287cef4d4cd13b203a0d9e0d9be0b76532f55fb302aeda5e68a99f4"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}

rule sha512_hashed_default_creds_data_general
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for data_general. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="bc87235367eb9b67e1f5ffceb7a1e5506d2c3d92fc655b5b75b7b3892e7e7cdbc0f614147df2e89b44846f18f6d83c9246831b542b92ed5ad49cf1f6fbdcf73f"
    $a1="bc87235367eb9b67e1f5ffceb7a1e5506d2c3d92fc655b5b75b7b3892e7e7cdbc0f614147df2e89b44846f18f6d83c9246831b542b92ed5ad49cf1f6fbdcf73f"
    $a2="36eb6902784e66e624b831d25208b67ff26198fcc87d7484f51ccadcc50e3c27e9bd75aa2bfb983fc9978098c70dbb45e2db9fdb20005ad45f3a6c73e4c33298"
    $a3="36eb6902784e66e624b831d25208b67ff26198fcc87d7484f51ccadcc50e3c27e9bd75aa2bfb983fc9978098c70dbb45e2db9fdb20005ad45f3a6c73e4c33298"
    $a4="36eb6902784e66e624b831d25208b67ff26198fcc87d7484f51ccadcc50e3c27e9bd75aa2bfb983fc9978098c70dbb45e2db9fdb20005ad45f3a6c73e4c33298"
    $a5="bc87235367eb9b67e1f5ffceb7a1e5506d2c3d92fc655b5b75b7b3892e7e7cdbc0f614147df2e89b44846f18f6d83c9246831b542b92ed5ad49cf1f6fbdcf73f"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}

rule sha256_hashed_default_creds_data_general
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for data_general. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="06e55b633481f7bb072957eabcf110c972e86691c3cfedabe088024bffe42f23"
    $a1="06e55b633481f7bb072957eabcf110c972e86691c3cfedabe088024bffe42f23"
    $a2="037aeaeaf4bbf26ddabe7256a8294dc52da48d575a1247b5c2598c47de7aebab"
    $a3="037aeaeaf4bbf26ddabe7256a8294dc52da48d575a1247b5c2598c47de7aebab"
    $a4="037aeaeaf4bbf26ddabe7256a8294dc52da48d575a1247b5c2598c47de7aebab"
    $a5="06e55b633481f7bb072957eabcf110c972e86691c3cfedabe088024bffe42f23"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}

rule blake2b_hashed_default_creds_data_general
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for data_general. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="1645ae4b5b2eb6fbe61362cd6d7a1fc4862db293d0e6f24d62731e836b5c42c3c38a80a370036c992ef1b42c8b2dfb1ff7df21589826b40ff393301f51459776"
    $a1="1645ae4b5b2eb6fbe61362cd6d7a1fc4862db293d0e6f24d62731e836b5c42c3c38a80a370036c992ef1b42c8b2dfb1ff7df21589826b40ff393301f51459776"
    $a2="902034c9874f2c0db9a2911f76f7cab56a4bcc5c472d278213f8449ef14d7c8d6b8f640210d5bdced9af79de2f3e9c3f13ff51aaad616a9e08b2380b25c95539"
    $a3="902034c9874f2c0db9a2911f76f7cab56a4bcc5c472d278213f8449ef14d7c8d6b8f640210d5bdced9af79de2f3e9c3f13ff51aaad616a9e08b2380b25c95539"
    $a4="902034c9874f2c0db9a2911f76f7cab56a4bcc5c472d278213f8449ef14d7c8d6b8f640210d5bdced9af79de2f3e9c3f13ff51aaad616a9e08b2380b25c95539"
    $a5="1645ae4b5b2eb6fbe61362cd6d7a1fc4862db293d0e6f24d62731e836b5c42c3c38a80a370036c992ef1b42c8b2dfb1ff7df21589826b40ff393301f51459776"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}

rule blake2s_hashed_default_creds_data_general
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for data_general. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="f137411b263f529b8021a6fcc3cf7e9ff325fa0f80a189b555fadec8e6ca1953"
    $a1="f137411b263f529b8021a6fcc3cf7e9ff325fa0f80a189b555fadec8e6ca1953"
    $a2="9c5bd1b309db17692b3b62c291ebb49cf9836e2e2f901667bb8ad2584765be76"
    $a3="9c5bd1b309db17692b3b62c291ebb49cf9836e2e2f901667bb8ad2584765be76"
    $a4="9c5bd1b309db17692b3b62c291ebb49cf9836e2e2f901667bb8ad2584765be76"
    $a5="f137411b263f529b8021a6fcc3cf7e9ff325fa0f80a189b555fadec8e6ca1953"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}

rule sha3_224_hashed_default_creds_data_general
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for data_general. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="3c77a35671072d55f6995bac6450ea2ad943503143087eabcbc106b5"
    $a1="3c77a35671072d55f6995bac6450ea2ad943503143087eabcbc106b5"
    $a2="e616bc283a5c8eb1227ee4e01f2ad82fca197f6c1ba7e1bb77d51522"
    $a3="e616bc283a5c8eb1227ee4e01f2ad82fca197f6c1ba7e1bb77d51522"
    $a4="e616bc283a5c8eb1227ee4e01f2ad82fca197f6c1ba7e1bb77d51522"
    $a5="3c77a35671072d55f6995bac6450ea2ad943503143087eabcbc106b5"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}

rule sha3_256_hashed_default_creds_data_general
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for data_general. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="d238602e3435b266dbc0153b200e85e208a20a0bae71010a6324eb0497804eae"
    $a1="d238602e3435b266dbc0153b200e85e208a20a0bae71010a6324eb0497804eae"
    $a2="47cc398a83c553ffd38e80272ef38d2f8b72fffed1194327a4e41c9a7b2c16e9"
    $a3="47cc398a83c553ffd38e80272ef38d2f8b72fffed1194327a4e41c9a7b2c16e9"
    $a4="47cc398a83c553ffd38e80272ef38d2f8b72fffed1194327a4e41c9a7b2c16e9"
    $a5="d238602e3435b266dbc0153b200e85e208a20a0bae71010a6324eb0497804eae"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}

rule sha3_384_hashed_default_creds_data_general
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for data_general. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="d8d982b13ac9aad8cb3030b3a86aa41e6e673d3fabda25aaf4a1ab184b26ce597fcd7a1e896823d995f25ce18f188150"
    $a1="d8d982b13ac9aad8cb3030b3a86aa41e6e673d3fabda25aaf4a1ab184b26ce597fcd7a1e896823d995f25ce18f188150"
    $a2="104ad37e1d492c4e6562d8365c129085b493e15ec4146b8ed3c64627a10250d4ad1c5f8200450170da2bba0f0f756270"
    $a3="104ad37e1d492c4e6562d8365c129085b493e15ec4146b8ed3c64627a10250d4ad1c5f8200450170da2bba0f0f756270"
    $a4="104ad37e1d492c4e6562d8365c129085b493e15ec4146b8ed3c64627a10250d4ad1c5f8200450170da2bba0f0f756270"
    $a5="d8d982b13ac9aad8cb3030b3a86aa41e6e673d3fabda25aaf4a1ab184b26ce597fcd7a1e896823d995f25ce18f188150"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}

rule sha3_512_hashed_default_creds_data_general
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for data_general. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="eb65ed18f38a818be59cfc0c06cc812c1b46ead14d3059b3d0ea8fe388119ae93c30df5ceb94dfd0a2dba10e062066edf65951d4ab734c7f953f95e669d2a0f5"
    $a1="eb65ed18f38a818be59cfc0c06cc812c1b46ead14d3059b3d0ea8fe388119ae93c30df5ceb94dfd0a2dba10e062066edf65951d4ab734c7f953f95e669d2a0f5"
    $a2="eabfe45c57ddcb5cbb58d2a91eaa40a645d1e50026ffef32a5743bfafd8d73165ffd8f21fbf1d1dd147b39b10feb19bfc3ec7b4d54d1f54f8f8d6ad1475ec8bf"
    $a3="eabfe45c57ddcb5cbb58d2a91eaa40a645d1e50026ffef32a5743bfafd8d73165ffd8f21fbf1d1dd147b39b10feb19bfc3ec7b4d54d1f54f8f8d6ad1475ec8bf"
    $a4="eabfe45c57ddcb5cbb58d2a91eaa40a645d1e50026ffef32a5743bfafd8d73165ffd8f21fbf1d1dd147b39b10feb19bfc3ec7b4d54d1f54f8f8d6ad1475ec8bf"
    $a5="eb65ed18f38a818be59cfc0c06cc812c1b46ead14d3059b3d0ea8fe388119ae93c30df5ceb94dfd0a2dba10e062066edf65951d4ab734c7f953f95e669d2a0f5"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}

rule base64_hashed_default_creds_data_general
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for data_general. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="b3BlcmF0b3I="
    $a1="b3BlcmF0b3I="
    $a2="b3A="
    $a3="b3A="
    $a4="b3A="
    $a5="b3BlcmF0b3I="
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}

