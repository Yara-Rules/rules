/*This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as long as you use it under this license.*/

rule md5_hashed_default_creds_carestream_health
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for carestream_health. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="6dff64efaf963fbf93dacefdf33986db"
    $a1="b2d8bb4924f59b71c06960e07bfca3fa"
    $a2="67795e98229f004a42d43d5ce62d007e"
    $a3="b2d8bb4924f59b71c06960e07bfca3fa"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule sha1_hashed_default_creds_carestream_health
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for carestream_health. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="f8517a59925f5202736d845f5e7fd9120f345faf"
    $a1="8eccb6cecfa119da06383342bac920ceb32f7032"
    $a2="1621c81b1c54f6b8e2fadf0bca3573747261baff"
    $a3="8eccb6cecfa119da06383342bac920ceb32f7032"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule sha384_hashed_default_creds_carestream_health
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for carestream_health. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="23f52cb8538a8014acef759c20e2d17368e306e7cb31e9107bb1fbe18c4ab7bec3016255382e3689c2ddd7aeb7041388"
    $a1="f361309582f8317b4bc33adcd743e00e8c11b5eb73ea4aa38f0f092f8d13337dae82de6d71e9e969045a234977e9d189"
    $a2="c045cd6c70f420905b9fe0edd0e7272fa776a2bfe6d23d4a93551208e819b29ef77f17b03f57d53b31f3309879148614"
    $a3="f361309582f8317b4bc33adcd743e00e8c11b5eb73ea4aa38f0f092f8d13337dae82de6d71e9e969045a234977e9d189"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule sha224_hashed_default_creds_carestream_health
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for carestream_health. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="7c85fdc099f0480fd1cf258c0ede273a9822f9978b7c2404a0890f6e"
    $a1="8d1118f1078da1becbff39f24585160bd8d1cf2d41326782f961f52a"
    $a2="81b29c67d513aa0767854fc82575b2b48f719e6cb5ddd4aa7aa86570"
    $a3="8d1118f1078da1becbff39f24585160bd8d1cf2d41326782f961f52a"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule sha512_hashed_default_creds_carestream_health
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for carestream_health. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="3cea291f4518daa07d514419645d833d3ee1aad28befd65cbb74bbee56585502722f0662676d6c5f69127c92ffa3de8991764902bdaceeae76b5958ca592320b"
    $a1="2ded69cac172a65f38e5045599ec77aab09f30505c6095860d3d0e2cfb7e5c2d60fde6f96f6ad2b0b675329dd8fd573b6cac2242a8cd783383c3668684368649"
    $a2="e48142a2ea8da9a97454aba4e985ba72e9effd2e26324b065619d700bf7303b423462e6c853197fdb99d8f91d1c253780dbccba99dc588346746c9265afc7cf7"
    $a3="2ded69cac172a65f38e5045599ec77aab09f30505c6095860d3d0e2cfb7e5c2d60fde6f96f6ad2b0b675329dd8fd573b6cac2242a8cd783383c3668684368649"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule sha256_hashed_default_creds_carestream_health
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for carestream_health. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="b4c51a6b12d78e48ea6cfe0702848b5d8e925985766fe7632a89993c09cf9f09"
    $a1="7a61d32b8ba90c5dd928e2a66d9ef5f686ebd1ff1cb7dd52f28c9da99e8fcceb"
    $a2="d140261e9173539cb2e60dbf1b594dfb9d05a09e925d6f54c0fe932c45be8dd2"
    $a3="7a61d32b8ba90c5dd928e2a66d9ef5f686ebd1ff1cb7dd52f28c9da99e8fcceb"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule blake2b_hashed_default_creds_carestream_health
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for carestream_health. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="9734ffc964bf0ea6b6c10084adfbd2daab9b26b4bcc102255561b413de7c204be389cb5b47c8fc08db62dc585b8b757125a2da131f22ec6e760f9de68bfaa85b"
    $a1="d9eb91de64469dd192d4c556a8b049ae688e112e2527624d7d8df3a5688631aeb0acb244aa2075569c9bbea6046dae668608d0d0591abd070d8d5c633dd8c152"
    $a2="815eb5f4b9764f53c18f2541bd4e4b737bcaa8f319e74487db065f9f1ae8c14f340ca9f83f947c31fc28ae7fd22342e069a8bc019b3b6648c5ea16beb10b4a78"
    $a3="d9eb91de64469dd192d4c556a8b049ae688e112e2527624d7d8df3a5688631aeb0acb244aa2075569c9bbea6046dae668608d0d0591abd070d8d5c633dd8c152"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule blake2s_hashed_default_creds_carestream_health
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for carestream_health. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="5cf8a38d67a9258564cf6df099ad8bb9b3699ef0ec57b1722d9bc819b48b2d66"
    $a1="1c62b7fa025a37e96e0e5a6897d7878b35b87fb57cdfac6a59c03707afccb311"
    $a2="35437b5e0da7d794d8acdd8fe7086bf559c45503bdab44cdc7a0261032323a2f"
    $a3="1c62b7fa025a37e96e0e5a6897d7878b35b87fb57cdfac6a59c03707afccb311"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule sha3_224_hashed_default_creds_carestream_health
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for carestream_health. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="c7c9c1dc66925f4627f485e9e07cbf970d0e8ee704cef2a58b593956"
    $a1="8fb01ff22b5cb74f8aa0f8beaddcabe9097ca4f33c42205221f9e37e"
    $a2="18b2bd676ec9184b2c3d3f6e7e72bbb34f5d3aa035aa5b4bb1691029"
    $a3="8fb01ff22b5cb74f8aa0f8beaddcabe9097ca4f33c42205221f9e37e"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule sha3_256_hashed_default_creds_carestream_health
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for carestream_health. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="ebf929bc2bd69ce7f96d91d8ac79fb4f242428c625dc499abc1b6630891876e4"
    $a1="9cc39ccfa55cb57330a585fafd33191d6899deaab66b126f84401cdd34d18814"
    $a2="ce031053646935c8d6025cba26e47389c1adc495811b7632f3b092f666c49a50"
    $a3="9cc39ccfa55cb57330a585fafd33191d6899deaab66b126f84401cdd34d18814"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule sha3_384_hashed_default_creds_carestream_health
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for carestream_health. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="7de6d3572939afe738e3a12af2157678d00834060887476eb84ce5805b47ff51c9c8dce8abcacaf0dee3722cce44274d"
    $a1="8736dc03fd6bcbb8a86d7a16ad795c208f1b482bfcc2a855b2fee12dee37531ed80891ea46bda836277e2cb220cec5e1"
    $a2="6179e192f720a8a2ec1f0a4fee2e9b7caf9c025334df38526bc320fa345ee8fa226fd5f0bee18a409a858c68e6634b36"
    $a3="8736dc03fd6bcbb8a86d7a16ad795c208f1b482bfcc2a855b2fee12dee37531ed80891ea46bda836277e2cb220cec5e1"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule sha3_512_hashed_default_creds_carestream_health
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for carestream_health. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="15a0ba31aa655fcc8d847b58402170934d96454a646aa67527b8c2c1a75791569507d1e6ade343e5513d34815ad411726aef691fac00fa8e5ed48c0b0395a371"
    $a1="b5886b2c57ad425f48ae63f8e3198f46a0700aa2c873d1ef287bd548ab3cbc13a91debc14476174c964335373296cf2cd1c7dd9953826cbfbfc29470bb7c7496"
    $a2="1afc6ee62646be541d4c94f4e60e6f6adb30658ff2b097999ffdb90c366a186fa35a2a5408278bb73379e7b76d48db3f515eb1e8734b1508f14da5ca7a14d7c5"
    $a3="b5886b2c57ad425f48ae63f8e3198f46a0700aa2c873d1ef287bd548ab3cbc13a91debc14476174c964335373296cf2cd1c7dd9953826cbfbfc29470bb7c7496"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule base64_hashed_default_creds_carestream_health
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for carestream_health. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="S2V5T3BlcmF0b3I="
    $a1="RFY1ODAw"
    $a2="TG9jYWxTZXJ2aWNl"
    $a3="RFY1ODAw"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

