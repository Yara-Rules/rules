/*This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as long as you use it under this license.*/

rule md5_hashed_default_creds_open_xchange_inc
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for open_xchange_inc. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="db77e4a763ec5b10bd818a3917fcc7bd"
    $a1="5ebe2294ecd0e0f08eab7690d2a6ee69"
condition:
    ($a0 and $a1)
}

rule sha1_hashed_default_creds_open_xchange_inc
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for open_xchange_inc. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="d7efbd2410ebe6df9d8449f5222cc49d69a58526"
    $a1="e5e9fa1ba31ecd1ae84f75caaa474f3a663f05f4"
condition:
    ($a0 and $a1)
}

rule sha384_hashed_default_creds_open_xchange_inc
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for open_xchange_inc. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="c36baa62607cd0f4bace35754ae89ed0790fa9132a89d87e67411febe43cf15caec6ea592b336afddd66fb3d52c59dd8"
    $a1="58a775ba4112be3005ae4407ce757d88fda71d40497bb8026ecac54d4e3ffc7232ce8de3ab5acb30ae39760fee7c53ed"
condition:
    ($a0 and $a1)
}

rule sha224_hashed_default_creds_open_xchange_inc
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for open_xchange_inc. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="dbf00387b40fd586561426359761bfb259be5ec3b98c683163ce86f9"
    $a1="95c7fbca92ac5083afda62a564a3d014fc3b72c9140e3cb99ea6bf12"
condition:
    ($a0 and $a1)
}

rule sha512_hashed_default_creds_open_xchange_inc
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for open_xchange_inc. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="6c19b3a7bdbb251e066660e1f0ba8077dfb25327e9dc0da10abb09402fc4663b122a2d7a6ec3c4a45a82331a1dc538a65ba5ba8540e7761ae07c85242835586c"
    $a1="bd2b1aaf7ef4f09be9f52ce2d8d599674d81aa9d6a4421696dc4d93dd0619d682ce56b4d64a9ef097761ced99e0f67265b5f76085e5b0ee7ca4696b2ad6fe2b2"
condition:
    ($a0 and $a1)
}

rule sha256_hashed_default_creds_open_xchange_inc
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for open_xchange_inc. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="bb96087835b2a082a33b6d7ee3ae240d07f8de033aaab3248dc0ff99705b042c"
    $a1="2bb80d537b1da3e38bd30361aa855686bde0eacd7162fef6a25fe97bf527a25b"
condition:
    ($a0 and $a1)
}

rule blake2b_hashed_default_creds_open_xchange_inc
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for open_xchange_inc. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="39abfeb0ef70ece46520df890afa2608246a4979dd277760e8cb3edd13c95224248e09e86e75c00cb073263c6a944bf0c49848c4ea9db9e178bc9d8dd2362c81"
    $a1="5fb6a5dd1b937f0c8a3ffc1cdb35edda4a41b2ca72b94e3d2c99c080aed86526aefcdc1e312cdd144d50b0bcd4a402051acd3373f90a96df6e13d9a0a9948993"
condition:
    ($a0 and $a1)
}

rule blake2s_hashed_default_creds_open_xchange_inc
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for open_xchange_inc. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="c9baf4238b775e7a778299593072754ca70f26b26becc007553253323d2edd92"
    $a1="66e754709229a1a76f12b770d612d4dba1d51e28894e2dce1b53ca15104f84c0"
condition:
    ($a0 and $a1)
}

rule sha3_224_hashed_default_creds_open_xchange_inc
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for open_xchange_inc. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="f975d3a3780115c7fd6353e66abb77a17da423ff28d46c2297a5a8d0"
    $a1="9817fd4e8ae39d6e41532989e4422c5a7e46411dab4d2fdfa2270dad"
condition:
    ($a0 and $a1)
}

rule sha3_256_hashed_default_creds_open_xchange_inc
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for open_xchange_inc. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="9596bc2c008337d5197d074fbf8d1d67f521baab8b638dd5d660220d86ab21df"
    $a1="f5a5207a8729b1f709cb710311751eb2fc8acad5a1fb8ac991b736e69b6529a3"
condition:
    ($a0 and $a1)
}

rule sha3_384_hashed_default_creds_open_xchange_inc
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for open_xchange_inc. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="e34ae819caca9487a6092ff046cd54c1eb14989ac529ef23c3489c5e5045a9d14457bf831839430537d8dd7d86a9eaf8"
    $a1="5222ddb86d6061d2c0ef2bbc607271ff6f355d4283fd54267766b88ee186ca93ab0e421f3142755d56f76ee87889cb8c"
condition:
    ($a0 and $a1)
}

rule sha3_512_hashed_default_creds_open_xchange_inc
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for open_xchange_inc. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="d5615815201ef429850e66f914747c19ad1488bae0142a7787f52e9f05df4610fa482becaeb5fd01377dec95c0eb3fb230e50f8a0f3629d8bd812465f810562a"
    $a1="b778a39a3663719dfc5e48c9d78431b1e45c2af9df538782bf199c189dabeac7680ada57dcec8eee91c4e3bf3bfa9af6ffde90cd1d249d1c6121d7b759a001b1"
condition:
    ($a0 and $a1)
}

rule base64_hashed_default_creds_open_xchange_inc
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for open_xchange_inc. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="bWFpbGFkbWlu"
    $a1="c2VjcmV0"
condition:
    ($a0 and $a1)
}

