/*This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as long as you use it under this license.*/

rule md5_hashed_default_creds_system_32
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for system_32. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="19ad89bc3e3c9d7ef68b89523eff1987"
    $a1="5ebe2294ecd0e0f08eab7690d2a6ee69"
condition:
    ($a0 and $a1)
}

rule sha1_hashed_default_creds_system_32
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for system_32. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="89fb511ffe93ee7826661ca1e3bb468dc1ad0ff2"
    $a1="e5e9fa1ba31ecd1ae84f75caaa474f3a663f05f4"
condition:
    ($a0 and $a1)
}

rule sha384_hashed_default_creds_system_32
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for system_32. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="2e2fddef7ad9bd5cf3c941a536b0ccc4162a836d64d3e2d9aa3f155912de790677f40b950d95f1db55dfc623f0503762"
    $a1="58a775ba4112be3005ae4407ce757d88fda71d40497bb8026ecac54d4e3ffc7232ce8de3ab5acb30ae39760fee7c53ed"
condition:
    ($a0 and $a1)
}

rule sha224_hashed_default_creds_system_32
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for system_32. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="e183e77efe617016cee5bfcb2b093efa10cac183dbe53b6198729de6"
    $a1="95c7fbca92ac5083afda62a564a3d014fc3b72c9140e3cb99ea6bf12"
condition:
    ($a0 and $a1)
}

rule sha512_hashed_default_creds_system_32
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for system_32. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="d658b336773d4c1e42dea5de35aac125621ee8c5691c11b42ea32aad8cd6256beceabf1d067947090497979ef2b4d1ab968be9167aab14b6441ac835c537c0e2"
    $a1="bd2b1aaf7ef4f09be9f52ce2d8d599674d81aa9d6a4421696dc4d93dd0619d682ce56b4d64a9ef097761ced99e0f67265b5f76085e5b0ee7ca4696b2ad6fe2b2"
condition:
    ($a0 and $a1)
}

rule sha256_hashed_default_creds_system_32
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for system_32. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="1e142e6277b12b7e1110478a24caee8f006a9349e86970c890203d6266209463"
    $a1="2bb80d537b1da3e38bd30361aa855686bde0eacd7162fef6a25fe97bf527a25b"
condition:
    ($a0 and $a1)
}

rule blake2b_hashed_default_creds_system_32
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for system_32. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="3efd1cf82c6a962a2ec5db6a85a61fcfd90538e4eaadf019067281dcd03e21ce6af897f84a5233bf44a7f79d7c4bf0134715c691c6eeac87fb55ba22fdfbbadb"
    $a1="5fb6a5dd1b937f0c8a3ffc1cdb35edda4a41b2ca72b94e3d2c99c080aed86526aefcdc1e312cdd144d50b0bcd4a402051acd3373f90a96df6e13d9a0a9948993"
condition:
    ($a0 and $a1)
}

rule blake2s_hashed_default_creds_system_32
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for system_32. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="83429da7b305984c64cbf2dc563d752d4a79717f286e679afc9b2daea14ef86b"
    $a1="66e754709229a1a76f12b770d612d4dba1d51e28894e2dce1b53ca15104f84c0"
condition:
    ($a0 and $a1)
}

rule sha3_224_hashed_default_creds_system_32
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for system_32. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="af537e3fe10bce58cff5834fe36a35fba380497f0065f36aa6b7061e"
    $a1="9817fd4e8ae39d6e41532989e4422c5a7e46411dab4d2fdfa2270dad"
condition:
    ($a0 and $a1)
}

rule sha3_256_hashed_default_creds_system_32
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for system_32. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="865800f9b7760c25f543722e0f21ecf224da3567f0ab921f04449135f30e5375"
    $a1="f5a5207a8729b1f709cb710311751eb2fc8acad5a1fb8ac991b736e69b6529a3"
condition:
    ($a0 and $a1)
}

rule sha3_384_hashed_default_creds_system_32
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for system_32. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="455110feb9390dfb134779ee606f68e8b2210bdea5bdc885e4181e7afc7ee72f5cc05e83009d95bbc76318ecfec979b1"
    $a1="5222ddb86d6061d2c0ef2bbc607271ff6f355d4283fd54267766b88ee186ca93ab0e421f3142755d56f76ee87889cb8c"
condition:
    ($a0 and $a1)
}

rule sha3_512_hashed_default_creds_system_32
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for system_32. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="c120e450fdc7ed75ffc85ef2058e7fdf19238d36879ca8704043ce1d356e9df3700ef2ca99cfa258274b181b2f0b10e9cd94ce28305b06dda78f19990d1db043"
    $a1="b778a39a3663719dfc5e48c9d78431b1e45c2af9df538782bf199c189dabeac7680ada57dcec8eee91c4e3bf3bfa9af6ffde90cd1d249d1c6121d7b759a001b1"
condition:
    ($a0 and $a1)
}

rule base64_hashed_default_creds_system_32
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for system_32. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="aW5zdGFsbA=="
    $a1="c2VjcmV0"
condition:
    ($a0 and $a1)
}

