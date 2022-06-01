/*This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as long as you use it under this license.*/

rule md5_hashed_default_creds_ge_security_inc
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for ge_security_inc. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="19ad89bc3e3c9d7ef68b89523eff1987"
    $a1="19ad89bc3e3c9d7ef68b89523eff1987"
condition:
    ($a0 and $a1)
}

rule sha1_hashed_default_creds_ge_security_inc
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for ge_security_inc. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="89fb511ffe93ee7826661ca1e3bb468dc1ad0ff2"
    $a1="89fb511ffe93ee7826661ca1e3bb468dc1ad0ff2"
condition:
    ($a0 and $a1)
}

rule sha384_hashed_default_creds_ge_security_inc
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for ge_security_inc. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="2e2fddef7ad9bd5cf3c941a536b0ccc4162a836d64d3e2d9aa3f155912de790677f40b950d95f1db55dfc623f0503762"
    $a1="2e2fddef7ad9bd5cf3c941a536b0ccc4162a836d64d3e2d9aa3f155912de790677f40b950d95f1db55dfc623f0503762"
condition:
    ($a0 and $a1)
}

rule sha224_hashed_default_creds_ge_security_inc
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for ge_security_inc. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="e183e77efe617016cee5bfcb2b093efa10cac183dbe53b6198729de6"
    $a1="e183e77efe617016cee5bfcb2b093efa10cac183dbe53b6198729de6"
condition:
    ($a0 and $a1)
}

rule sha512_hashed_default_creds_ge_security_inc
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for ge_security_inc. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="d658b336773d4c1e42dea5de35aac125621ee8c5691c11b42ea32aad8cd6256beceabf1d067947090497979ef2b4d1ab968be9167aab14b6441ac835c537c0e2"
    $a1="d658b336773d4c1e42dea5de35aac125621ee8c5691c11b42ea32aad8cd6256beceabf1d067947090497979ef2b4d1ab968be9167aab14b6441ac835c537c0e2"
condition:
    ($a0 and $a1)
}

rule sha256_hashed_default_creds_ge_security_inc
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for ge_security_inc. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="1e142e6277b12b7e1110478a24caee8f006a9349e86970c890203d6266209463"
    $a1="1e142e6277b12b7e1110478a24caee8f006a9349e86970c890203d6266209463"
condition:
    ($a0 and $a1)
}

rule blake2b_hashed_default_creds_ge_security_inc
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for ge_security_inc. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="3efd1cf82c6a962a2ec5db6a85a61fcfd90538e4eaadf019067281dcd03e21ce6af897f84a5233bf44a7f79d7c4bf0134715c691c6eeac87fb55ba22fdfbbadb"
    $a1="3efd1cf82c6a962a2ec5db6a85a61fcfd90538e4eaadf019067281dcd03e21ce6af897f84a5233bf44a7f79d7c4bf0134715c691c6eeac87fb55ba22fdfbbadb"
condition:
    ($a0 and $a1)
}

rule blake2s_hashed_default_creds_ge_security_inc
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for ge_security_inc. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="83429da7b305984c64cbf2dc563d752d4a79717f286e679afc9b2daea14ef86b"
    $a1="83429da7b305984c64cbf2dc563d752d4a79717f286e679afc9b2daea14ef86b"
condition:
    ($a0 and $a1)
}

rule sha3_224_hashed_default_creds_ge_security_inc
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for ge_security_inc. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="af537e3fe10bce58cff5834fe36a35fba380497f0065f36aa6b7061e"
    $a1="af537e3fe10bce58cff5834fe36a35fba380497f0065f36aa6b7061e"
condition:
    ($a0 and $a1)
}

rule sha3_256_hashed_default_creds_ge_security_inc
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for ge_security_inc. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="865800f9b7760c25f543722e0f21ecf224da3567f0ab921f04449135f30e5375"
    $a1="865800f9b7760c25f543722e0f21ecf224da3567f0ab921f04449135f30e5375"
condition:
    ($a0 and $a1)
}

rule sha3_384_hashed_default_creds_ge_security_inc
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for ge_security_inc. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="455110feb9390dfb134779ee606f68e8b2210bdea5bdc885e4181e7afc7ee72f5cc05e83009d95bbc76318ecfec979b1"
    $a1="455110feb9390dfb134779ee606f68e8b2210bdea5bdc885e4181e7afc7ee72f5cc05e83009d95bbc76318ecfec979b1"
condition:
    ($a0 and $a1)
}

rule sha3_512_hashed_default_creds_ge_security_inc
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for ge_security_inc. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="c120e450fdc7ed75ffc85ef2058e7fdf19238d36879ca8704043ce1d356e9df3700ef2ca99cfa258274b181b2f0b10e9cd94ce28305b06dda78f19990d1db043"
    $a1="c120e450fdc7ed75ffc85ef2058e7fdf19238d36879ca8704043ce1d356e9df3700ef2ca99cfa258274b181b2f0b10e9cd94ce28305b06dda78f19990d1db043"
condition:
    ($a0 and $a1)
}

rule base64_hashed_default_creds_ge_security_inc
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for ge_security_inc. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="aW5zdGFsbA=="
    $a1="aW5zdGFsbA=="
condition:
    ($a0 and $a1)
}

