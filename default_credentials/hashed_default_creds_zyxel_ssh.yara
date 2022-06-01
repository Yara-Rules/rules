/*This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as long as you use it under this license.*/

rule md5_hashed_default_creds_zyxel_ssh
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for zyxel_ssh. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="0da65ec5cc6a2f9c511b2e4510285845"
    $a1="3a85810ab38c634ae31f6c421bc04445"
condition:
    ($a0 and $a1)
}

rule sha1_hashed_default_creds_zyxel_ssh
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for zyxel_ssh. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="d45feae75cb37cf86df05382292d27d66fa951fe"
    $a1="de8c9d19ebaeeb1660fdc9a27723b499827c7749"
condition:
    ($a0 and $a1)
}

rule sha384_hashed_default_creds_zyxel_ssh
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for zyxel_ssh. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="1feb54dd8d55fe3acdcc88bbefa920c7d57cbf14be8e12271c428cfa460e04f38caa37eef53f34c141dc1674a7967ba8"
    $a1="672737e7130b76016fd70da90a6335333abf04ea8307be4c8b0c5e3088f87d602dbec8b602480be4011cf4edaf449614"
condition:
    ($a0 and $a1)
}

rule sha224_hashed_default_creds_zyxel_ssh
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for zyxel_ssh. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="b9d6be0a741186f9057b1046240a6df19364bba94ba228519cc6c556"
    $a1="73d45486175c2dfd38dde3d9c224a96c2364f8a02dffd3039e1cee7a"
condition:
    ($a0 and $a1)
}

rule sha512_hashed_default_creds_zyxel_ssh
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for zyxel_ssh. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="ac190ec2765fe303f43f1f5aae982aaa64f0c701a19d6e540ff421d4d53b347c7dd784620b8b030c315bde81a0587adbc387a7a270e76a096126df8dbd7fbd8e"
    $a1="f628ac307c494ab7620b51935842da4d18b1a150910133b39438cf551745753920dbba90515487e33168e917002b45ee73cded3014e9cbec09cee0f736d11fce"
condition:
    ($a0 and $a1)
}

rule sha256_hashed_default_creds_zyxel_ssh
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for zyxel_ssh. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="97eab8eca5407fe0bd1af1eb4f1e4fe0c4760ea48aef889803ac7584586e2cdd"
    $a1="f81474dd5c6fdfd0b86d874390fa7e5b960e29c4f7f1e860635ac3bc5e32a897"
condition:
    ($a0 and $a1)
}

rule blake2b_hashed_default_creds_zyxel_ssh
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for zyxel_ssh. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="50ef1ff7afd840785894fe8447ab0175436d1a0ea24b8fc05b60049e6ca7242d19d8a53aaf65149f8c0ce5416d4924977dfb39f41d227b0cd01542059ec8ac77"
    $a1="aa04814d76ce71ff41174915b0f6add1a36645683395290c98a9fea0e9b043f924b96446e22c7badadc80d46f7e4b54b1a7d70b669d024982c0ce8773461f48f"
condition:
    ($a0 and $a1)
}

rule blake2s_hashed_default_creds_zyxel_ssh
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for zyxel_ssh. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="48be671246741fa37fff3e382f72646a7b1f0bfcf762caf5fe37e276b6348aea"
    $a1="7e725df21b16a98b5f874683d3565b972e134c009a193cb17a41df3652ee0fb3"
condition:
    ($a0 and $a1)
}

rule sha3_224_hashed_default_creds_zyxel_ssh
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for zyxel_ssh. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="f34188f6d2656d5b004f971527c55270dadc7a5d1132d28a5621181a"
    $a1="5941b2b71710b18d8edfdd60680bb91a4ec86d5b8977798debcce383"
condition:
    ($a0 and $a1)
}

rule sha3_256_hashed_default_creds_zyxel_ssh
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for zyxel_ssh. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="6767dd7e79ed2ea1a11ee88be0f0d80590d25697aa2b5d5b8a37421a9bbf625e"
    $a1="337160cd0065da43c33c0df1a7903dd16ed8547ea91733366a614d0072ca5add"
condition:
    ($a0 and $a1)
}

rule sha3_384_hashed_default_creds_zyxel_ssh
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for zyxel_ssh. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="59e8791b3c6afcaed93cca20f50282848687f5f037287d8510e2a04e30c41c4d1133066dc1382b1c21e8ee0edf9f0dd4"
    $a1="0e4eebde2872cc827253b095351ff431bce62c6207c0886354b53fb660f1a0b566f05afe3de0b1d31deccd9bfc7a9dfc"
condition:
    ($a0 and $a1)
}

rule sha3_512_hashed_default_creds_zyxel_ssh
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for zyxel_ssh. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="59f6d83edd3122738ea7c4d28ca71317419d790311f2664b44155b5d8bd2bfe36d932ef5cd99da1cd36dc34cfc19bedbcc2d17c2259eaddd2c1c55d77e14f86d"
    $a1="9ca618b265911ee80b3288cbd3c51281fc31d0e90432325e037c11b96ded04ccdad3dae2637c507f0a1b0e32d20ef8b37f0d97de4bb2ed9c506f512db2e09ecf"
condition:
    ($a0 and $a1)
}

rule base64_hashed_default_creds_zyxel_ssh
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for zyxel_ssh. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="enlmd3A="
    $a1="UHJPdyFhTl9mWHA="
condition:
    ($a0 and $a1)
}

