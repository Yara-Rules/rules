/*This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as long as you use it under this license.*/

rule md5_hashed_default_creds_modernie_ssh
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for modernie_ssh. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="fd3b01b628fbcd566ccf5a2ab4056a1b"
    $a1="78b1ce6f7e90374fe98c8c351b3c04ad"
condition:
    ($a0 and $a1)
}

rule sha1_hashed_default_creds_modernie_ssh
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for modernie_ssh. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="09037a798d8c55da576d803ffa440a7e9c9402fa"
    $a1="0e3e8bc62d44ce9866e30457b0ef583b794d8c45"
condition:
    ($a0 and $a1)
}

rule sha384_hashed_default_creds_modernie_ssh
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for modernie_ssh. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="1d684629cdafb4a4a107f99d3610ddb9b8610f8439e02b8431241370173194d73afd317df0df4af3a62d9316a1a611bb"
    $a1="504da0cfa732ceb7f99ac06c8074aa4e7b36621a10a15a428c1fbe43bfc43d810cf7d200999ba936f95474143ee2e375"
condition:
    ($a0 and $a1)
}

rule sha224_hashed_default_creds_modernie_ssh
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for modernie_ssh. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="01fc824c9cfa6ab1597d349b0e0cbb60983375278a990d2b7529a997"
    $a1="eb11768af6e89759ee9aa33ced5659362dead5f702c6441339e86239"
condition:
    ($a0 and $a1)
}

rule sha512_hashed_default_creds_modernie_ssh
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for modernie_ssh. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="793eb58a2fdf9f8de72659580f8414f841dbae459d0d60230b9ca0f18f2c3b591d887e07055f9fef891909bd155c26d2ae39f76e886f87523a5a8132840a9b3d"
    $a1="9fb34f7b753a936ea0ffd9d569918241809b4f187b00121ad63518f432d46835bb40e2bd3681865b6630a32a753e8534793aa3c96376b1101e0700e1de79534e"
condition:
    ($a0 and $a1)
}

rule sha256_hashed_default_creds_modernie_ssh
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for modernie_ssh. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="d6b4a087a58f8645107241b783dc4f187ca708413107433dfb9d2058a64dfcd8"
    $a1="d651988096ee1c5bb2e0f7574a21390483f883f58f70adc9175cc78f85bb9afc"
condition:
    ($a0 and $a1)
}

rule blake2b_hashed_default_creds_modernie_ssh
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for modernie_ssh. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="2af8151bc3707323d828facb3cdcbf853baf893a5fa46cd03f4382745980fba33183dc43fab77d74a4193202c7ef6b45a07af8b0497b2fc4cb9d7c892b3f7feb"
    $a1="6c7ecc957bf227e01fcc0ec710e3dd8df84cadf843e958f34658013216a535e6d6db487386f78792a9e7747b69582fb7f883c44a96de300bac7dee8ae3fa7ac9"
condition:
    ($a0 and $a1)
}

rule blake2s_hashed_default_creds_modernie_ssh
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for modernie_ssh. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="4e16ea6c76d0e434343f7afdcdf6aa2c7dd877a175438565816b67bd1c5ccc07"
    $a1="1fbc578b901414ca42cfc90301221201473feb655a08354cbbf56173136509e5"
condition:
    ($a0 and $a1)
}

rule sha3_224_hashed_default_creds_modernie_ssh
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for modernie_ssh. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="aff90b20aa2231ce2938f9ade9e50f319d1e0a643c668a1155aeb52c"
    $a1="66f1101d4753565b63d91d2df0ea611b9c935e69dc05bce99725de9f"
condition:
    ($a0 and $a1)
}

rule sha3_256_hashed_default_creds_modernie_ssh
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for modernie_ssh. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="368f91f113cf0f343f177c6df26c9a02e28422adab83c3472372c8cc7ea51065"
    $a1="91eafe66793d6fae1b658e241eed8f1b010eb514005596de5407c9187203ce88"
condition:
    ($a0 and $a1)
}

rule sha3_384_hashed_default_creds_modernie_ssh
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for modernie_ssh. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="93e239479ca32eb330eddf7beb6103d71beac60a0ac7b3a7ffb179ad88c83a6f6132672ad5ffa860191c278f49fe65f9"
    $a1="ef3678ad01ee027a5142d36fa4b27bfb2650f7b3e3bf7e508fb180f661468bcfaae8b545ac197c2ba0921dc005d39f19"
condition:
    ($a0 and $a1)
}

rule sha3_512_hashed_default_creds_modernie_ssh
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for modernie_ssh. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="2869c26f456718306d1175e76906d7d79830e1342b7b73f1f56ae8cdd6950160e1320ff50058a7e1db030a868dd9f593aa37b99149461dc93181d25130fa3c45"
    $a1="ba7e0993284435f7e8b3220617d8cbb4751909686649a9f793d15334081cf76be4b3ee96743ee9cc499022d412f4b22d486db65ee0d12df800cd299840f86fae"
condition:
    ($a0 and $a1)
}

rule base64_hashed_default_creds_modernie_ssh
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for modernie_ssh. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="SUVVc2Vy"
    $a1="REByajMzbDFuZw=="
condition:
    ($a0 and $a1)
}

