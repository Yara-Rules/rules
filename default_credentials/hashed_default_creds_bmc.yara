/*This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as long as you use it under this license.*/

rule md5_hashed_default_creds_bmc
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for bmc. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="7e39411afa494a20a2b1a11eff1fe660"
    $a1="7e39411afa494a20a2b1a11eff1fe660"
condition:
    ($a0 and $a1)
}

rule sha1_hashed_default_creds_bmc
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for bmc. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="378373635d00507b124b65aa64205d8e16fd5ac9"
    $a1="378373635d00507b124b65aa64205d8e16fd5ac9"
condition:
    ($a0 and $a1)
}

rule sha384_hashed_default_creds_bmc
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for bmc. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="172b0067e069e237ba0f102f1ef1bcc2a365c4d325b0255debba924d3effe2bf090a4ec7ccf33aae860a87a519ed6677"
    $a1="172b0067e069e237ba0f102f1ef1bcc2a365c4d325b0255debba924d3effe2bf090a4ec7ccf33aae860a87a519ed6677"
condition:
    ($a0 and $a1)
}

rule sha224_hashed_default_creds_bmc
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for bmc. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="346c2b964650d10a2ec07dd30f55802d9b77476c40a7b52e20e82126"
    $a1="346c2b964650d10a2ec07dd30f55802d9b77476c40a7b52e20e82126"
condition:
    ($a0 and $a1)
}

rule sha512_hashed_default_creds_bmc
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for bmc. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="15249a9ac68a88215a642611eb1e97864358299439e9602d267265592617fc81c6b97916057d686fe5443baf38c1c37ddbba1f0274b431b1c0bd1cf81a466e1c"
    $a1="15249a9ac68a88215a642611eb1e97864358299439e9602d267265592617fc81c6b97916057d686fe5443baf38c1c37ddbba1f0274b431b1c0bd1cf81a466e1c"
condition:
    ($a0 and $a1)
}

rule sha256_hashed_default_creds_bmc
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for bmc. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="e87f314e6f2183a5804fc8491c946716b365e23c9a964baf584da96fb90ce13b"
    $a1="e87f314e6f2183a5804fc8491c946716b365e23c9a964baf584da96fb90ce13b"
condition:
    ($a0 and $a1)
}

rule blake2b_hashed_default_creds_bmc
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for bmc. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="0c5406d0cb9f4c79fd9eb85c8aa6ac104cab80c479fc16d2d67bea490b4c72455c6dfe25c7c00546efe3ab0a2e674f95447f8f10ca28cdd3b37ff26e328fc670"
    $a1="0c5406d0cb9f4c79fd9eb85c8aa6ac104cab80c479fc16d2d67bea490b4c72455c6dfe25c7c00546efe3ab0a2e674f95447f8f10ca28cdd3b37ff26e328fc670"
condition:
    ($a0 and $a1)
}

rule blake2s_hashed_default_creds_bmc
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for bmc. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="76ef2cedafd9d332a98d5962e03a89e5edc4b8af423aad2d7db73727829ea8c2"
    $a1="76ef2cedafd9d332a98d5962e03a89e5edc4b8af423aad2d7db73727829ea8c2"
condition:
    ($a0 and $a1)
}

rule sha3_224_hashed_default_creds_bmc
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for bmc. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="03bd1d59c7162683d3afade8f5ac9179cd8e1e262170add8bd500509"
    $a1="03bd1d59c7162683d3afade8f5ac9179cd8e1e262170add8bd500509"
condition:
    ($a0 and $a1)
}

rule sha3_256_hashed_default_creds_bmc
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for bmc. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="ce6299cea06e9502aa2c6e5dc13a38e224b346e973c4330f199266c895d35073"
    $a1="ce6299cea06e9502aa2c6e5dc13a38e224b346e973c4330f199266c895d35073"
condition:
    ($a0 and $a1)
}

rule sha3_384_hashed_default_creds_bmc
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for bmc. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="968951d5d06f5dce1d93b83ea0809953fc5ad70b81ac6c36d6cce23bc29c76d121f3cfaffca16c8604cdc5a554f0d340"
    $a1="968951d5d06f5dce1d93b83ea0809953fc5ad70b81ac6c36d6cce23bc29c76d121f3cfaffca16c8604cdc5a554f0d340"
condition:
    ($a0 and $a1)
}

rule sha3_512_hashed_default_creds_bmc
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for bmc. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="81381e2fa9bfe4eb3ed7c90e73a52dfb39437c3d7ecca0c7e01bff54e7d4d4247c0a1cbbcf505ad2819893e831a813b2f0571a33349bfaef310450d7f3b8dca2"
    $a1="81381e2fa9bfe4eb3ed7c90e73a52dfb39437c3d7ecca0c7e01bff54e7d4d4247c0a1cbbcf505ad2819893e831a813b2f0571a33349bfaef310450d7f3b8dca2"
condition:
    ($a0 and $a1)
}

rule base64_hashed_default_creds_bmc
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for bmc. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="cGF0cm9s"
    $a1="cGF0cm9s"
condition:
    ($a0 and $a1)
}

