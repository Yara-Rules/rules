/*This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as long as you use it under this license.*/

rule md5_hashed_default_creds_stratacom
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for stratacom. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="ebcc114a45ceb8c9312fa8c275e90138"
    $a1="09cf23dc78f6dc6e6b16f7c6786ad5c5"
condition:
    ($a0 and $a1)
}

rule sha1_hashed_default_creds_stratacom
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for stratacom. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="ca84f7b39732dc4e4cad58514c3507ec33410a1c"
    $a1="a5aa248e8ee802a958266dd0337600c10d3fefeb"
condition:
    ($a0 and $a1)
}

rule sha384_hashed_default_creds_stratacom
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for stratacom. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="dac32cd47547c127b8724766d1f4b77b9ea53639e84c7d07268f6969aea80513134ae77aceae74a444deb3ad62db1f3b"
    $a1="e85d2fdb8cab77a9bac7a917af0c70054b4e912cd654abb679ca059157f386bf534a808a0b6bd2e0a00f99a9dd6d8d49"
condition:
    ($a0 and $a1)
}

rule sha224_hashed_default_creds_stratacom
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for stratacom. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="8dd6ba06f79ff869e7c8f1b339cda5a03f61cb7fa7f52ed2251680b9"
    $a1="cc05f990c1fd59d5205293b9bb7e27193e796d26baf4b5fc81921736"
condition:
    ($a0 and $a1)
}

rule sha512_hashed_default_creds_stratacom
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for stratacom. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="353fef828b97f476d722500f1ea85dcf46107f789145b3854ce5c7a9a341da1d2c7a3d50095888d9d93f4caa075ee198a3a9d72353d5748dfadeb2b838c77809"
    $a1="d33938cbd0dac04f6e8e64917eaab5ef17c690939b0361447c5f70b8d2c8970e382104cc071452f3d00f7832a655aa5179a788fad06851cb5d4dd0e99da0c54f"
condition:
    ($a0 and $a1)
}

rule sha256_hashed_default_creds_stratacom
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for stratacom. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="928dbb18ffa58ef5541af2eb6f134bccac2b5cd99c9c7bf9cf9415114d505181"
    $a1="7b007a1b653efca19ed81702b270e6cc94ac78c739c8e92b7636930fcea20bde"
condition:
    ($a0 and $a1)
}

rule blake2b_hashed_default_creds_stratacom
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for stratacom. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="45c70ac54f2bc07ee2f2ef6d5bfa419b73bf9d5d3ba10f5b046bb8802ecde33e4df42faab1ee3454213a6d2496a9a9eddabeabfe024b99a54730b853f8720e88"
    $a1="1a73e624e5f1539e285c5913f236c6abe07863948cede2a29ffcbaece100206952f439bf5021c2ad3f2c1b0a360acf93046f04697c2943a920906549ffd5f169"
condition:
    ($a0 and $a1)
}

rule blake2s_hashed_default_creds_stratacom
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for stratacom. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="9f72eab1d44d592baa2244a306e38d84ff14875bb768060c75832ce873a22cae"
    $a1="4735e3cd0823bd8f7a686744446bef03523c0c998016ca31b6dd53fb84e15b84"
condition:
    ($a0 and $a1)
}

rule sha3_224_hashed_default_creds_stratacom
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for stratacom. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="65bf012c41d3550a376d4dbc8ad04708040c88f52150c02bb654aa05"
    $a1="3cc104ff0fb2fc24dca9fb070b345992f7dc937bce23907a694cdef9"
condition:
    ($a0 and $a1)
}

rule sha3_256_hashed_default_creds_stratacom
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for stratacom. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="bee935851f51f5e0434b5b7fcd10dfe137ec896f05d0b0c24d84fdba6c228dc7"
    $a1="59704ae14dd3d4ad331b2e058426998cfb93d921adc38b61f3460d81619e0979"
condition:
    ($a0 and $a1)
}

rule sha3_384_hashed_default_creds_stratacom
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for stratacom. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="a36dc138cbce7b094201aa2e5b8b744d7042ac9e012df98a50c5e1c109d2ff4cbf8cc505b16ff5fa937ad17f13d164d7"
    $a1="202310c64c6018f2d20bffca56af176e3f761f460a61239b979ffebbe0dddf625a1e0c0716b1acc5314738983dfe0e17"
condition:
    ($a0 and $a1)
}

rule sha3_512_hashed_default_creds_stratacom
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for stratacom. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="bee5381af343c00b4c1747b4e5e64373fe2cbbeb53c6d01adfdab16ca6b5a3ffb1a3297fd7d97877f4b715621d2962188b1e100624482d80fd594f2ee762e108"
    $a1="14f9a0c1b9a35eec9d6c4c6fe4c6def00413c26ba1f0e6b9efcddd51da084b7ee395be21a08dd7259a00ecd6b48abf520fd043d5efcf74ec08db30956c4497a5"
condition:
    ($a0 and $a1)
}

rule base64_hashed_default_creds_stratacom
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for stratacom. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="c3RyYXRhY29t"
    $a1="c3RyYXRhdXNlcg=="
condition:
    ($a0 and $a1)
}

