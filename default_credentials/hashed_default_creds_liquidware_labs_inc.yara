/*This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as long as you use it under this license.*/

rule md5_hashed_default_creds_liquidware_labs_inc
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for liquidware_labs_inc. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="8784b1eb76a1aa5fae25ad19fbaf0afb"
    $a1="e91fb0cb082dbf5a7ee15fd6840b97ab"
condition:
    ($a0 and $a1)
}

rule sha1_hashed_default_creds_liquidware_labs_inc
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for liquidware_labs_inc. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="e3b543639b1b3d3ba7fd7dc4f881620b983b7630"
    $a1="0fcb9570a8103a1a8f6eade3a0d20e2fc7c5151a"
condition:
    ($a0 and $a1)
}

rule sha384_hashed_default_creds_liquidware_labs_inc
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for liquidware_labs_inc. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="0154f64bee08cfa1ff3d89190186e96709d8e46415e0e844bd66225896fa10d4373446307d147ec42eca51436aee8e19"
    $a1="cd049df322769f6ed74fe359a60cf6891469fb24c7e8c10bb43c07c277fb0ca1d065cb9afd925fc252f508aa23d30283"
condition:
    ($a0 and $a1)
}

rule sha224_hashed_default_creds_liquidware_labs_inc
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for liquidware_labs_inc. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="f09caf525ef42b656863a1fd139cddc582bb574c3a17ffcf0ce6532f"
    $a1="c0036db3abd7efa5aee571300356457938319c26190e3b5cadb42a38"
condition:
    ($a0 and $a1)
}

rule sha512_hashed_default_creds_liquidware_labs_inc
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for liquidware_labs_inc. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="cb3234ebe5f89ce313284062ca63fb3d3a463d16cebc1bebdaba9ceb4e57fa35d87e195db50f41b4f2344b4f38cfc802defd4706c81a023cad2026a936e62edc"
    $a1="026cbed7b25e63a97c4a2509b9ec77ab49b181fc1053eeb3d4a95d87aef057dfbfe40d968c14e8b6590544a53652c0ab37a10de0679581dada3b1d1a4f21a545"
condition:
    ($a0 and $a1)
}

rule sha256_hashed_default_creds_liquidware_labs_inc
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for liquidware_labs_inc. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="6e543c8618e419b9eda97fc216e44a0fa5953baa4e87223e78ad1e2c5d91e974"
    $a1="8d8a15a135e50e10d348fbee0ecebf1a3be51ea8590d0a369cfa768963877f8f"
condition:
    ($a0 and $a1)
}

rule blake2b_hashed_default_creds_liquidware_labs_inc
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for liquidware_labs_inc. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="bc457c419235100068e394a18b35cfa0a33ba93582441d427d84421fef6537cc873c58783939f3942a2c736ddbddde5caa0073859f6e2a3e9bbd9013d2262c4b"
    $a1="143a67efd513122ca7646c83bcf7cb0671a5575ebe3d5afee3a3148351fdb1038c687ee51236823f361fa9e3b1b35ef3d6317fbd31e78681a58613be2407419f"
condition:
    ($a0 and $a1)
}

rule blake2s_hashed_default_creds_liquidware_labs_inc
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for liquidware_labs_inc. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="2002e445bd9ec6a1d9e4a34293a8679c0fa6a2cf2ec353e250f86d4e69b114e1"
    $a1="59c5837f62276c570e82a5a8be40fbd5f6e8c511d89cf80132118967d2578843"
condition:
    ($a0 and $a1)
}

rule sha3_224_hashed_default_creds_liquidware_labs_inc
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for liquidware_labs_inc. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="4dec25da1dc96489a4acaa05caa4eaeeffe14568d864d7813b399e75"
    $a1="46ec5989d941258fbcba2f7abd73c4e12c63ca2557f05d5774979dbb"
condition:
    ($a0 and $a1)
}

rule sha3_256_hashed_default_creds_liquidware_labs_inc
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for liquidware_labs_inc. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="d2dd47ce498a42c13efdec56421a9f0216f878f3f797c0968be4610962fa5d28"
    $a1="a347294427c8865c0ccc12a737dfe510fc0f8a8ecd1ae68370bf15c2b30dfefe"
condition:
    ($a0 and $a1)
}

rule sha3_384_hashed_default_creds_liquidware_labs_inc
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for liquidware_labs_inc. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="6fccb029278d6f571eda2a5ba309343c91bf0728a23722dc257aedfb2fe5a0023f9f36935049a0497eebe75d2db3b31b"
    $a1="c8f5864ccd4c0bea7bde3c20a4d9b1b225a4725e18a8e440338fbf77fda53028229d3f22a51302b1f18196f4e05fe0d8"
condition:
    ($a0 and $a1)
}

rule sha3_512_hashed_default_creds_liquidware_labs_inc
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for liquidware_labs_inc. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="7434076f4e91d703b1736ab561218a6de6dfdd1e67d8b18329e044e59a72ce534c3e5c2d61904b8ecc39aac465ac276d2f1d33158face0df07ea3340a29d70a1"
    $a1="8854e95de857e02c5259d91607b4262d094d5a6306d9d88e70c49c984bbc35e2deeb92fdad75f8c6e9c72957c9093a82a38217d7056a3f47e1cf6e42102965aa"
condition:
    ($a0 and $a1)
}

rule base64_hashed_default_creds_liquidware_labs_inc
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for liquidware_labs_inc. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="c3NhZG1pbg=="
    $a1="c3NwYXNzd29yZA=="
condition:
    ($a0 and $a1)
}

