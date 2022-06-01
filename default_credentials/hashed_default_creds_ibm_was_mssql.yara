/*This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as long as you use it under this license.*/

rule md5_hashed_default_creds_ibm_was_mssql
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for ibm_was_mssql. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="35f2e49a6729b95335b3566f769da826"
    $a1="35f2e49a6729b95335b3566f769da826"
condition:
    ($a0 and $a1)
}

rule sha1_hashed_default_creds_ibm_was_mssql
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for ibm_was_mssql. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="eecfc1cff12c987f4ddec126beea51acf7086612"
    $a1="eecfc1cff12c987f4ddec126beea51acf7086612"
condition:
    ($a0 and $a1)
}

rule sha384_hashed_default_creds_ibm_was_mssql
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for ibm_was_mssql. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="573efba8477ee21f309d7e3275c7cf0887a87ed148a448e057ab443a98c56b61a00bbaeaabe6036e62aec60c2de86f52"
    $a1="573efba8477ee21f309d7e3275c7cf0887a87ed148a448e057ab443a98c56b61a00bbaeaabe6036e62aec60c2de86f52"
condition:
    ($a0 and $a1)
}

rule sha224_hashed_default_creds_ibm_was_mssql
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for ibm_was_mssql. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="251adab9b068f9de8a561d2f7e388d1f4710696f64b9e4ae83e60951"
    $a1="251adab9b068f9de8a561d2f7e388d1f4710696f64b9e4ae83e60951"
condition:
    ($a0 and $a1)
}

rule sha512_hashed_default_creds_ibm_was_mssql
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for ibm_was_mssql. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="11b6b4d3f1a12a0a96487520aee711b0a74413caebcbdfb0476f0939b7f7dcf424fd6e77dbb65ff387f00573a43f653af38fa0112c4d3bf45f3c55fee888707f"
    $a1="11b6b4d3f1a12a0a96487520aee711b0a74413caebcbdfb0476f0939b7f7dcf424fd6e77dbb65ff387f00573a43f653af38fa0112c4d3bf45f3c55fee888707f"
condition:
    ($a0 and $a1)
}

rule sha256_hashed_default_creds_ibm_was_mssql
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for ibm_was_mssql. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="702630be17378d19c80ac9efe2f451828d39fbee6578d9edccba45e05fd5a20e"
    $a1="702630be17378d19c80ac9efe2f451828d39fbee6578d9edccba45e05fd5a20e"
condition:
    ($a0 and $a1)
}

rule blake2b_hashed_default_creds_ibm_was_mssql
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for ibm_was_mssql. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="6effacaf73c1e23f1ea52c5ccc0946a6c95cd1ff5968cc2216fc3967541a3ac8d3e5707e2477a8f6c55958ed904361e409037695b5467b1c2582ac58c80fdc47"
    $a1="6effacaf73c1e23f1ea52c5ccc0946a6c95cd1ff5968cc2216fc3967541a3ac8d3e5707e2477a8f6c55958ed904361e409037695b5467b1c2582ac58c80fdc47"
condition:
    ($a0 and $a1)
}

rule blake2s_hashed_default_creds_ibm_was_mssql
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for ibm_was_mssql. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="cf0d620f7107a7fb64d40665b5c2f93e067efcf982aa1e1ae005c171f0a78cb3"
    $a1="cf0d620f7107a7fb64d40665b5c2f93e067efcf982aa1e1ae005c171f0a78cb3"
condition:
    ($a0 and $a1)
}

rule sha3_224_hashed_default_creds_ibm_was_mssql
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for ibm_was_mssql. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="05a040e23f67c06d76c9d93625fbe023236714c7fcd78bef428e81a4"
    $a1="05a040e23f67c06d76c9d93625fbe023236714c7fcd78bef428e81a4"
condition:
    ($a0 and $a1)
}

rule sha3_256_hashed_default_creds_ibm_was_mssql
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for ibm_was_mssql. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="003d8e7819c382f2b5860ec7ce6e464cd39e1e132d082d265316c8dfb2c3fed9"
    $a1="003d8e7819c382f2b5860ec7ce6e464cd39e1e132d082d265316c8dfb2c3fed9"
condition:
    ($a0 and $a1)
}

rule sha3_384_hashed_default_creds_ibm_was_mssql
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for ibm_was_mssql. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="7c932b911817327b78cc140309ba83cb0e5e360ab93195d1e9c328fa045d2ee9af6a3cad254f7055709ebf338fbdae22"
    $a1="7c932b911817327b78cc140309ba83cb0e5e360ab93195d1e9c328fa045d2ee9af6a3cad254f7055709ebf338fbdae22"
condition:
    ($a0 and $a1)
}

rule sha3_512_hashed_default_creds_ibm_was_mssql
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for ibm_was_mssql. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="8dd2120641ef9de1ceee1a6d1a6684225d2424f10c51a3ace90a0fcdd395c7308497ec37fd422d8e653abad8660e8f0f6fb044ff6babf96fd2e91365fb9f39d7"
    $a1="8dd2120641ef9de1ceee1a6d1a6684225d2424f10c51a3ace90a0fcdd395c7308497ec37fd422d8e653abad8660e8f0f6fb044ff6babf96fd2e91365fb9f39d7"
condition:
    ($a0 and $a1)
}

rule base64_hashed_default_creds_ibm_was_mssql
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for ibm_was_mssql. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="d2FzYWRtaW4="
    $a1="d2FzYWRtaW4="
condition:
    ($a0 and $a1)
}

