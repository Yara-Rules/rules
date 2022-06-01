/*This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as long as you use it under this license.*/

rule md5_hashed_default_creds_ubiquiti_edgeos_web
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for ubiquiti_edgeos_web. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="ba86f2bbe107c7c57eb5f2690775c712"
    $a1="ba86f2bbe107c7c57eb5f2690775c712"
condition:
    ($a0 and $a1)
}

rule sha1_hashed_default_creds_ubiquiti_edgeos_web
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for ubiquiti_edgeos_web. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="b5e701c92eb74de4d60cdc06f349e4cf009dad65"
    $a1="b5e701c92eb74de4d60cdc06f349e4cf009dad65"
condition:
    ($a0 and $a1)
}

rule sha384_hashed_default_creds_ubiquiti_edgeos_web
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for ubiquiti_edgeos_web. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="dfa6565e08c58600772ea633020fbff6f438eb361b8326473e01f56e37b35e58d5457dc2af808efc30b633ee154453fd"
    $a1="dfa6565e08c58600772ea633020fbff6f438eb361b8326473e01f56e37b35e58d5457dc2af808efc30b633ee154453fd"
condition:
    ($a0 and $a1)
}

rule sha224_hashed_default_creds_ubiquiti_edgeos_web
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for ubiquiti_edgeos_web. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="578b95221113d01e96aa5e9e6385e6594d2ff7c6e0ec35f1f4d9b854"
    $a1="578b95221113d01e96aa5e9e6385e6594d2ff7c6e0ec35f1f4d9b854"
condition:
    ($a0 and $a1)
}

rule sha512_hashed_default_creds_ubiquiti_edgeos_web
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for ubiquiti_edgeos_web. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="9a9a1b637cf31e2b159b512c24d3fae2407e2dcf15026c23a19d8828dca4d1b95f32cb78dbd87648afeb9281dee909b37e638e8b971f918579a5e756cafdecb7"
    $a1="9a9a1b637cf31e2b159b512c24d3fae2407e2dcf15026c23a19d8828dca4d1b95f32cb78dbd87648afeb9281dee909b37e638e8b971f918579a5e756cafdecb7"
condition:
    ($a0 and $a1)
}

rule sha256_hashed_default_creds_ubiquiti_edgeos_web
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for ubiquiti_edgeos_web. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="1af4cfa0ae8cb48c99dec1e17e2e78e1c0dc8d84194c078537c79b2bfb1096d4"
    $a1="1af4cfa0ae8cb48c99dec1e17e2e78e1c0dc8d84194c078537c79b2bfb1096d4"
condition:
    ($a0 and $a1)
}

rule blake2b_hashed_default_creds_ubiquiti_edgeos_web
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for ubiquiti_edgeos_web. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="c087c9aeff4d51b3a6156d4e53950d1a96d07b8904a75e9d8a23c4d1d3af4e6fb49325ac7cda6dee257b5cfcb79ba6c8de296eb425adaf488f4f0aefd8b9dc72"
    $a1="c087c9aeff4d51b3a6156d4e53950d1a96d07b8904a75e9d8a23c4d1d3af4e6fb49325ac7cda6dee257b5cfcb79ba6c8de296eb425adaf488f4f0aefd8b9dc72"
condition:
    ($a0 and $a1)
}

rule blake2s_hashed_default_creds_ubiquiti_edgeos_web
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for ubiquiti_edgeos_web. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="a70406d9a492442497b7e3d9f89487d6ab15c8eb14cdcf3e9512fe26157004ac"
    $a1="a70406d9a492442497b7e3d9f89487d6ab15c8eb14cdcf3e9512fe26157004ac"
condition:
    ($a0 and $a1)
}

rule sha3_224_hashed_default_creds_ubiquiti_edgeos_web
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for ubiquiti_edgeos_web. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="26eb9af91717ecfc0c09d6931b38d5cc042c100dd0f953a6dbe46858"
    $a1="26eb9af91717ecfc0c09d6931b38d5cc042c100dd0f953a6dbe46858"
condition:
    ($a0 and $a1)
}

rule sha3_256_hashed_default_creds_ubiquiti_edgeos_web
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for ubiquiti_edgeos_web. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="f5ac746ad512d7ad9a394bd8ac3d1a26084ac0c8a64528f6b6fb6a47666378ff"
    $a1="f5ac746ad512d7ad9a394bd8ac3d1a26084ac0c8a64528f6b6fb6a47666378ff"
condition:
    ($a0 and $a1)
}

rule sha3_384_hashed_default_creds_ubiquiti_edgeos_web
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for ubiquiti_edgeos_web. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="118255d8ecf3afde0a9c33214f4d65fa2fe3eba96c12ba7f92d676e067d2b01a573ed43b751b84abf8da2d5a8253984d"
    $a1="118255d8ecf3afde0a9c33214f4d65fa2fe3eba96c12ba7f92d676e067d2b01a573ed43b751b84abf8da2d5a8253984d"
condition:
    ($a0 and $a1)
}

rule sha3_512_hashed_default_creds_ubiquiti_edgeos_web
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for ubiquiti_edgeos_web. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="c60f2dea66779d66f9e7a7e1eb82421d95d95f7ef3f5e9ff50ae18206e219b6000c28a6fd55e76bb0373a417ab68cdfe9336996388c6ac6af413b70a68570e72"
    $a1="c60f2dea66779d66f9e7a7e1eb82421d95d95f7ef3f5e9ff50ae18206e219b6000c28a6fd55e76bb0373a417ab68cdfe9336996388c6ac6af413b70a68570e72"
condition:
    ($a0 and $a1)
}

rule base64_hashed_default_creds_ubiquiti_edgeos_web
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for ubiquiti_edgeos_web. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="dWJudA=="
    $a1="dWJudA=="
condition:
    ($a0 and $a1)
}

