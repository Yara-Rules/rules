/*This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as long as you use it under this license.*/

rule md5_hashed_default_creds_metro
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for metro. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="62608e08adc29a8d6dbc9754e659f125"
    $a1="62608e08adc29a8d6dbc9754e659f125"
condition:
    ($a0 and $a1)
}

rule sha1_hashed_default_creds_metro
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for metro. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="d2a04d71301a8915217dd5faf81d12cffd6cd958"
    $a1="d2a04d71301a8915217dd5faf81d12cffd6cd958"
condition:
    ($a0 and $a1)
}

rule sha384_hashed_default_creds_metro
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for metro. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="dccfe25e8c0d8b5b355fe1e715f466b3e7027be30acbf965f4e6160045ea11a6d871190306f00fbabd09931a2a0bea2e"
    $a1="dccfe25e8c0d8b5b355fe1e715f466b3e7027be30acbf965f4e6160045ea11a6d871190306f00fbabd09931a2a0bea2e"
condition:
    ($a0 and $a1)
}

rule sha224_hashed_default_creds_metro
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for metro. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="192a06d20b1a067cc25d4916200752c0903521fdd342bef03961284a"
    $a1="192a06d20b1a067cc25d4916200752c0903521fdd342bef03961284a"
condition:
    ($a0 and $a1)
}

rule sha512_hashed_default_creds_metro
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for metro. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="85d7741af27f18cbefc7fdc96d4465f63d4e8da2126a196f87c4f7e1f65298855a0e4a4a8986936eae95e2b899e837c48ae39d8048f907ebd0095c87c49fb0af"
    $a1="85d7741af27f18cbefc7fdc96d4465f63d4e8da2126a196f87c4f7e1f65298855a0e4a4a8986936eae95e2b899e837c48ae39d8048f907ebd0095c87c49fb0af"
condition:
    ($a0 and $a1)
}

rule sha256_hashed_default_creds_metro
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for metro. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="948fe603f61dc036b5c596dc09fe3ce3f3d30dc90f024c85f3c82db2ccab679d"
    $a1="948fe603f61dc036b5c596dc09fe3ce3f3d30dc90f024c85f3c82db2ccab679d"
condition:
    ($a0 and $a1)
}

rule blake2b_hashed_default_creds_metro
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for metro. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="d6dc44ef4c274486bf10ad45b9b97537746443c665b875817010b6398aba76b321064857dd86568a6610e4de9ab520e57bbf64b11da6c1402873f4372d230414"
    $a1="d6dc44ef4c274486bf10ad45b9b97537746443c665b875817010b6398aba76b321064857dd86568a6610e4de9ab520e57bbf64b11da6c1402873f4372d230414"
condition:
    ($a0 and $a1)
}

rule blake2s_hashed_default_creds_metro
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for metro. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="ff95b804efe8412a293bdff3bfe9bffa0251ea7327f243a195bc6e1f68f16142"
    $a1="ff95b804efe8412a293bdff3bfe9bffa0251ea7327f243a195bc6e1f68f16142"
condition:
    ($a0 and $a1)
}

rule sha3_224_hashed_default_creds_metro
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for metro. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="e4edba7fad7cb671e5fd65394c56bb10d40a3fa809b44f7fdd3725ba"
    $a1="e4edba7fad7cb671e5fd65394c56bb10d40a3fa809b44f7fdd3725ba"
condition:
    ($a0 and $a1)
}

rule sha3_256_hashed_default_creds_metro
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for metro. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="b0c487aac068df482bf0a6ca161ac7dde146730324ac52c23dc429975a64fc6e"
    $a1="b0c487aac068df482bf0a6ca161ac7dde146730324ac52c23dc429975a64fc6e"
condition:
    ($a0 and $a1)
}

rule sha3_384_hashed_default_creds_metro
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for metro. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="4a7fa999178fa9e19fb8cdca4cb9eab9976c4f738563687e4d36be911be8e1a57f4aec666bd134946030419a12f2cee7"
    $a1="4a7fa999178fa9e19fb8cdca4cb9eab9976c4f738563687e4d36be911be8e1a57f4aec666bd134946030419a12f2cee7"
condition:
    ($a0 and $a1)
}

rule sha3_512_hashed_default_creds_metro
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for metro. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="8dab86975e5efa0a8f140e8a29b33ba232edeb8b2aaf2408f5fe1070fdaaad1795c227d58931a275777fe92e3c3fcef21b395f3b87384e9cfae5513c7685d889"
    $a1="8dab86975e5efa0a8f140e8a29b33ba232edeb8b2aaf2408f5fe1070fdaaad1795c227d58931a275777fe92e3c3fcef21b395f3b87384e9cfae5513c7685d889"
condition:
    ($a0 and $a1)
}

rule base64_hashed_default_creds_metro
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for metro. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="Y2xpZW50"
    $a1="Y2xpZW50"
condition:
    ($a0 and $a1)
}

