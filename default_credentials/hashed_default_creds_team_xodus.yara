/*This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as long as you use it under this license.*/

rule md5_hashed_default_creds_team_xodus
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for team_xodus. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="3a3417f5f20a03a98973689887fb72a2"
    $a1="3a3417f5f20a03a98973689887fb72a2"
condition:
    ($a0 and $a1)
}

rule sha1_hashed_default_creds_team_xodus
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for team_xodus. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="682e113198b41b8b3429a7ba36840e99c886cba6"
    $a1="682e113198b41b8b3429a7ba36840e99c886cba6"
condition:
    ($a0 and $a1)
}

rule sha384_hashed_default_creds_team_xodus
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for team_xodus. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="db3468813281f294730b7210c29fd2a1cdac962740a7d95c443a6f34c1613625ce065ba663c63a97c62fb9681964ffe1"
    $a1="db3468813281f294730b7210c29fd2a1cdac962740a7d95c443a6f34c1613625ce065ba663c63a97c62fb9681964ffe1"
condition:
    ($a0 and $a1)
}

rule sha224_hashed_default_creds_team_xodus
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for team_xodus. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="2e357c0e270314c6b9b732e707420c67bb748295b4df16cc452bd77b"
    $a1="2e357c0e270314c6b9b732e707420c67bb748295b4df16cc452bd77b"
condition:
    ($a0 and $a1)
}

rule sha512_hashed_default_creds_team_xodus
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for team_xodus. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="df801d823f7c5228a19afd14b6dd4f50283d1c280a8dc43591b5d2e40c1d27c338b91a90c2e5703c45908c065740676385f1c1153d89d4e0365d3dc15b4e2133"
    $a1="df801d823f7c5228a19afd14b6dd4f50283d1c280a8dc43591b5d2e40c1d27c338b91a90c2e5703c45908c065740676385f1c1153d89d4e0365d3dc15b4e2133"
condition:
    ($a0 and $a1)
}

rule sha256_hashed_default_creds_team_xodus
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for team_xodus. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="f711da60664c04c146d7a47b722c38a8d0bf46c3f52c2084c5c8d1cb78138e73"
    $a1="f711da60664c04c146d7a47b722c38a8d0bf46c3f52c2084c5c8d1cb78138e73"
condition:
    ($a0 and $a1)
}

rule blake2b_hashed_default_creds_team_xodus
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for team_xodus. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="7ee0048a5fcdebe2afe62962ca40b9e76ac7289928307045f562a55fef28a6cbe276f9a53b5af31bb7586523c58f62b4f8a4d47efd15023e1fad37de836e049b"
    $a1="7ee0048a5fcdebe2afe62962ca40b9e76ac7289928307045f562a55fef28a6cbe276f9a53b5af31bb7586523c58f62b4f8a4d47efd15023e1fad37de836e049b"
condition:
    ($a0 and $a1)
}

rule blake2s_hashed_default_creds_team_xodus
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for team_xodus. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="6a50859736e29118c4448e9cf25ca6c1cca783e0e0a5bec7c4864067078594b0"
    $a1="6a50859736e29118c4448e9cf25ca6c1cca783e0e0a5bec7c4864067078594b0"
condition:
    ($a0 and $a1)
}

rule sha3_224_hashed_default_creds_team_xodus
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for team_xodus. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="e137a282db1a1e01ca6a338fccde3cba160545fd4d055ce2baf02d38"
    $a1="e137a282db1a1e01ca6a338fccde3cba160545fd4d055ce2baf02d38"
condition:
    ($a0 and $a1)
}

rule sha3_256_hashed_default_creds_team_xodus
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for team_xodus. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="a243aaf3c9d0b7ca3da869e7366affaafd2d38d7c8f74ce3ab8886c0d970adc4"
    $a1="a243aaf3c9d0b7ca3da869e7366affaafd2d38d7c8f74ce3ab8886c0d970adc4"
condition:
    ($a0 and $a1)
}

rule sha3_384_hashed_default_creds_team_xodus
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for team_xodus. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="bc9d433da860db1ae55d7dba03251945b66fad207ff41ef84453112bfb46d30271ca96dfd9621df0f5b77018fc7fc87c"
    $a1="bc9d433da860db1ae55d7dba03251945b66fad207ff41ef84453112bfb46d30271ca96dfd9621df0f5b77018fc7fc87c"
condition:
    ($a0 and $a1)
}

rule sha3_512_hashed_default_creds_team_xodus
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for team_xodus. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="471d6087ddf83fc1dacca51213356f2ccd0bdaed27e1636c84be34a0d5879c30c07abf47fab1a13c0d255bd44e61d7ff0b9a7ea5be7cccac482882a098aa456a"
    $a1="471d6087ddf83fc1dacca51213356f2ccd0bdaed27e1636c84be34a0d5879c30c07abf47fab1a13c0d255bd44e61d7ff0b9a7ea5be7cccac482882a098aa456a"
condition:
    ($a0 and $a1)
}

rule base64_hashed_default_creds_team_xodus
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for team_xodus. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="eGJveA=="
    $a1="eGJveA=="
condition:
    ($a0 and $a1)
}

