/*This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as long as you use it under this license.*/

rule md5_hashed_default_creds_cellit
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for cellit. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="bf922f6b4d66adab93fac39a5d5c2f7b"
    $a1="bf922f6b4d66adab93fac39a5d5c2f7b"
condition:
    ($a0 and $a1)
}

rule sha1_hashed_default_creds_cellit
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for cellit. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="5261ddac504c42c1070fdb34a9d6e1658a9f35a9"
    $a1="5261ddac504c42c1070fdb34a9d6e1658a9f35a9"
condition:
    ($a0 and $a1)
}

rule sha384_hashed_default_creds_cellit
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for cellit. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="bba0b34a984916991d58fab8cfedf50bf9e3983a2472dccc56c72f9b73beec31d084f1cbf8544151f8552d3af69fe4d0"
    $a1="bba0b34a984916991d58fab8cfedf50bf9e3983a2472dccc56c72f9b73beec31d084f1cbf8544151f8552d3af69fe4d0"
condition:
    ($a0 and $a1)
}

rule sha224_hashed_default_creds_cellit
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for cellit. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="10872985bb31edc6ee132c33b52a046ef90246fe8ac9c9943e965d6b"
    $a1="10872985bb31edc6ee132c33b52a046ef90246fe8ac9c9943e965d6b"
condition:
    ($a0 and $a1)
}

rule sha512_hashed_default_creds_cellit
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for cellit. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="adfcbddb386b6488dadfb43444abcdd8ec6f96cff59bcc2b412ec3d6a813967de3a11c35d7ad334fda9ba135813bba40ce0dd41abd7014559fcc2de90884f5ea"
    $a1="adfcbddb386b6488dadfb43444abcdd8ec6f96cff59bcc2b412ec3d6a813967de3a11c35d7ad334fda9ba135813bba40ce0dd41abd7014559fcc2de90884f5ea"
condition:
    ($a0 and $a1)
}

rule sha256_hashed_default_creds_cellit
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for cellit. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="372ffc10580c9b72e58a97200989a628b87a0e0791a1d8501a65ff93ed08fed5"
    $a1="372ffc10580c9b72e58a97200989a628b87a0e0791a1d8501a65ff93ed08fed5"
condition:
    ($a0 and $a1)
}

rule blake2b_hashed_default_creds_cellit
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for cellit. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="8de8daad1e9de94269e6e15cdbdef413c65c1780e19d77645782bb43e99dc6a2d68fc2dfadae12b45f11e19c191d5b2ba59f4275fa044016ff5e77ad842818b4"
    $a1="8de8daad1e9de94269e6e15cdbdef413c65c1780e19d77645782bb43e99dc6a2d68fc2dfadae12b45f11e19c191d5b2ba59f4275fa044016ff5e77ad842818b4"
condition:
    ($a0 and $a1)
}

rule blake2s_hashed_default_creds_cellit
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for cellit. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="4b83277e8332664080e91ced1bc99caa929bb8990dec9cb5ebe72d8546c17466"
    $a1="4b83277e8332664080e91ced1bc99caa929bb8990dec9cb5ebe72d8546c17466"
condition:
    ($a0 and $a1)
}

rule sha3_224_hashed_default_creds_cellit
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for cellit. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="4eb100e4c3113f2d961ec53cb83d77d1525391e3dbffc04810dc6463"
    $a1="4eb100e4c3113f2d961ec53cb83d77d1525391e3dbffc04810dc6463"
condition:
    ($a0 and $a1)
}

rule sha3_256_hashed_default_creds_cellit
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for cellit. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="46e08431c07005676f272596588d0ee27dd4ab575d64c657f099d78a9132c082"
    $a1="46e08431c07005676f272596588d0ee27dd4ab575d64c657f099d78a9132c082"
condition:
    ($a0 and $a1)
}

rule sha3_384_hashed_default_creds_cellit
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for cellit. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="1368a27f687cab00ae4d5de4d601110d1322b1345816a460d94f7ed68c2923c78fda34a0aeb1aa71184ca79f5813faf5"
    $a1="1368a27f687cab00ae4d5de4d601110d1322b1345816a460d94f7ed68c2923c78fda34a0aeb1aa71184ca79f5813faf5"
condition:
    ($a0 and $a1)
}

rule sha3_512_hashed_default_creds_cellit
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for cellit. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="90b71decf58039a87310db6392b829c319e8ff6cd60e5c35f519757d16b55fbb25d6f3d509305cea7a8ed363811499b3bf2729c0ef4d39b6dd2369b1eb59143f"
    $a1="90b71decf58039a87310db6392b829c319e8ff6cd60e5c35f519757d16b55fbb25d6f3d509305cea7a8ed363811499b3bf2729c0ef4d39b6dd2369b1eb59143f"
condition:
    ($a0 and $a1)
}

rule base64_hashed_default_creds_cellit
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for cellit. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="Y2VsbGl0"
    $a1="Y2VsbGl0"
condition:
    ($a0 and $a1)
}

