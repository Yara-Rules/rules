/*This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as long as you use it under this license.*/

rule md5_hashed_default_creds_darkman
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for darkman. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="5397304a349e1b0a76c909e673d5c8aa"
    $a1="5397304a349e1b0a76c909e673d5c8aa"
condition:
    ($a0 and $a1)
}

rule sha1_hashed_default_creds_darkman
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for darkman. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="6045b1757913f659b210fceb4f2746d74d4d6b32"
    $a1="6045b1757913f659b210fceb4f2746d74d4d6b32"
condition:
    ($a0 and $a1)
}

rule sha384_hashed_default_creds_darkman
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for darkman. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="37ea15be066e1403e294d8a989ee2def70adbc014f70c1e5894a52295c10d0127317a4344ef29f4d49a03838682fbb3e"
    $a1="37ea15be066e1403e294d8a989ee2def70adbc014f70c1e5894a52295c10d0127317a4344ef29f4d49a03838682fbb3e"
condition:
    ($a0 and $a1)
}

rule sha224_hashed_default_creds_darkman
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for darkman. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="c9f28532416f34d4bbcc8f8851f97934cdeb2c977b8c55aeee46d025"
    $a1="c9f28532416f34d4bbcc8f8851f97934cdeb2c977b8c55aeee46d025"
condition:
    ($a0 and $a1)
}

rule sha512_hashed_default_creds_darkman
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for darkman. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="cc586db59176a9cc8c36457c58c6e7808164aac4bc6939b25d82e599622d288a2c3a4e505a7d59930f8a9177d346807a848b7e1f7e7f94629d2c750f402d4ab5"
    $a1="cc586db59176a9cc8c36457c58c6e7808164aac4bc6939b25d82e599622d288a2c3a4e505a7d59930f8a9177d346807a848b7e1f7e7f94629d2c750f402d4ab5"
condition:
    ($a0 and $a1)
}

rule sha256_hashed_default_creds_darkman
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for darkman. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="d56e5d6fad2da9f75de4a0fa70e8f88c77445c4cccf840865f3326abf8191a5a"
    $a1="d56e5d6fad2da9f75de4a0fa70e8f88c77445c4cccf840865f3326abf8191a5a"
condition:
    ($a0 and $a1)
}

rule blake2b_hashed_default_creds_darkman
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for darkman. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="539a05d51f92cb8a08d531414c69a83480fe8012954da087c1d21541dc1006de7dfb25de1b581fb791c12ba30316e68224b81b36df743fd7442d460e8bf8c0b9"
    $a1="539a05d51f92cb8a08d531414c69a83480fe8012954da087c1d21541dc1006de7dfb25de1b581fb791c12ba30316e68224b81b36df743fd7442d460e8bf8c0b9"
condition:
    ($a0 and $a1)
}

rule blake2s_hashed_default_creds_darkman
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for darkman. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="95eae19904a789f6a9959520a02cbb7d5f83d89bb1ab2c3b71d657f501be091b"
    $a1="95eae19904a789f6a9959520a02cbb7d5f83d89bb1ab2c3b71d657f501be091b"
condition:
    ($a0 and $a1)
}

rule sha3_224_hashed_default_creds_darkman
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for darkman. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="d3b1148ef23b2c6a93a97e2099b5e21c51fd5fd585ac91677f4d35e0"
    $a1="d3b1148ef23b2c6a93a97e2099b5e21c51fd5fd585ac91677f4d35e0"
condition:
    ($a0 and $a1)
}

rule sha3_256_hashed_default_creds_darkman
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for darkman. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="08ef0fddbc3238b40f0884d2299f1b91a6692f96d160388c9fd8bde732ac1921"
    $a1="08ef0fddbc3238b40f0884d2299f1b91a6692f96d160388c9fd8bde732ac1921"
condition:
    ($a0 and $a1)
}

rule sha3_384_hashed_default_creds_darkman
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for darkman. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="e804842b693589539e86f93ed38ba3dc4fd3dd113a9215ace8b9d1da1516abcfc59e10877a35dd44695d6d714360c4cf"
    $a1="e804842b693589539e86f93ed38ba3dc4fd3dd113a9215ace8b9d1da1516abcfc59e10877a35dd44695d6d714360c4cf"
condition:
    ($a0 and $a1)
}

rule sha3_512_hashed_default_creds_darkman
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for darkman. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="8ffc1dcbe8c1ee16b60afa4522ea10b02392d3c9b394572f906e1ede44def4d6622c79b66f8e441eb016dc3c92bf4b112f4431943683ea3eca61ed5c92b68d33"
    $a1="8ffc1dcbe8c1ee16b60afa4522ea10b02392d3c9b394572f906e1ede44def4d6622c79b66f8e441eb016dc3c92bf4b112f4431943683ea3eca61ed5c92b68d33"
condition:
    ($a0 and $a1)
}

rule base64_hashed_default_creds_darkman
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for darkman. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="aW9GVFBE"
    $a1="aW9GVFBE"
condition:
    ($a0 and $a1)
}

