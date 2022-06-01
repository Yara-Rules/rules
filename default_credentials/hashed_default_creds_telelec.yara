/*This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as long as you use it under this license.*/

rule md5_hashed_default_creds_telelec
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for telelec. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="b09315ea09c6d3b5680094257f1f70e4"
    $a1="b09315ea09c6d3b5680094257f1f70e4"
condition:
    ($a0 and $a1)
}

rule sha1_hashed_default_creds_telelec
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for telelec. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="c29e4d9c8824409119eaa8ba182051b89121e663"
    $a1="c29e4d9c8824409119eaa8ba182051b89121e663"
condition:
    ($a0 and $a1)
}

rule sha384_hashed_default_creds_telelec
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for telelec. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="e9f8866402e5d88a92d7164f4ab16ccc48ceebcd9e204d22414f0d124b5b81fa51313c38dedfb37cab53b3bc2ba644eb"
    $a1="e9f8866402e5d88a92d7164f4ab16ccc48ceebcd9e204d22414f0d124b5b81fa51313c38dedfb37cab53b3bc2ba644eb"
condition:
    ($a0 and $a1)
}

rule sha224_hashed_default_creds_telelec
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for telelec. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="d19b187a2c44a9043d2941a96f588a644098c7a06381855aac2bce1e"
    $a1="d19b187a2c44a9043d2941a96f588a644098c7a06381855aac2bce1e"
condition:
    ($a0 and $a1)
}

rule sha512_hashed_default_creds_telelec
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for telelec. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="a8783749cff88f94fe983f9e4123a3b5848216eb0fa95f0c334abe27fea06c391e376512641c88c0ded61c2b08446a29c38f90a38583b9eb90a42d218ce24c39"
    $a1="a8783749cff88f94fe983f9e4123a3b5848216eb0fa95f0c334abe27fea06c391e376512641c88c0ded61c2b08446a29c38f90a38583b9eb90a42d218ce24c39"
condition:
    ($a0 and $a1)
}

rule sha256_hashed_default_creds_telelec
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for telelec. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="e73b48f750be953532c1d1757b5ba081e8a6b0408ea8b4e65ef1e65631a7da06"
    $a1="e73b48f750be953532c1d1757b5ba081e8a6b0408ea8b4e65ef1e65631a7da06"
condition:
    ($a0 and $a1)
}

rule blake2b_hashed_default_creds_telelec
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for telelec. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="62ee14697e16b5fd419cebf793537af17c124bf70a44bde2daaf4ce00a78c5593fbb1fc77da0c6545d703a0bc2070018db9039473bea3dba753b361ef7f4652c"
    $a1="62ee14697e16b5fd419cebf793537af17c124bf70a44bde2daaf4ce00a78c5593fbb1fc77da0c6545d703a0bc2070018db9039473bea3dba753b361ef7f4652c"
condition:
    ($a0 and $a1)
}

rule blake2s_hashed_default_creds_telelec
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for telelec. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="6f8839ae82b7e03ad2588043c694b6c7edcc39b7ea68916c2371d3ae3494ec75"
    $a1="6f8839ae82b7e03ad2588043c694b6c7edcc39b7ea68916c2371d3ae3494ec75"
condition:
    ($a0 and $a1)
}

rule sha3_224_hashed_default_creds_telelec
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for telelec. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="d02a75815c14cbbf88eb9061380adffd14dc907032ea27ffa6bb187c"
    $a1="d02a75815c14cbbf88eb9061380adffd14dc907032ea27ffa6bb187c"
condition:
    ($a0 and $a1)
}

rule sha3_256_hashed_default_creds_telelec
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for telelec. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="15b00f8137831443b85524fbd38723468fe52ca1015feb5ff0f9d56a78548544"
    $a1="15b00f8137831443b85524fbd38723468fe52ca1015feb5ff0f9d56a78548544"
condition:
    ($a0 and $a1)
}

rule sha3_384_hashed_default_creds_telelec
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for telelec. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="a31a9d3ef8e51ecba10bbf97fdb7ed9c08e0378c4905027e7526d6607e35e609143b54f0c9cdaceac33aba62c2b6c34b"
    $a1="a31a9d3ef8e51ecba10bbf97fdb7ed9c08e0378c4905027e7526d6607e35e609143b54f0c9cdaceac33aba62c2b6c34b"
condition:
    ($a0 and $a1)
}

rule sha3_512_hashed_default_creds_telelec
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for telelec. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="eae654e894a01929842ad4de51f57855b2b0567dbea71b75e622c76d03addea718bedaeff3aedca98bfd56de5644a4915158f1c106af7cc34e9f883ac083a1f8"
    $a1="eae654e894a01929842ad4de51f57855b2b0567dbea71b75e622c76d03addea718bedaeff3aedca98bfd56de5644a4915158f1c106af7cc34e9f883ac083a1f8"
condition:
    ($a0 and $a1)
}

rule base64_hashed_default_creds_telelec
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for telelec. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="ZWFnbGU="
    $a1="ZWFnbGU="
condition:
    ($a0 and $a1)
}

