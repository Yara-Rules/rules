/*This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as long as you use it under this license.*/

rule md5_hashed_default_creds_hyperic_inc
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for hyperic_inc. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="5df2f3c1f350ba3a3f0b1c5a617dce0a"
    $a1="5df2f3c1f350ba3a3f0b1c5a617dce0a"
condition:
    ($a0 and $a1)
}

rule sha1_hashed_default_creds_hyperic_inc
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for hyperic_inc. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="7fd1fdc058b8e357e5fe0aaeb084066ed18dab0c"
    $a1="7fd1fdc058b8e357e5fe0aaeb084066ed18dab0c"
condition:
    ($a0 and $a1)
}

rule sha384_hashed_default_creds_hyperic_inc
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for hyperic_inc. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="f82902fb8460f054e8275b3cc7197e3ccf98dcb8553844964033d2b2655bbfe8fa3f0ed7492b128d1adb699f422909c7"
    $a1="f82902fb8460f054e8275b3cc7197e3ccf98dcb8553844964033d2b2655bbfe8fa3f0ed7492b128d1adb699f422909c7"
condition:
    ($a0 and $a1)
}

rule sha224_hashed_default_creds_hyperic_inc
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for hyperic_inc. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="b16d3cf31a6f3f94d841009629a128c1c4e534b81879ff796e197d9c"
    $a1="b16d3cf31a6f3f94d841009629a128c1c4e534b81879ff796e197d9c"
condition:
    ($a0 and $a1)
}

rule sha512_hashed_default_creds_hyperic_inc
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for hyperic_inc. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="e4820193be3c13daa7156cca78bd33de6ef6d05111bd3b3a712adcc7bd4004bfb54c7e8820c8578c4db457ec6684eb529474df547cec0f8afc8e77a13b8f8ee7"
    $a1="e4820193be3c13daa7156cca78bd33de6ef6d05111bd3b3a712adcc7bd4004bfb54c7e8820c8578c4db457ec6684eb529474df547cec0f8afc8e77a13b8f8ee7"
condition:
    ($a0 and $a1)
}

rule sha256_hashed_default_creds_hyperic_inc
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for hyperic_inc. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="fda0254c0a5b76a0c86430085fdbf4d8c0b468e521f92b1678e1994b1d708b15"
    $a1="fda0254c0a5b76a0c86430085fdbf4d8c0b468e521f92b1678e1994b1d708b15"
condition:
    ($a0 and $a1)
}

rule blake2b_hashed_default_creds_hyperic_inc
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for hyperic_inc. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="9a3dbb59c730596da4c896254ed275e3c9b2762d71d32b8a432451c4bdff585b9afa7a4cb395a09e5fe43029b7f5a9e6aa2411eb416ee102a4f5831e78e4724d"
    $a1="9a3dbb59c730596da4c896254ed275e3c9b2762d71d32b8a432451c4bdff585b9afa7a4cb395a09e5fe43029b7f5a9e6aa2411eb416ee102a4f5831e78e4724d"
condition:
    ($a0 and $a1)
}

rule blake2s_hashed_default_creds_hyperic_inc
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for hyperic_inc. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="9f2365a7087bd67698576a5c71ed5434b1e4c4255763761ed05f94cb1c2ed7ba"
    $a1="9f2365a7087bd67698576a5c71ed5434b1e4c4255763761ed05f94cb1c2ed7ba"
condition:
    ($a0 and $a1)
}

rule sha3_224_hashed_default_creds_hyperic_inc
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for hyperic_inc. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="c76a4df1b64a64bced13df71c61575ce6c2dbdde9eb03e3ea1a9d9ef"
    $a1="c76a4df1b64a64bced13df71c61575ce6c2dbdde9eb03e3ea1a9d9ef"
condition:
    ($a0 and $a1)
}

rule sha3_256_hashed_default_creds_hyperic_inc
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for hyperic_inc. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="eb7b132b35b5b14b7f8c3a692cecf87ee62ab9af5e31c7b11cf333a997a0e05e"
    $a1="eb7b132b35b5b14b7f8c3a692cecf87ee62ab9af5e31c7b11cf333a997a0e05e"
condition:
    ($a0 and $a1)
}

rule sha3_384_hashed_default_creds_hyperic_inc
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for hyperic_inc. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="c758d9d252b8f071b1088d3f59ff670741ea735b2beede4860eb95c4a42cb49cb020c1ec2190723ed70a57af803be906"
    $a1="c758d9d252b8f071b1088d3f59ff670741ea735b2beede4860eb95c4a42cb49cb020c1ec2190723ed70a57af803be906"
condition:
    ($a0 and $a1)
}

rule sha3_512_hashed_default_creds_hyperic_inc
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for hyperic_inc. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="937be475e5fac0db8642ee99e1b2a73943e0ac8a19ed452ac58e0e19d4e87a926eef0d9d4a2ec56d7565e8e4d28a045f4fa4d1064f1686ca0babd60e0f5428f0"
    $a1="937be475e5fac0db8642ee99e1b2a73943e0ac8a19ed452ac58e0e19d4e87a926eef0d9d4a2ec56d7565e8e4d28a045f4fa4d1064f1686ca0babd60e0f5428f0"
condition:
    ($a0 and $a1)
}

rule base64_hashed_default_creds_hyperic_inc
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for hyperic_inc. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="aHFhZG1pbg=="
    $a1="aHFhZG1pbg=="
condition:
    ($a0 and $a1)
}

