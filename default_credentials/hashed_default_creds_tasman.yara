/*This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as long as you use it under this license.*/

rule md5_hashed_default_creds_tasman
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for tasman. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="0ff4ce7c07739a71312e134abed679ce"
    $a1="6e4197a6ba7c128d0b0db1f48ee95a6b"
condition:
    ($a0 and $a1)
}

rule sha1_hashed_default_creds_tasman
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for tasman. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="9aaa862d80281332790cb4dea8e3e2846f41e0ab"
    $a1="d4d0cb42d8e995dea3e2871819dcc2de2eebfade"
condition:
    ($a0 and $a1)
}

rule sha384_hashed_default_creds_tasman
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for tasman. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="cb0d861c8af5784a7a79ccb114744ad728f567e744c9480ad90e0ef1be2ee9eaad18fb3e65d657b6286d7ae221738cd9"
    $a1="5fd6937ab0f465e4586d60c7a263f543e642e2f5153dc747643bfbf6d674c2da2413342f2b3af94283270bf2e33168aa"
condition:
    ($a0 and $a1)
}

rule sha224_hashed_default_creds_tasman
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for tasman. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="fc7ccabfc13e5e636e4b7770f08a1a27b15a7f178b610ff9bf64986e"
    $a1="680fcafecd41635708757493f4665390af480e77a8706dc3b75b9e30"
condition:
    ($a0 and $a1)
}

rule sha512_hashed_default_creds_tasman
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for tasman. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="af2fb2cbe8abcdf00434ef435c03d638750f5842c1c97c870db9ad7bd9cdb2640715e99df233045618684ce6a3eb1f968822436c2c65ea2dd91a2e11c65916af"
    $a1="7301a7a91ffc67747442b844f75e39145d312425b48ef51cb0d2869a38e372a4ff67c4ead2f50a34e5fdd261c99756e8df74540f996032762dfe9a81c5d93bcd"
condition:
    ($a0 and $a1)
}

rule sha256_hashed_default_creds_tasman
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for tasman. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="463758162c3c33c4bd2817e3ee24b590fdf9557b57fadec8a67bc965ff7a2892"
    $a1="72225f294d4db545cfce9e5412d14427e695ac79e79ed75e4e78a426751d1a4d"
condition:
    ($a0 and $a1)
}

rule blake2b_hashed_default_creds_tasman
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for tasman. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="78618dfd6cc2037c478bbd350b683130e209f5e6a2ea4d686ae9cfd276c2b898bb004a172382ee5a158945166b46a9cf6c6c37e21eebb9658a00a75f0d0da9bc"
    $a1="e16e38a0bc5af9028b4d0a97063659a53b65a4b177cb3ed7a220a22f415edf82df51f4c4ef180072568adfd3121f04b2a6ca86356f05a1bba513f76fe94999a0"
condition:
    ($a0 and $a1)
}

rule blake2s_hashed_default_creds_tasman
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for tasman. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="b2f150f3f7b086b0f9359658435fc8efb97dd7d7a4d451a6492a4362ea50fe2f"
    $a1="e3b2de5947a6cde05dd63697d585cae20eef5cbba476da7370ceb7983e46befc"
condition:
    ($a0 and $a1)
}

rule sha3_224_hashed_default_creds_tasman
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for tasman. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="1bc96dc63d3c7e8e3df00d1ab3f3f94cd27c427fed7649fa4867eb78"
    $a1="f35a090cc2ac04cc3a439b923190373b2adf654afd0ce61f8dcb9cf7"
condition:
    ($a0 and $a1)
}

rule sha3_256_hashed_default_creds_tasman
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for tasman. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="2feb0d839d212deeeb0c9b34a278aa6991bf1651714f573e5c615dfa7f43f642"
    $a1="0f2c27ee63f493acab330e7b1baa42ebcf31ba108251e8bcf70057c9efb648d5"
condition:
    ($a0 and $a1)
}

rule sha3_384_hashed_default_creds_tasman
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for tasman. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="186754002af123da7918dd8976c2040520afe3372cd348fa34a9e6bc501ceb06acad0455e1b09f944f952cf304b07984"
    $a1="1017e4c1bac9403628b270ab4adfbe211edb2c6a47b5a51cdc3bb1ba5ff5fd700846c80ecda74e5c9ef7d5eda716034d"
condition:
    ($a0 and $a1)
}

rule sha3_512_hashed_default_creds_tasman
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for tasman. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="0f486dd98c5dcfe4e62421e8c8aee6dfb031af24357c101bc2ddeb2301f6e2dfe82a1c35f5301c9d6ad21c6e837eb4365905da365e3840655ce64dfed65b3b4f"
    $a1="f390e84c4e1b582a9bbff9248424f26cf2ec34d09ab7f4fff72ee1fd83aec8f583f54260920ee63251d9ab125e08d78b47df95abb1b556dc02aae0c994c1ad7e"
condition:
    ($a0 and $a1)
}

rule base64_hashed_default_creds_tasman
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for tasman. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="VGFzbWFu"
    $a1="VGFzbWFubmV0"
condition:
    ($a0 and $a1)
}

