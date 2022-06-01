/*This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as long as you use it under this license.*/

rule md5_hashed_default_creds_solution_6
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for solution_6. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="47bce5c74f589f4867dbd57e9ca9f808"
    $a1="d015fbbbc2e496873bb26496f89fad82"
condition:
    ($a0 and $a1)
}

rule sha1_hashed_default_creds_solution_6
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for solution_6. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="7e240de74fb1ed08fa08d38063f6a6a91462a815"
    $a1="80fe26caedf45ec566a73358b54edd887c9a9e69"
condition:
    ($a0 and $a1)
}

rule sha384_hashed_default_creds_solution_6
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for solution_6. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="8e07e5bdd64aa37536c1f257a6b44963cc327b7d7dcb2cb47a22073d33414462bfa184487cf372ce0a19dfc83f8336d8"
    $a1="df397ab5425650522befed588b722caac6a7c6e1d8f9a9e43dadbb9a09b5d451fb092091ff119a7af4a499f72e714635"
condition:
    ($a0 and $a1)
}

rule sha224_hashed_default_creds_solution_6
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for solution_6. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="ed782653bfec275cf37d027511a68cece08d1e53df1360c762ce043a"
    $a1="1c379f650b25800eb91fc88fcd178d83139ecd88fd2b1566383d0720"
condition:
    ($a0 and $a1)
}

rule sha512_hashed_default_creds_solution_6
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for solution_6. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="d6f644b19812e97b5d871658d6d3400ecd4787faeb9b8990c1e7608288664be77257104a58d033bcf1a0e0945ff06468ebe53e2dff36e248424c7273117dac09"
    $a1="6cf15bacd083f53748b50889e3442c6a161344b888ab58ab869fce387ae7421e3053897ff50fdb3b9bfea5603449aaf6946c999709666f9e6af8677ad126de67"
condition:
    ($a0 and $a1)
}

rule sha256_hashed_default_creds_solution_6
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for solution_6. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="9834876dcfb05cb167a5c24953eba58c4ac89b1adf57f28f2f9d09af107ee8f0"
    $a1="fdaea5b274313621e9c177bdc834ea5a92b2269f76306c2da119b26d589cafb9"
condition:
    ($a0 and $a1)
}

rule blake2b_hashed_default_creds_solution_6
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for solution_6. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="e0df35984516b6af9d5b3deafecab7b5198103c2ffddf31c5516dab61273634729c9109e039ae16ac8f784fcb58bd8fd9bec0be31f335b0fc841e96c2898f1dd"
    $a1="962f6d019874d5564ed95a56da180d9ce718d0f92b9192f7e2c94c4919be446cb91d77b6e411146479b5066430eb5fafbf4c72273c824213d9f5090a07301a5c"
condition:
    ($a0 and $a1)
}

rule blake2s_hashed_default_creds_solution_6
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for solution_6. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="e29140a30d9494d5e3cdaa97016cbc07492acaf791724a232f46ca28f0e8f862"
    $a1="798085e4439ff7e1610111e2d74f5a8ed3a8789e07baccc5773eb849ac51bf03"
condition:
    ($a0 and $a1)
}

rule sha3_224_hashed_default_creds_solution_6
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for solution_6. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="a99a788ac95cc8b7784128688dcdf8022f09242a15cacd131aeecdb4"
    $a1="70a68a1895837440c21501fae2333d3f2e29f9ece3336b91cc5aab4d"
condition:
    ($a0 and $a1)
}

rule sha3_256_hashed_default_creds_solution_6
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for solution_6. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="80fb34a2c6bc537d2d044c013042b3b36239aaf3cfd381d62a9ab8e8753876d0"
    $a1="292a87034724359d41264b44778ee243e74b20d5dfd6d61f00a820f7dce0c9be"
condition:
    ($a0 and $a1)
}

rule sha3_384_hashed_default_creds_solution_6
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for solution_6. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="e4a9e91e5c0dce64649fff8efab71939d2b9e5a7678edffd19e48112a744e2fbd31884b37de34a7fc41739c338ee25b1"
    $a1="e387327804185c4445f0ba41fcdfedcd01179d13e62c12e764d8eac7dc04110f8e46ac4e6dcb893b3ca1567d7cc4e7b0"
condition:
    ($a0 and $a1)
}

rule sha3_512_hashed_default_creds_solution_6
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for solution_6. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="f6518719cabaf6268c008ecca3f39c166720d252b9b5053a8b37a7f40465222fd8485e122e27eb387894f52b913d7aa0a3b615fbd62fff573dbdf3ba381c7ef2"
    $a1="4c3e44ed00020f999f4e101a8d736f3dd95f0210a8c3ed784211bcb4e96384045fc27b0b53e428a26ac5f6751c22dd1a2f426d6c755f7c985eac3c653c2ca19b"
condition:
    ($a0 and $a1)
}

rule base64_hashed_default_creds_solution_6
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for solution_6. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="YWFh"
    $a1="b2Z0ZW4gYmxhbms="
condition:
    ($a0 and $a1)
}

