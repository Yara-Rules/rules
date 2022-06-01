/*This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as long as you use it under this license.*/

rule md5_hashed_default_creds_mentec
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for mentec. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="14cb593ad5e4233d8e92219001350821"
    $a1="38705ba532df108d65689745581c80ac"
condition:
    ($a0 and $a1)
}

rule sha1_hashed_default_creds_mentec
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for mentec. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="772fb595d325180bd952a01b8ef6a57d7d0fcbbe"
    $a1="64f2509e3816cc86d80429be424a431bff2d9e5d"
condition:
    ($a0 and $a1)
}

rule sha384_hashed_default_creds_mentec
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for mentec. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="531a9ebc5892bffcfe960b8d9aaccedd5a769125093014991f9fc013aec215c82439570c5449c8afb6c3bfe80474ef72"
    $a1="14a80bcb82e085a28b4f555a824f607761893ccf140bd48b4226862f27ebeed742f8025e83dae5bf3078d228efa5e9ea"
condition:
    ($a0 and $a1)
}

rule sha224_hashed_default_creds_mentec
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for mentec. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="83081668bcb1f3b2d26b1f989303cd6fe0dfd7ff53045f92d55c9fd5"
    $a1="54dad0bb829ff15eb1dc661e980f3b69d5791944eef9898fefd6e432"
condition:
    ($a0 and $a1)
}

rule sha512_hashed_default_creds_mentec
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for mentec. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="5cc61365b6a4bc604af55a81ac49d26c41a437b1f098d4c3085586cb586e5ab7ac8c691d09658c5c5b586f0a0b1bfcb883bf141ba2719f89c4518b672bf90c81"
    $a1="f184565468795cb530cc19cb510a9fe6307017052152a44ba5ddbe5858f00fd38aec6b0e414831522d938263f83ec1c23d41b956b637387d8714ceb4f85e8c37"
condition:
    ($a0 and $a1)
}

rule sha256_hashed_default_creds_mentec
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for mentec. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="e425556fafa738b9df7b1fca2ceba5dc2c72ae03583c49aed001b2fbde89492b"
    $a1="d1def82c7182125d9573f0d32fbaf0a335471783984709da526a26d167ff532a"
condition:
    ($a0 and $a1)
}

rule blake2b_hashed_default_creds_mentec
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for mentec. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="7c2fd17ca3ef62d2767d42b888c466048b1cd0228ff30e9f7fc76d70d504cf4463f63d2cd2f008c8a08ca3684a99211c41c9a8668f41e4d38b1581debc5a198c"
    $a1="886ea35aac3c6c96a8c6fc59ddc89cd44376cd0441cb4d4d1ae957858695280041298013612dafa508dbff7c29fe62f01ca072d6822b85d40d0200dfa1ad1a16"
condition:
    ($a0 and $a1)
}

rule blake2s_hashed_default_creds_mentec
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for mentec. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="fa0c39a1d1860925ea0e571a3a74e81d041d322ff8e8aceb420fd52e756365c9"
    $a1="5fa108f7c1494550c600e2f174bce4371173840e5376c20e0cd127372806c46e"
condition:
    ($a0 and $a1)
}

rule sha3_224_hashed_default_creds_mentec
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for mentec. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="deed3c24c32fd60689b89b4d782ed61b78d06248a38b1e3b1bece02f"
    $a1="43b7502f4464964c095a86aa5cd822719f9375c4967b762c48cc746d"
condition:
    ($a0 and $a1)
}

rule sha3_256_hashed_default_creds_mentec
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for mentec. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="6260d281ebd3b464cd9afc57e15810877b0504cd8713f879e9f704619f47f754"
    $a1="3d0c9a49420e92890a7a4f23faef8ed43c8be00cd272271d35ceb908580781a1"
condition:
    ($a0 and $a1)
}

rule sha3_384_hashed_default_creds_mentec
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for mentec. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="9fd252aa83354cb14c673589fbebdcbb1c37853c189e06563b2f60377473a488a7015f7d60257aefba580ab60a9c53c4"
    $a1="b11c68424e670d3d904291ce5b8321b3bc5b9dfd8f3376ac1d006d8b98f37e13099d2968705cc8c8ea37556c208e5ad3"
condition:
    ($a0 and $a1)
}

rule sha3_512_hashed_default_creds_mentec
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for mentec. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="7e522d39b21fa3d9b17108f158549cbe0761480df202ea73f3579c0751a9f7fe52b7c3d7cce6ff0604a33e85df3634b179d2fe665f131827602ef837e663aa27"
    $a1="2091216f5c8bfc962206f9135031bc011f3831f3651b1827c20357f238312fedd50d3a05a4a62fb8a1afc8847a38f0912bcec151c5a2a2e1f4552911a80ca46c"
condition:
    ($a0 and $a1)
}

rule base64_hashed_default_creds_mentec
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for mentec. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="TUlDUk8="
    $a1="UlNY"
condition:
    ($a0 and $a1)
}

