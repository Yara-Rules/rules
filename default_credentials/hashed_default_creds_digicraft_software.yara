/*This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as long as you use it under this license.*/

rule md5_hashed_default_creds_digicraft_software
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for digicraft_software. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="191e854eb00dbd804fa1fed83b373be7"
    $a1="bfd59291e825b5f2bbf1eb76569f8fe7"
condition:
    ($a0 and $a1)
}

rule sha1_hashed_default_creds_digicraft_software
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for digicraft_software. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="a28f5a8167c0602b461f6f11afebc3c08998b421"
    $a1="2891baceeef1652ee698294da0e71ba78a2a4064"
condition:
    ($a0 and $a1)
}

rule sha384_hashed_default_creds_digicraft_software
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for digicraft_software. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="516ae2219d76b409c936cdb312451d9e282159a992dd03db87e2e094c2d09feef70cf71c008e95f4ade6153e931719b0"
    $a1="ffb4dbde5c617f19891aaa842ec0b501dc59eb65c13ee0a0a9bb7857d044699692461a6e1991fa24483d6f21f7a573c1"
condition:
    ($a0 and $a1)
}

rule sha224_hashed_default_creds_digicraft_software
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for digicraft_software. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="4eeaf9da68e49e7f07c591625d939b7026ef96599988c16133c29389"
    $a1="38b388bf3e29c3feab3c7be6832061809086cf172d333dccb1e88b2a"
condition:
    ($a0 and $a1)
}

rule sha512_hashed_default_creds_digicraft_software
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for digicraft_software. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="99f36316b624228c009f15d482ccbd4bf8a6c9ab0fe04965187d96d411c3ab2b135c52fdb298b10a54ade1cd4f758a547242ef53b7d19467a46f708fd8b290dc"
    $a1="81fbf929a6196fae3564d34457b0f2f74345786f9fc3a762039f57e8d47f5f8a612e61a96f33ee165414de36e7ab0d2615667a7636ae5d598b5afb25ce87c0b4"
condition:
    ($a0 and $a1)
}

rule sha256_hashed_default_creds_digicraft_software
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for digicraft_software. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="dfbb2ff38689713c43a078485eaf6ddb34c0a1d9e5f774d1b06f7c0ebead7e60"
    $a1="54d5cb2d332dbdb4850293caae4559ce88b65163f1ea5d4e4b3ac49d772ded14"
condition:
    ($a0 and $a1)
}

rule blake2b_hashed_default_creds_digicraft_software
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for digicraft_software. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="6e93a4726000feeafd62bac1d9ffdbff801dbb19105f93928165b0bb686dbe4f9dc857920cc0a9c80cf98992ad485c5fa5ec2e0190356c10f689b0cc547249be"
    $a1="7f82be8f37360380ea46cb18b230adf21dda1c5213bffd904f89dd09d4d8d7b0b8b2b29b7263ccb54c71e5f0b74c94b16cb01b273754a63ee136f1608bda7896"
condition:
    ($a0 and $a1)
}

rule blake2s_hashed_default_creds_digicraft_software
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for digicraft_software. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="1fb0f8f465816ecc563bfcdd9b241efefe9fd6d03adce135db7b13f2da9947f6"
    $a1="9ab98a6e4ddfe395155a107b4474cc81c8ff27e334e8e2a8319290c938ecbdcf"
condition:
    ($a0 and $a1)
}

rule sha3_224_hashed_default_creds_digicraft_software
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for digicraft_software. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="79a55f9e8e8400d2dafb3ebe75f63688984635d133a7148a78b9bb06"
    $a1="95dde9344286ad899ba443825e96788c45598474090f1e15e8e05292"
condition:
    ($a0 and $a1)
}

rule sha3_256_hashed_default_creds_digicraft_software
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for digicraft_software. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="f7266b98396e2bfe8e44de46d72bb3d3b86ee3d5e6fb7fff9d89f980ac664598"
    $a1="017f703e717fa5c2313cb2cefd06faf8afb31a0a79f75ab3959b354aafd8732a"
condition:
    ($a0 and $a1)
}

rule sha3_384_hashed_default_creds_digicraft_software
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for digicraft_software. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="40a1f312227d75d654ad1c94bb8dd124c47a854ba35ba082885180e31f67760fa4e152c10bdfb838101a04b6cc9f35eb"
    $a1="db71b81ee66ca19c04e7b1804d1dad4e31ad0f3dab39c01753305fb12d28e8572388deeed7b1f1b898ef3c418942f676"
condition:
    ($a0 and $a1)
}

rule sha3_512_hashed_default_creds_digicraft_software
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for digicraft_software. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="ea2075ec83ffbce8a318373ee69e45720fc5870a00ed697489ab4557202338c4595840f5b864cebf3331398ff6d3da143456b22a886530a472d75871caf08ecc"
    $a1="d93817071b62f94cbcd35d060ab3aa44c76910e96d25da18043dda006035827c98cd53eea944760af8970913c1aba72697008928cd1dfc4e314d30c3f613cb1e"
condition:
    ($a0 and $a1)
}

rule base64_hashed_default_creds_digicraft_software
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for digicraft_software. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="WWFr"
    $a1="YXNkMTIz"
condition:
    ($a0 and $a1)
}

