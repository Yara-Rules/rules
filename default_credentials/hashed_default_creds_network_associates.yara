/*This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as long as you use it under this license.*/

rule md5_hashed_default_creds_network_associates
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for network_associates. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="9d82d05cc097f966e26b0cb0bd6bbe2b"
    $a1="85d45488b210c628e0816f146eb809b4"
    $a2="f486c0003adcc21bf1ed25067e5a89e1"
    $a3="7e700a165df76746530903ba4f2922d9"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule sha1_hashed_default_creds_network_associates
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for network_associates. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="d5668af487c01ab83515c90eb3952a7f9677ebcf"
    $a1="8f3237e14a7beb1e3f598866a2f2959c7e11729f"
    $a2="821751d8ab4c6d75d927e7f092d55be896f7f67a"
    $a3="553b35f8e572aca9a6538d5d6e997aeb1411cb1a"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule sha384_hashed_default_creds_network_associates
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for network_associates. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="924ee7b4065b25d8a933997d230d78e41a1d68fcbd709cc6573eaf96cd5f74e9199e45044d0f945f66bd18f77a6e54f3"
    $a1="aff4e02f6a5694606ac6480196ee6cad61d37bce6bca1009e8a2c64bd78f01675e2ccc86e7f15a9ca86bf53ee8771cba"
    $a2="b5ff757b5f6ca9c2e392275181751242b55b930d475a36d7b4119e61e6568151aa6224e3d4f5b1f5e51e9673bfe54c57"
    $a3="fc628e4a904d3e0712eb453d27d05c26e32eed150ca2bc905dd622a49d96ab34d177a6d848112a83726e5f318c909bf8"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule sha224_hashed_default_creds_network_associates
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for network_associates. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="11ea23d09b816a812427c1a4dc9bcdc1badb7190d5f83f2f1c40a5de"
    $a1="6e3ee31716ea3ec3ff9de7ead99504b8edaff7b43b164d97cb5c3ff4"
    $a2="62a1b357b1265caa6d47ede4ea5000c79b0f91d1c7a8aa966d4f2e22"
    $a3="b41b098fb9ea6c277a4225c6de84ea684c916057f546e18fa40a539f"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule sha512_hashed_default_creds_network_associates
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for network_associates. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="cf3ed851c2bca5e3f7c807c68e5487d8cb54b450d901ff2ccd545abdabddb3f1e7da1b743612f08952cefeec1e79905057add52ff71cb08a5d4c8778921d8957"
    $a1="89f5654c35384d63975995b021eff8abe1f5e17fe6e7e87c15ccb316954ece3bb7738648781b2122021f3adeafc5369fe0f5d516f1fdedce2a88327c3dd09064"
    $a2="376217211b17c39bc42ab92e485775210533681ad7afbabb0600390862ba6e9dc2d41e9fdc49a00fe027752dc01237268069cb6f66970e5fdb8e0ed14847c3df"
    $a3="c0ae3eac8a741ba529d5302c3c897d31b6c4cc78daf72e57fb5d9bcb0a7860bed93d0406258f4341a4a38b7f11393ebc4e77550180cb1aa993565c33b8673fa7"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule sha256_hashed_default_creds_network_associates
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for network_associates. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="f877f677d9ec932532789bb16efa289aa29c004bb07bed121dd4de181eb5884b"
    $a1="3deaaf71e54e0692fdde0b26e9ffb7a4ee357f5c7109d582e41d9834d1e0d03b"
    $a2="41cac0aae7b9f4aa7610fd2c85382e16f53360625c0797c5f7de9bd1c2bfd590"
    $a3="f1789d72938e61d6c9ab1b1ef994c43bdbff5bfad2639c6ab9542e0b8ed49533"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule blake2b_hashed_default_creds_network_associates
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for network_associates. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="946ef07e9ab08014ece09632f9ac766ee6acc2a89df2339a7098c2d6578a5e9945ca094d7e1629fd736404c3e22995c63100f49f4826b27443fb000abac0f216"
    $a1="faf5a7207d91c00e038e8488c21936552e6550f9fdccab3a1fdd6b0d57ca01d2fdce73f14c95e6c79fe69ac1ed6e4ab6c1d293be4f1222bfa1d19aa2e901f443"
    $a2="d962358bd07f4410a4c23e17be89e07c8d8cf0797e53e27f2e4a72047bfe578ae6022fae203511f00e5db919451114a96ee64f304e1cb92c51e3fbaaa209017f"
    $a3="e119c1e54334cf65f157bb72f910fa9c13b373f2f1bb4617b78d310b93ebea97c2ff0fb6abf39d4490b94644529dd0156a322eab420ceda46a3515d117cbc902"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule blake2s_hashed_default_creds_network_associates
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for network_associates. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="ae97729b645f81a275ed811ed8b4f6c5e646c70b17d2b5f1f24c34cd80a7465e"
    $a1="48be87a5445f158975f2ef6fac329ca333eabe0f1afcdc327ab1a6c4ae417e9e"
    $a2="899874a085ecf026a11adafdeb61ec1db9dfefe1a8cf460f10fe3762702624f6"
    $a3="9fa465cfeca39e1e0ffd65d6e7bd4a5aed840a48c96127d05f7072623ad1a0e8"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule sha3_224_hashed_default_creds_network_associates
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for network_associates. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="3da3582dd4ed112902f255253013dbd0d2709fe9df3e6fc2072e98e2"
    $a1="4468a98fe96280279d0b3ef7ac856b628d9e937b314df7724b1c65f7"
    $a2="8b9d42039f175bec40f1abc6354e7da32e29d7205437f2d4428c56f0"
    $a3="b007c02d625965d6115fb4aa268f2b2e4196b4fb521959b8e392a76a"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule sha3_256_hashed_default_creds_network_associates
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for network_associates. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="bdf5c5032f5ea6152c984e035eb40c809440d77c4a89f1e00496e5309641137b"
    $a1="6f9c367574f0c9861cfc13a1389af7da4e47cd00a86be9ed29831e785f6f4ca9"
    $a2="cad5c7cd2f8efbc78365abcfec9e4ed1e8f86fca0fec6b5049065f338ab2ff38"
    $a3="fc9d4fe67296f4bf92b64708e437ac2072657fa417d3f9c771bcd3bcc5f67e17"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule sha3_384_hashed_default_creds_network_associates
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for network_associates. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="8501e5a3fed811600ebc2f02a626472f6a93adba63532101dfe050e2fed586529dfa00d36054024b84825e4759a2235c"
    $a1="a130ee831b24f499c4aa3a99a389e6c5e6eebe767d408591235c4a9a2e1c24f395056c3e46de95d9a1fb869492c4d5ca"
    $a2="aa5d8f5685d4f1fc9526a988e5c5a7dab2af1408c20fafe8ded016cbf66434f82610f1ec07531fa817e40727bfef2dfd"
    $a3="45d359ed93db161812ecaa3524e268d34204689d8a91e02b8bc406daae708652ca13362b952c67d75d136f845de6a34f"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule sha3_512_hashed_default_creds_network_associates
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for network_associates. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="67dbd1aeabd7e13817abee6bda3460715d1dd15e6a52098496617cf554f29ba4103dc675088c430a915a9f858dd0391834dc8b6122a100279c599f609905eeba"
    $a1="ab278665a311f812d0ebbb92f95de813cc87efab66f24e6fbfcb9e2a91b651811969b6604c9810be104adfa7de46491653af20d15e69b77d62310ca2569e4635"
    $a2="a7edafd8ef3c6d2238af6e6dd12c7ce7d88f6e4e8497a89675bd0e66e11d82e802f0b7f72d170c75168cd91c18cf8ac738187562b43234016cd1a2962f85e6ec"
    $a3="4e84f4ef7dad9f772ff78413fea586c65c972918ecbd3df4f183749a850d160ecffdc1199001a3df901f1191b377bb9db7bb2f81206f572c38d3f3c4fa82553d"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule base64_hashed_default_creds_network_associates
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for network_associates. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="ZTI1MA=="
    $a1="ZTI1MGNoYW5nZW1l"
    $a2="ZTUwMA=="
    $a3="ZTUwMGNoYW5nZW1l"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

