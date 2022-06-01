/*This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as long as you use it under this license.*/

rule md5_hashed_default_creds_aspect
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for aspect. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="91ec1f9324753048c0096d036a694f86"
    $a1="d41d8cd98f00b204e9800998ecf8427e"
    $a2="1a18949f92444ce850965bb2d91066fc"
    $a3="5649b1aecae442676812575f584843b9"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule sha1_hashed_default_creds_aspect
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for aspect. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="b39f008e318efd2bb988d724a161b61c6909677f"
    $a1="da39a3ee5e6b4b0d3255bfef95601890afd80709"
    $a2="07bcf4b1b99943c95fb77f60ce1cabbcb88cc005"
    $a3="9a72475bb7479c142f8faf235af3db111cb447a3"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule sha384_hashed_default_creds_aspect
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for aspect. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="b50a8bc3fcca76f6f0d1318954ec5b25b22f4694c9889e1dd7f47adda22a0e6b4d908bb453cd16091bd0ef5cdeeb4244"
    $a1="38b060a751ac96384cd9327eb1b1e36a21fdb71114be07434c0cc7bf63f6e1da274edebfe76f65fbd51ad2f14898b95b"
    $a2="53b85072d746d6436f988e6dd79617edfb83ce678d900efe95c64cf4f5706a17d57cdc5dd71b5979d51e5379e4f20323"
    $a3="19ea73c1d4b4071f2eafba548e5d49c07bcc678f6c20735f5ab4158b32ce5bd16137b11f762b77fbf07c5468b8f29fda"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule sha224_hashed_default_creds_aspect
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for aspect. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="551d8c9437f4f41e023c875243726b3c4ec8a8fd7c6c49d96d3dd478"
    $a1="d14a028c2a3a2bc9476102bb288234c415a2b01f828ea62ac5b3e42f"
    $a2="5c32ed64506aa528c8e6624e654f0c9a2807f1b886adf9bad383aad2"
    $a3="ef66d39313e803486363a6b0116754fe4814d41fd346fdc6ee1ddc19"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule sha512_hashed_default_creds_aspect
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for aspect. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="154e75fd96b7267f1c852159dccbf194b8c45720e3b6ef3f3d192d731cb8ff03dedc20eec18f28085ab3e3dc3e5b402bd4a67e3174b8cd85fa519c68aac2cade"
    $a1="cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e"
    $a2="cb227f47afe814cab9c9d019a8613751d1bd25eafe152afed284e118b58b0078a8c49f0bb7fe912f381c55f257bd8b4ef6bec4b5256cf9ccb8f107cec23e88cc"
    $a3="c71ecac0817cb2e13de19fe11b79bb6c2b6f0febc3b1656205275f691c01b8c0e6ef9a70f8dafc56e4516fab16e519cdcceee3d58e7214de34df35cf436f343a"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule sha256_hashed_default_creds_aspect
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for aspect. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="b6c45863875e34487ca3c155ed145efe12a74581e27befec5aa661b8ee8ca6dd"
    $a1="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    $a2="19924fa90248276110c813dcc2420accc205e63debb765fe5481a32d3611ffb4"
    $a3="4afb4c1859fd78ec03112d82ea605089c78f7fe350ff098fe1f22596b889eaed"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule blake2b_hashed_default_creds_aspect
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for aspect. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="85c512a6e2876ee47d4af6b74dba6d3ffc45f3b49ceb1c655c6921febb2f4c8958e3ea36fb916eb9e460812bd0603a76c689c635e6de4bc79f58eaadf1e311b2"
    $a1="786a02f742015903c6c6fd852552d272912f4740e15847618a86e217f71f5419d25e1031afee585313896444934eb04b903a685b1448b755d56f701afe9be2ce"
    $a2="0a108d5bcebe7fbce3ebe0ed5a1cf0066b0334afa9dbbfad9786ace5c39fc991f1cd60276777ef57d33ca994dc9e28c78274e17d5a1aaa89d01e5c5c808cd37a"
    $a3="4750d18fe9450fed836299927b5501d108a3eb413826946f50db42fd06b2845854d7ad19063dd9f8cd544119e7fe6fecfc2bfec593698066c1c91749da467c9b"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule blake2s_hashed_default_creds_aspect
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for aspect. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="36b1ab340a77ef63e27b102918b6238e97f358b90410fef9cada658f35a484d0"
    $a1="69217a3079908094e11121d042354a7c1f55b6482ca1a51e1b250dfd1ed0eef9"
    $a2="c3e499629f8208dc87b465bdb21682f66751ce949cc3ce7a2095694c0fa77960"
    $a3="0a01466987d9c7e8f019ca34ef0f1bd429625552a2fd151021b84cca58cd67fe"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule sha3_224_hashed_default_creds_aspect
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for aspect. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="5e08d05c5fdf28eb27d60db00dd60eaf13d08d01893fe13d720e4665"
    $a1="6b4e03423667dbb73b6e15454f0eb1abd4597f9a1b078e3f5b5a6bc7"
    $a2="c2fe3bf982847e3ddd1367530fbf855e8a9c43621783d172fd2ff2d2"
    $a3="634c2f94abf7af46ed1bd91e0d9232c19a4377f841926e2a9593a641"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule sha3_256_hashed_default_creds_aspect
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for aspect. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="01b2fd6e06f20c8908e45fcf88a8d15c42af3679aa10791a6053b401b4de3a70"
    $a1="a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a"
    $a2="e65f6a6be44d4eeed68fec04b7d9be433afc1fd0591e42a280f520b177f9532c"
    $a3="313befa3dd5d8b2606045245fe48492706bbe14c7a4b846305f242e6c6d59e3c"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule sha3_384_hashed_default_creds_aspect
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for aspect. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="0cf6f78d27589c1847089b2bdbaef0e3546ebd7d8fc48dd0f0c74594d3af7a2527e4465b5fb90304d9fa38190130f865"
    $a1="0c63a75b845e4f7d01107d852e4c2485c51a50aaaa94fc61995e71bbee983a2ac3713831264adb47fb6bd1e058d5f004"
    $a2="4c21117ec7e9dd46365ea0da5f068289c985f8c56f68b35870efe30878944aeffc18d29ca5bc804ae231191a8ef5ae9c"
    $a3="3b0f9e5c2f7266a20e793bc00d82c28adc1ff5c3b903f81ec057cf6a613624b56e759fad9468aa16cf61d203179e54da"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule sha3_512_hashed_default_creds_aspect
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for aspect. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="a5a00632f3795d0d2da20e131fdbe281943b3867d1142c188fcc53d1b11cc58e6653227d5eceb895dacded97e4804aa9d2e8771e117f1893ce5387f139b12b0e"
    $a1="a69f73cca23a9ac5c8b567dc185a756e97c982164fe25859e0d1dcc1475c80a615b2123af1f5f94c11e3e9402c3ac558f500199d95b6d3e301758586281dcd26"
    $a2="d4ddffe7e3cbeb7e980e98e15537dc5913aed29df5c2aee851671e29060eea07856526665092097db9e1db12cb0c7a3680d7f48ea1eb51eb11a039add5259cb4"
    $a3="f318fcacb18e3f9830c1e965eb4ce3066d7aa4a86620bdeca6bcd53bea99c6676645d9e4aaf860cef4d7abbcc1c07d982091fbf6c5b5835e8a308bbf589e452a"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule base64_hashed_default_creds_aspect
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for aspect. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="Y3VzdG9tZXI="
    $a1="===="
    $a2="RFRB"
    $a3="VEpN"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

