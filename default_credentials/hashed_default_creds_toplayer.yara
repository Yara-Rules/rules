/*This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as long as you use it under this license.*/

rule md5_hashed_default_creds_toplayer
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for toplayer. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="6f3cac6213ffceee27cc85414f458caa"
    $a1="fe507524ab04c298639474f3842425cf"
condition:
    ($a0 and $a1)
}

rule sha1_hashed_default_creds_toplayer
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for toplayer. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="e74d23e1dc81a4940393c22973763cf7ddb95f08"
    $a1="d7b61954a6a4811249bcf3012c556839d638862c"
condition:
    ($a0 and $a1)
}

rule sha384_hashed_default_creds_toplayer
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for toplayer. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="435b65d39d2507f4e923e6de7efd729e361293351025e458e06d2bbbacf7260ecc7a5623d84e36eecab0af1238fb786a"
    $a1="88fe00cc7a1ea381a17e7f76fc1dc8bc52594bf5b7155aafb35410f015f1a9aaf471b3e11be0302fcb3e3af409f9a655"
condition:
    ($a0 and $a1)
}

rule sha224_hashed_default_creds_toplayer
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for toplayer. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="19e44e0486c72a88c0bc2053dd530e4d82913b6aa1da9e10ef6340a4"
    $a1="fb97fd1a7c0a206965223185cf1a1affdd01ff52279a98457dac8693"
condition:
    ($a0 and $a1)
}

rule sha512_hashed_default_creds_toplayer
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for toplayer. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="8cb396a3bc1acf6ede3397050437ffcf4b18dc0a26b75e67d257be5431eed904151ac118e687f3fe42438794106136ca7047b6d2a2f271054a44528432184ded"
    $a1="bfe22dcd5b3f9fb745c406374feb9a5af60fab038165539c7c44700928e075cf6d54cfb8fd3b0a16d0a25c7d68988a4f242da7e08429066197a7fd1c7bb38e54"
condition:
    ($a0 and $a1)
}

rule sha256_hashed_default_creds_toplayer
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for toplayer. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="4b4d84a924bee4381c8cba1badfe3aa96cd7746ec02e36f862fab18caf42dafc"
    $a1="67c942383e477c55d6843d10cdde5494601c53e060966dd95a1dfd7930a74a00"
condition:
    ($a0 and $a1)
}

rule blake2b_hashed_default_creds_toplayer
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for toplayer. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="b545816449da80858876774b3b4c2a7ff96b033303aee0159cff6ef46acd8f5c4293304ce736d98754f03e737075200087738cbb5aedec1d8bfd457ca653761f"
    $a1="c8e38b2eafef907f27a1a4202b4b8a4be3c50a4fc4e9f52099cdf14f07ca7e97df599993bcd3a6168916360247c4d5a42b2772b82438cdbfda86184c9d33b8a1"
condition:
    ($a0 and $a1)
}

rule blake2s_hashed_default_creds_toplayer
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for toplayer. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="cd6174dabe77c06c69b54be3835b567510f8864605b6b1a5498a4c9ca211faaa"
    $a1="75c856f8dafea2efdd289bd1899bb0ead16d3046755cadf0bd7b4d5ed84004e4"
condition:
    ($a0 and $a1)
}

rule sha3_224_hashed_default_creds_toplayer
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for toplayer. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="7107183828f71b28d0c6d450ba993db247b38d2ac71f9f78a628de6e"
    $a1="90b9dfc1a34e0b1db29cb4cece660fd8edc9af9ec2129734e3c0dd50"
condition:
    ($a0 and $a1)
}

rule sha3_256_hashed_default_creds_toplayer
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for toplayer. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="25681be0e935280e34e345c5dc9132119842edce53abd47c516039e7da581c3e"
    $a1="bb67652b485bf3df26bbac9cb24b281ba5670ddce7c3707b0eadc1fb26a15dce"
condition:
    ($a0 and $a1)
}

rule sha3_384_hashed_default_creds_toplayer
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for toplayer. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="eb4bb1f4042e76b51e80dfaeb0d4d1d715fe9e7d3b61d97417df67deb643d809e45700b08540403fcb70ab1821492b3f"
    $a1="f3ac5428e5ab29e39a3a13e23348a5c7710ab5e94247386def74f64c861b917927b3d30190416561965ed47e0cf6624f"
condition:
    ($a0 and $a1)
}

rule sha3_512_hashed_default_creds_toplayer
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for toplayer. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="15bdaebc5c86f9bfb3a73a77ccb557874bd5f81c1e01a28c5f366486353039c00f755183b4f02a99cd3ba3873ebdb1295cc9b504121ae4be692af15dad883e16"
    $a1="5cab65850a63a4a7e6a1758f135b640d198751ef45d61757237e0cab56ed38de8a3f384c5b9847ef345936a84a921d1d2023d8605b9c445c6277cc95e207769a"
condition:
    ($a0 and $a1)
}

rule base64_hashed_default_creds_toplayer
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for toplayer. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="c2l0ZWFkbWlu"
    $a1="dG9wbGF5ZXI="
condition:
    ($a0 and $a1)
}

