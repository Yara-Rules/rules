/*This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as long as you use it under this license.*/

rule md5_hashed_default_creds_episd
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for episd. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="df53ca268240ca76670c8566ee54568a"
    $a1="9ab776b93b3c6bbb67f4545371814423"
condition:
    ($a0 and $a1)
}

rule sha1_hashed_default_creds_episd
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for episd. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="c60266a8adad2f8ee67d793b4fd3fd0ffd73cc61"
    $a1="e8a7d6f2bc4132a0f764d5e084371ff67d21a516"
condition:
    ($a0 and $a1)
}

rule sha384_hashed_default_creds_episd
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for episd. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="dbaf470e968c60a318904e61145c6e4c18be449fc891661a7445f852194f48e413c8a170ba27fc89ae4680a93aaf3fef"
    $a1="2d19c666186eb160ee654293a743256ccb20d0897888d7d4dcb6a2968652220fa192686d1381d9bb19ee556030e7f6c0"
condition:
    ($a0 and $a1)
}

rule sha224_hashed_default_creds_episd
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for episd. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="00aea1ea2d7e2f8ed62b68883f7be17ba58145a070e1c82d954eaf6b"
    $a1="31b7d4391e3c3baee2f06d45fa50ff36c622bcf17d34f183deae307d"
condition:
    ($a0 and $a1)
}

rule sha512_hashed_default_creds_episd
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for episd. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="922d076069b1df893fc010b7a6d2aa55c7c4c5d194f163394a4c864de5754131c17bfa94ac1667f56b5181cc7eca5dc3a09444caee6eecf16114926bb29f7e79"
    $a1="be843b8d5b590eb0ed4351404aed9187a24acff292fc299bc2a8c5e4c2f42596de7d90b105621cde3d48b5e0431724bd2df4fb36f5d0dc112e297da46104d073"
condition:
    ($a0 and $a1)
}

rule sha256_hashed_default_creds_episd
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for episd. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="aa97302150fce811425cd84537028a5afbe37e3f1362ad45a51d467e17afdc9c"
    $a1="a1a14ff4aab4f1d3efbe2f3fe8e32ec686289ba95e5b2fc3e1f38052d64da522"
condition:
    ($a0 and $a1)
}

rule blake2b_hashed_default_creds_episd
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for episd. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="824e069b4a2ac4f916680961c9b3630f402bb64e07a17a999dd560d0c026288282504c5d952bc98c87cd19d59ac9b65a2e3865676bc434cf5925be68c6da0134"
    $a1="c5a1796a4955552f5c7efa62253814339cd06c1fb48bfaf55450a2024514fd974e7b2899b7ff971ecef0557aeb2ccb3421214ffd40aecea0caca4fb9fda1bee1"
condition:
    ($a0 and $a1)
}

rule blake2s_hashed_default_creds_episd
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for episd. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="89db98a21af3715f3707917d07cb76d66e39c908e4e34d3a88dfa0dd60739e7c"
    $a1="a978436268c07b66b548ca889e1b0595873fe4677bea3b846bbc3dc8292bc734"
condition:
    ($a0 and $a1)
}

rule sha3_224_hashed_default_creds_episd
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for episd. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="19c2c6515bd63f05d668b5adadbffcfab9993518fd472f2da730e809"
    $a1="8089ced613c8ede09cb1bf48f9de39e3b42f54accb77410cce430328"
condition:
    ($a0 and $a1)
}

rule sha3_256_hashed_default_creds_episd
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for episd. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="277fa848e714c1fa61b2339613951295c4d1e5b328de803202c95fc4d715b561"
    $a1="1e280f79cd35f136820a5143ba05e8c961cfdcd0ccd16114c2fba6ccfa85f66b"
condition:
    ($a0 and $a1)
}

rule sha3_384_hashed_default_creds_episd
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for episd. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="2389b739ae11f7303b554d59da4b58427e4be308a00d9649cbb28901d6a64b709e12a22725afa934d4b3d0e81f281e71"
    $a1="e966fea393df6f2218d5a91c2b7d09ad3a569c43c7221e6895fbbcb4e8a19e4c9e948218ebca2ddacb0c829ba0278c8b"
condition:
    ($a0 and $a1)
}

rule sha3_512_hashed_default_creds_episd
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for episd. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="3716d757f739c14ea17a89ee7ec9a73ab3e54674b885e717064591986fb8cee9eeb48f07f60df3ca48c2a81b1bddc242388d2d8069f13600ec91b30942e5d89f"
    $a1="c6e84f348796b56cb8d9fe545549e509aa37e6cc3d0d2ba3c72255c76874b0520532bdc9961facf0fc3fba972310736e0accb0890ab041a5f32665f8aede7317"
condition:
    ($a0 and $a1)
}

rule base64_hashed_default_creds_episd
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for episd. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="Y29tcHV0ZXI="
    $a1="cmVwYWly"
condition:
    ($a0 and $a1)
}

