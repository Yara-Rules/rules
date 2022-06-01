/*This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as long as you use it under this license.*/

rule md5_hashed_default_creds_aris_mssql
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for aris_mssql. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="75a2fb70c26f37de2bd469ac98703a01"
    $a1="481a61707d893d2700fd9e67c2aafe3c"
condition:
    ($a0 and $a1)
}

rule sha1_hashed_default_creds_aris_mssql
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for aris_mssql. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="2adbb38ec9b652a57ac1d412b6d2ff4feaee1a35"
    $a1="01c144ecbaba83790efdfaf2aaa8c13bae8e598d"
condition:
    ($a0 and $a1)
}

rule sha384_hashed_default_creds_aris_mssql
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for aris_mssql. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="fa28e61969da6e2494626ef23f027def7420c27677afe91c5b9eabd3bdf5fe33c97c1de66cb6ad2d3584f111f3d43b21"
    $a1="8da2e51fde9d47294d76ed066f16d43f4c698cd5675f6ba39a5351e46e3748c4fb02c6625fd87cf7c92a3deb7c39dacd"
condition:
    ($a0 and $a1)
}

rule sha224_hashed_default_creds_aris_mssql
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for aris_mssql. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="5ef51c218947eb21691aaeaf7123beb3119aace025a324811d9e1fca"
    $a1="d3bd523474a5152bf38095d32240acacfaa75ffa420b2b460c5b40f8"
condition:
    ($a0 and $a1)
}

rule sha512_hashed_default_creds_aris_mssql
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for aris_mssql. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="f6e16adaef97f1a0856e11027a4cc5568605d91d31a64ce3766011f3d0d04e51194ac07197e34cd012eb27c238027756ee914c65b6c13ece5de8a79e104a2a32"
    $a1="3e6fab89ebb13868b5d85f327ad3ac8f23b1fd26a9f6b88fc6c3cb4820ba3dc97ca9531a6b3b08b95394b8780a831aea29bf3b1c5121963fa0229a3795d58db6"
condition:
    ($a0 and $a1)
}

rule sha256_hashed_default_creds_aris_mssql
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for aris_mssql. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="5eca455d5bc4c37e410c1571ef4eb9d784807e47e6a9ff52045ea8e94a92e306"
    $a1="8136ad3f558a1f498ae9e21abc15b24904c2e639728601294c2c5baa79d29f49"
condition:
    ($a0 and $a1)
}

rule blake2b_hashed_default_creds_aris_mssql
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for aris_mssql. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="3185a74b789650208d139696e3e42531715b421bc982ddd0b47f28bd1efdc812d0cc2f40b292ba630390ed200041b3c45dca8fa033fe204b3973a5eb8a763219"
    $a1="628f4adc600a551eda6068ad51654883a99c5aaa3a973bb2f6cd033bc5f8e2f866ac6ce598f1131f2f46580bbf6461f9cb813e3b9286dbf3c53da5a1961a624c"
condition:
    ($a0 and $a1)
}

rule blake2s_hashed_default_creds_aris_mssql
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for aris_mssql. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="889e03fc1b469bb6b8da41b0e4022928fbfc1d9d4d62f8c227f0858000044e20"
    $a1="e67a399e6e3ce0012e6da0e1e87fa9e422f7feea894dce8c0cee8a0ec17f69ee"
condition:
    ($a0 and $a1)
}

rule sha3_224_hashed_default_creds_aris_mssql
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for aris_mssql. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="d1c7e3c92532460637abf9f99ca5aa19f1eea0ea3b72fbd48928285d"
    $a1="6055b0490c127ad12a595551e7345a35d36d4b5073851f6014df53f0"
condition:
    ($a0 and $a1)
}

rule sha3_256_hashed_default_creds_aris_mssql
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for aris_mssql. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="d56b05e25e7c833134dee3c29ee3419260f286bbe95f397ec0ca1959ca1aa11e"
    $a1="8d9ca96277faedad9f5613442151e23f7b4ec373b11351cff19cf6baba39a654"
condition:
    ($a0 and $a1)
}

rule sha3_384_hashed_default_creds_aris_mssql
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for aris_mssql. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="3bce26b2ed0167d339470a48dd6152b09f241f0e404dffb8c7a0caedeb450caf96e8944769f4388645d685d7c08423f1"
    $a1="da3e70980cb2c13c83430cef527169ba38c148085f6ff80371126f7f7e8f961befe4569797684faf9ad9d99ce404ba3d"
condition:
    ($a0 and $a1)
}

rule sha3_512_hashed_default_creds_aris_mssql
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for aris_mssql. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="da51ef2b1b97b232805d160076014f9713007a95d5399b4fe765e158c6bf394f7f5786c708770b6062009bb99e8deffb294a668a1135a2f80a9aa66bc47f9b53"
    $a1="794ba3c101b035c39d559a0f2fcc9bdf84cbc9e7572e9c133bdea12417186c0f433a0404763b1c01fc8c3cd8de4452049de50e00b35b009fb259d2d1cb70f0a7"
condition:
    ($a0 and $a1)
}

rule base64_hashed_default_creds_aris_mssql
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for aris_mssql. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="QVJJUzk="
    $a1="KkFSSVMhMWRtOW4j"
condition:
    ($a0 and $a1)
}

