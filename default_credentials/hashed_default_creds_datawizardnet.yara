/*This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as long as you use it under this license.*/

rule md5_hashed_default_creds_datawizardnet
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for datawizardnet. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="294de3557d9d00b3d2d8a1e6aab028cf"
    $a1="100b8cad7cf2a56f6df78f171f97a1ec"
    $a2="294de3557d9d00b3d2d8a1e6aab028cf"
    $a3="6d76c441e7b50697b1cd21714d233fd8"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule sha1_hashed_default_creds_datawizardnet
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for datawizardnet. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="0a92fab3230134cca6eadd9898325b9b2ae67998"
    $a1="c5fe0200d1c7a5139bd18fd22268c4ca8bf45e90"
    $a2="0a92fab3230134cca6eadd9898325b9b2ae67998"
    $a3="a07ef5ebc409e10540a4f4a572d31493126bc149"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule sha384_hashed_default_creds_datawizardnet
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for datawizardnet. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="7f9d109c4c8b04efd32a69140fbfc75a48e0be4adb2f8aef8798aa549c6ae1c878150333071246b29f52b821aa511e97"
    $a1="da39e337d7aca91516ebc4d0c96f3549c15be792df607f1cf5885ad30910c19a69743b873e409b54e6b8bcc9db829a3c"
    $a2="7f9d109c4c8b04efd32a69140fbfc75a48e0be4adb2f8aef8798aa549c6ae1c878150333071246b29f52b821aa511e97"
    $a3="b11a42689ec58f04c80132d9e1bc00269f67ec57f61f95ed937b3d53196b2da17648d67e466e1453d23bfc96398b26f4"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule sha224_hashed_default_creds_datawizardnet
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for datawizardnet. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="2ce11767207a153185b411fb5cd2d3cee0c35a954aa59a1511beed1d"
    $a1="904e1dfdd115698ca60d626134dd92d5f3362df3cd4bcf8fde0501de"
    $a2="2ce11767207a153185b411fb5cd2d3cee0c35a954aa59a1511beed1d"
    $a3="90155d3dfe0beb7689fa60dced7f07844014b60d9c86f36c180fe5a3"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule sha512_hashed_default_creds_datawizardnet
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for datawizardnet. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="b67f71a782accc6e99740fb4d0295572d81c9a15f8e9e24174e0d1a2a1cee7435d1a99833490983eaba65c68022122bcea002e29fb8d76716e97db79741819dc"
    $a1="40d380d92f53ad12cf2194596874a9179f1ee3f92e8f7c994bf94db3291abb89c3ff351ed2b91130157fc7d32f842ced4b998a9de6e0e01d987a28d96934e6cc"
    $a2="b67f71a782accc6e99740fb4d0295572d81c9a15f8e9e24174e0d1a2a1cee7435d1a99833490983eaba65c68022122bcea002e29fb8d76716e97db79741819dc"
    $a3="f6153cb5cdd386d53707c3bd2c0c68421a9a0f1358fcc0b927cb35cd8351fe6a3e7fda09671f5bcc1aec03907f2bbba8d1e7af158f20a2c1340aa0e8be5ceffd"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule sha256_hashed_default_creds_datawizardnet
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for datawizardnet. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="2f183a4e64493af3f377f745eda502363cd3e7ef6e4d266d444758de0a85fcc8"
    $a1="d6a7cd2a7371b1a15d543196979ff74fdb027023ebf187d5d329be11055c77fd"
    $a2="2f183a4e64493af3f377f745eda502363cd3e7ef6e4d266d444758de0a85fcc8"
    $a3="30eaa4e621d188cd12f986718055ac1990811f46ca16760abc5fb4e31a6cd2f9"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule blake2b_hashed_default_creds_datawizardnet
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for datawizardnet. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="ac90bf4db023d0c5a9344ec19a9f3da5cda88de709f402502bd549511a544e22747913c49d5f296cfc98762bae191c6bb3f7f406efc6c246fc8c0e12d0b279a8"
    $a1="9d0cdc80d29977b52125ac1e933f95e8d41e0de299291e4e2d8659883dd1f3b7d15c4d4422433259bbaab04eb2021d8d83d79f02fed263509b1df6eff0e1c726"
    $a2="ac90bf4db023d0c5a9344ec19a9f3da5cda88de709f402502bd549511a544e22747913c49d5f296cfc98762bae191c6bb3f7f406efc6c246fc8c0e12d0b279a8"
    $a3="1f712995205f25355869b6aaba277ef26e231f6473c22d0292fae013a158f157af2a3527f87ba0be2ed08ecdacda5f503246a91291a6cd2f9ec7df407dd1b5c8"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule blake2s_hashed_default_creds_datawizardnet
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for datawizardnet. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="e06f7374ab7dc222d4086d9afc52ba24ddc4ac30018b423a2356ac6eb9fddaff"
    $a1="73baba47b79bb83663182e7d9bfcdf5e4ce5c7812d7d91995b704d01a29e0b5d"
    $a2="e06f7374ab7dc222d4086d9afc52ba24ddc4ac30018b423a2356ac6eb9fddaff"
    $a3="acb922de250d529a9d65d59ce9ffe60197342b522d8d181f94e82d82f16ff53b"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule sha3_224_hashed_default_creds_datawizardnet
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for datawizardnet. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="290cebb49aa996b5f19244127e2c0253710bfb405ac5bf89c539e07b"
    $a1="1b80ba673a959ff153aa35c0bcf7bbc66aee780c7680fbb15a445c3a"
    $a2="290cebb49aa996b5f19244127e2c0253710bfb405ac5bf89c539e07b"
    $a3="6bbf6d1d88b83d947de2db6432cf00c63086a94df29e86744db20e0e"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule sha3_256_hashed_default_creds_datawizardnet
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for datawizardnet. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="36e7a2865de35667ff62ee2b3c9135f8352a421a710f247ac927ebd11eff4393"
    $a1="7798f5d064ee771c317e429a5e947ea61afa61a9071c4c0a4abac29ed8a83947"
    $a2="36e7a2865de35667ff62ee2b3c9135f8352a421a710f247ac927ebd11eff4393"
    $a3="b22e4b311f68689da4a81cfb0d075ab0eec06aedcc32cbef03ec1fda66401850"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule sha3_384_hashed_default_creds_datawizardnet
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for datawizardnet. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="3bad431ae955a326af10fdce3efb08932e403c5a8be7befa9e02903b12860296660817a88fe0cb3be1d0371532fac4be"
    $a1="29bbaaf5bb4833d1ee99731dd706c7564d545323dc38077324710346b47c672f6cd95b095b2ab146106b26250aa52eb8"
    $a2="3bad431ae955a326af10fdce3efb08932e403c5a8be7befa9e02903b12860296660817a88fe0cb3be1d0371532fac4be"
    $a3="d8515cb06235da20af87c4f5bda3c5370d04368e323b7fcfae33419f1d173e4d92f4491596e8607481e15a3bbdb370b5"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule sha3_512_hashed_default_creds_datawizardnet
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for datawizardnet. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="40bd2966cd3cbaa13a0a32a668619531d52702e98c298513f81fe205b941a45fc3515ed296ef55a67808a85d7289430dc79a11c71d23ce0613a2f7e5032e0b9c"
    $a1="6b6c2518fc56046954105459797b70438cc08402f8d6eef226fc8f020a2455cf1d82d399252a237846cb6e72215e1168372d99fc54618321ca44838b1705c63b"
    $a2="40bd2966cd3cbaa13a0a32a668619531d52702e98c298513f81fe205b941a45fc3515ed296ef55a67808a85d7289430dc79a11c71d23ce0613a2f7e5032e0b9c"
    $a3="58b1d2774616992212b71e58dc4e5c4662012d9f40cefd193e3b3cffedd312595c3a7cc4c2fcc6d98a2501bd49f658b3276740455787bfa109a4ea29fe2ddc86"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule base64_hashed_default_creds_datawizardnet
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for datawizardnet. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="YW5vbnltb3Vz"
    $a1="YW55"
    $a2="YW5vbnltb3Vz"
    $a3="YW55QA=="
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

