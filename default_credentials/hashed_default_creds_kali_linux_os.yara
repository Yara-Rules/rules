/*This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as long as you use it under this license.*/

rule md5_hashed_default_creds_kali_linux_os
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for kali_linux_os. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="d6ca3fd0c3a3b462ff2b83436dda495e"
    $a1="d6ca3fd0c3a3b462ff2b83436dda495e"
    $a2="63a9f0ea7bb98050796b649e85481845"
    $a3="7b24afc8bc80e548d66c4e7ff72171c5"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule sha1_hashed_default_creds_kali_linux_os
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for kali_linux_os. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="e7e971e55af10f713238780785ec5e63720509f0"
    $a1="e7e971e55af10f713238780785ec5e63720509f0"
    $a2="dc76e9f0c0006e8f919e0c515c66dbba3982f785"
    $a3="435b41068e8665513a20070c033b08b9c66e4332"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule sha384_hashed_default_creds_kali_linux_os
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for kali_linux_os. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="93b956ac57c87e7fbef0da72eb12bf7b14219e2c8d5f402d5429387de0410b01981b358da9b6219bd8002fc7c6dd3f8d"
    $a1="93b956ac57c87e7fbef0da72eb12bf7b14219e2c8d5f402d5429387de0410b01981b358da9b6219bd8002fc7c6dd3f8d"
    $a2="7ed8c2c790aa83d6c3e404b5368f6832c18d46a0e98b9c7a7a5e3ef823e2c9f0e310abbf6f7ea9d9d883ccb64ec2736a"
    $a3="a4f37384a08960b815d63acecfd8a0241d67cbe32db4d4f2d5c94760c107cdb9bb70ce81cdab41955c0f428af830e9c1"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule sha224_hashed_default_creds_kali_linux_os
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for kali_linux_os. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="118fbfd07d5d711e25007efd603d686047f69905b5e36db547720c6d"
    $a1="118fbfd07d5d711e25007efd603d686047f69905b5e36db547720c6d"
    $a2="871ce144069ea0816545f52f09cd135d1182262c3b235808fa5a3281"
    $a3="3e779dd776252527f0f7178bf00b49151ac85b6559bcdac4eb5eb514"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule sha512_hashed_default_creds_kali_linux_os
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for kali_linux_os. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="e5d7234d85b9b847d5cbcc7974bca2a82a0cf2bda7dc728d899370ba423275fcd3d7e47e83b87f1122968c3f7c823c6d6798ce91ef171baac51c41ce3739749d"
    $a1="e5d7234d85b9b847d5cbcc7974bca2a82a0cf2bda7dc728d899370ba423275fcd3d7e47e83b87f1122968c3f7c823c6d6798ce91ef171baac51c41ce3739749d"
    $a2="99adc231b045331e514a516b4b7680f588e3823213abe901738bc3ad67b2f6fcb3c64efb93d18002588d3ccc1a49efbae1ce20cb43df36b38651f11fa75678e8"
    $a3="2b64f2e3f9fee1942af9ff60d40aa5a719db33b8ba8dd4864bb4f11e25ca2bee00907de32a59429602336cac832c8f2eeff5177cc14c864dd116c8bf6ca5d9a9"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule sha256_hashed_default_creds_kali_linux_os
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for kali_linux_os. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="fc5669b52ce4e283ad1d5d182de88ff9faec6672bace84ac2ce4c083f54fe2bc"
    $a1="fc5669b52ce4e283ad1d5d182de88ff9faec6672bace84ac2ce4c083f54fe2bc"
    $a2="4813494d137e1631bba301d5acab6e7bb7aa74ce1185d456565ef51d737677b2"
    $a3="ce5ca673d13b36118d54a7cf13aeb0ca012383bf771e713421b4d1fd841f539a"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule blake2b_hashed_default_creds_kali_linux_os
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for kali_linux_os. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="1546bc4c13dd59a32ca1d372cbfd0f41cf2a5f08a7ffe53c46f441164b2e2f51898f5055de4fcdf326d26779f671e3b158981543f76e3b0038757f010d2e00fa"
    $a1="1546bc4c13dd59a32ca1d372cbfd0f41cf2a5f08a7ffe53c46f441164b2e2f51898f5055de4fcdf326d26779f671e3b158981543f76e3b0038757f010d2e00fa"
    $a2="da23f3a4e096b0816ec2070050eac6cd9243240dad0b5cde6573e41d6852939ac5468aa9d81b5fbe156feb231a069f5afe8a5146630abc7807b1e0dcdaeb049a"
    $a3="27e200a377873d0925cc1d01852f2e15bd7125da124b40c05ddb2d051ef7f20fbc4d7de79cc53e71e5733c4da2f3db58515fa112df1c67022aa3f2d91aff7413"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule blake2s_hashed_default_creds_kali_linux_os
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for kali_linux_os. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="213369a1b2277fa60f82f1339e9b20d3f062d9a22c236bfe644dfda0fec8670a"
    $a1="213369a1b2277fa60f82f1339e9b20d3f062d9a22c236bfe644dfda0fec8670a"
    $a2="0cb8a879dc5d94ed67eb49cc7a4d3052d6a346f2e28fcd9e10e5822aba92eb39"
    $a3="ef410e2762842f4c2bce465d7ebb2428b0cf82521424995f6ea41813f39f342e"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule sha3_224_hashed_default_creds_kali_linux_os
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for kali_linux_os. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="ad0d5bca596b15309b523076915d9fbcb0065f1de56180305c534089"
    $a1="ad0d5bca596b15309b523076915d9fbcb0065f1de56180305c534089"
    $a2="3e42295e89a3a84ce7ee38e2ba317aeb57ca3164459bdf48f4da0e92"
    $a3="c3ca50a128c23ca92e0209e50b70b374aec795064f8f331b6708aebf"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule sha3_256_hashed_default_creds_kali_linux_os
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for kali_linux_os. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="3aeffb032a51d224814e7c8d876ec433aae4ad44cd6362dc26b6b9cb750c7620"
    $a1="3aeffb032a51d224814e7c8d876ec433aae4ad44cd6362dc26b6b9cb750c7620"
    $a2="a00e4d3b352e9d11979549b9eef5dc951592f594488451e6cd86fdc4bce76a53"
    $a3="e5ead65714a14368b08263779941b023f2d991e97fc7e888752616f5da2fded6"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule sha3_384_hashed_default_creds_kali_linux_os
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for kali_linux_os. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="8cc25b22315e2bf0a311a67b097154bc9e3f7833c8e52da00f44141a67f1af8564bf5164cd8edcfbef3d407e8432e8ad"
    $a1="8cc25b22315e2bf0a311a67b097154bc9e3f7833c8e52da00f44141a67f1af8564bf5164cd8edcfbef3d407e8432e8ad"
    $a2="aac595410801e93eadb099ac575ccc12e43be2c15e31e7991e908329e5beb0729881b3be9ccdb0eeb6eb79335ea38b6d"
    $a3="a621bff9d75491dcffeb7b70227b7f2557edc8abc8afc56ddc495c1d69d54cbde78c4db85b0afd9c222cd834506e4cf9"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule sha3_512_hashed_default_creds_kali_linux_os
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for kali_linux_os. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="73efab342d5db69356a6f29739897ca187580b6ce27eda2ea4996a6d4decb4709ea167d9d18e53976c50fe2da1a8c39fc12b36a842b923c9289e059a3cf4b972"
    $a1="73efab342d5db69356a6f29739897ca187580b6ce27eda2ea4996a6d4decb4709ea167d9d18e53976c50fe2da1a8c39fc12b36a842b923c9289e059a3cf4b972"
    $a2="8cd824c700eb0c125fff40c8c185d14c5dfe7f32814afac079ba7c20d93bc3c082193243c420fed22ef2474fbb85880e7bc1ca772150a1f759f8ddebca77711f"
    $a3="17bbd4bd5bcf969ab5874e84d389d9d28f511529c08fd55f6f733f3a43a9609759e6c955ef7211751fb40ea61292b289c424638801b00b223589e49b14d27a1b"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule base64_hashed_default_creds_kali_linux_os
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for kali_linux_os. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="a2FsaQ=="
    $a1="a2FsaQ=="
    $a2="cm9vdA=="
    $a3="dG9vcg=="
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

