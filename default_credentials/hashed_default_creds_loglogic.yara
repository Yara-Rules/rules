/*This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as long as you use it under this license.*/

rule md5_hashed_default_creds_loglogic
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for loglogic. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="63a9f0ea7bb98050796b649e85481845"
    $a1="29b2080676f3716c6cdde7b14b2b47bd"
    $a2="7b24afc8bc80e548d66c4e7ff72171c5"
    $a3="29b2080676f3716c6cdde7b14b2b47bd"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule sha1_hashed_default_creds_loglogic
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for loglogic. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="dc76e9f0c0006e8f919e0c515c66dbba3982f785"
    $a1="545497203ac9b57e2d69d9e81577ee54558b9f48"
    $a2="435b41068e8665513a20070c033b08b9c66e4332"
    $a3="545497203ac9b57e2d69d9e81577ee54558b9f48"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule sha384_hashed_default_creds_loglogic
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for loglogic. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="7ed8c2c790aa83d6c3e404b5368f6832c18d46a0e98b9c7a7a5e3ef823e2c9f0e310abbf6f7ea9d9d883ccb64ec2736a"
    $a1="251cd026e76038b7eee4d4c2f4dc27956af4540e3aa93b9ca0902aa4ef758d3a84d241097ccd3ebf14c065d7f396f6f4"
    $a2="a4f37384a08960b815d63acecfd8a0241d67cbe32db4d4f2d5c94760c107cdb9bb70ce81cdab41955c0f428af830e9c1"
    $a3="251cd026e76038b7eee4d4c2f4dc27956af4540e3aa93b9ca0902aa4ef758d3a84d241097ccd3ebf14c065d7f396f6f4"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule sha224_hashed_default_creds_loglogic
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for loglogic. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="871ce144069ea0816545f52f09cd135d1182262c3b235808fa5a3281"
    $a1="ea296f64710b090f1016dbac77b820f57c6ee755a7a71f46bbb4b32f"
    $a2="3e779dd776252527f0f7178bf00b49151ac85b6559bcdac4eb5eb514"
    $a3="ea296f64710b090f1016dbac77b820f57c6ee755a7a71f46bbb4b32f"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule sha512_hashed_default_creds_loglogic
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for loglogic. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="99adc231b045331e514a516b4b7680f588e3823213abe901738bc3ad67b2f6fcb3c64efb93d18002588d3ccc1a49efbae1ce20cb43df36b38651f11fa75678e8"
    $a1="3f0b8dd3c30cadcc238fcc20a3fe601eda8203f9f708f1881dbcdcc85b0a9cc94f067c6f4e0ec2b2d8b75509624bcb764b9be677d1337d0d036f9eac4b06e7b5"
    $a2="2b64f2e3f9fee1942af9ff60d40aa5a719db33b8ba8dd4864bb4f11e25ca2bee00907de32a59429602336cac832c8f2eeff5177cc14c864dd116c8bf6ca5d9a9"
    $a3="3f0b8dd3c30cadcc238fcc20a3fe601eda8203f9f708f1881dbcdcc85b0a9cc94f067c6f4e0ec2b2d8b75509624bcb764b9be677d1337d0d036f9eac4b06e7b5"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule sha256_hashed_default_creds_loglogic
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for loglogic. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="4813494d137e1631bba301d5acab6e7bb7aa74ce1185d456565ef51d737677b2"
    $a1="fb5f7ec189d15b9959f548f2c96e84c93168d248de214f0fd63b237140b1bac2"
    $a2="ce5ca673d13b36118d54a7cf13aeb0ca012383bf771e713421b4d1fd841f539a"
    $a3="fb5f7ec189d15b9959f548f2c96e84c93168d248de214f0fd63b237140b1bac2"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule blake2b_hashed_default_creds_loglogic
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for loglogic. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="da23f3a4e096b0816ec2070050eac6cd9243240dad0b5cde6573e41d6852939ac5468aa9d81b5fbe156feb231a069f5afe8a5146630abc7807b1e0dcdaeb049a"
    $a1="e9033763effce1ecc8417e9666095dc3553b2b1c065341edb45c213931a83fadf073060c008560c2b3d45c9ded17dc7d0c94ed882baaf7746870af024fcac09b"
    $a2="27e200a377873d0925cc1d01852f2e15bd7125da124b40c05ddb2d051ef7f20fbc4d7de79cc53e71e5733c4da2f3db58515fa112df1c67022aa3f2d91aff7413"
    $a3="e9033763effce1ecc8417e9666095dc3553b2b1c065341edb45c213931a83fadf073060c008560c2b3d45c9ded17dc7d0c94ed882baaf7746870af024fcac09b"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule blake2s_hashed_default_creds_loglogic
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for loglogic. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="0cb8a879dc5d94ed67eb49cc7a4d3052d6a346f2e28fcd9e10e5822aba92eb39"
    $a1="b829912d3fb7849a324dddf0ddff60fd5e483ec6471d57173e0230a75bfd74d1"
    $a2="ef410e2762842f4c2bce465d7ebb2428b0cf82521424995f6ea41813f39f342e"
    $a3="b829912d3fb7849a324dddf0ddff60fd5e483ec6471d57173e0230a75bfd74d1"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule sha3_224_hashed_default_creds_loglogic
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for loglogic. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="3e42295e89a3a84ce7ee38e2ba317aeb57ca3164459bdf48f4da0e92"
    $a1="e3e0fb087598b01aa404c8c1bd26cb8e02d6fa2890bcc3bec768ebc2"
    $a2="c3ca50a128c23ca92e0209e50b70b374aec795064f8f331b6708aebf"
    $a3="e3e0fb087598b01aa404c8c1bd26cb8e02d6fa2890bcc3bec768ebc2"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule sha3_256_hashed_default_creds_loglogic
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for loglogic. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="a00e4d3b352e9d11979549b9eef5dc951592f594488451e6cd86fdc4bce76a53"
    $a1="8f34274e6958a224b0d93d89907ef357a8c17a9e2bd45bb52ca630e4db611ed8"
    $a2="e5ead65714a14368b08263779941b023f2d991e97fc7e888752616f5da2fded6"
    $a3="8f34274e6958a224b0d93d89907ef357a8c17a9e2bd45bb52ca630e4db611ed8"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule sha3_384_hashed_default_creds_loglogic
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for loglogic. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="aac595410801e93eadb099ac575ccc12e43be2c15e31e7991e908329e5beb0729881b3be9ccdb0eeb6eb79335ea38b6d"
    $a1="2a3fb3710f792dd9f7d03178d60510a11d388cc9e46ecb9e013ad7ba93f8f30446ffff2c9fc4daafd6dde827b35df1c4"
    $a2="a621bff9d75491dcffeb7b70227b7f2557edc8abc8afc56ddc495c1d69d54cbde78c4db85b0afd9c222cd834506e4cf9"
    $a3="2a3fb3710f792dd9f7d03178d60510a11d388cc9e46ecb9e013ad7ba93f8f30446ffff2c9fc4daafd6dde827b35df1c4"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule sha3_512_hashed_default_creds_loglogic
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for loglogic. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="8cd824c700eb0c125fff40c8c185d14c5dfe7f32814afac079ba7c20d93bc3c082193243c420fed22ef2474fbb85880e7bc1ca772150a1f759f8ddebca77711f"
    $a1="ca0661fca915c10e6a55a4ac5b4c4ba678ae36e38786ba533c1a90eafd8d1a6cdbc0e0078bf90395ba4cfa3f9931d49bb3aa5504588a10038ac3b54c210079e1"
    $a2="17bbd4bd5bcf969ab5874e84d389d9d28f511529c08fd55f6f733f3a43a9609759e6c955ef7211751fb40ea61292b289c424638801b00b223589e49b14d27a1b"
    $a3="ca0661fca915c10e6a55a4ac5b4c4ba678ae36e38786ba533c1a90eafd8d1a6cdbc0e0078bf90395ba4cfa3f9931d49bb3aa5504588a10038ac3b54c210079e1"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule base64_hashed_default_creds_loglogic
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for loglogic. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="cm9vdA=="
    $a1="bG9nYXBw"
    $a2="dG9vcg=="
    $a3="bG9nYXBw"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

