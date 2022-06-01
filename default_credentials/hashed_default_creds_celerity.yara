/*This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as long as you use it under this license.*/

rule md5_hashed_default_creds_celerity
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for celerity. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="cc69f666c4058c656acc8817334be55f"
    $a1="cc69f666c4058c656acc8817334be55f"
    $a2="63a9f0ea7bb98050796b649e85481845"
    $a3="9e57e25848ca617c397b35b6507e2710"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule sha1_hashed_default_creds_celerity
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for celerity. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="09e8ee583731c8064600fa2d5fdc251ed3888f90"
    $a1="09e8ee583731c8064600fa2d5fdc251ed3888f90"
    $a2="dc76e9f0c0006e8f919e0c515c66dbba3982f785"
    $a3="15dc450365539fa619d1b4fb5ab2616086c5078a"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule sha384_hashed_default_creds_celerity
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for celerity. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="2845d2352e91ec6c23950ffae8d2068256bfa3328b8be6b0f05e64165a88badbe3d1bd046a131b6584d32e8196a2e73c"
    $a1="2845d2352e91ec6c23950ffae8d2068256bfa3328b8be6b0f05e64165a88badbe3d1bd046a131b6584d32e8196a2e73c"
    $a2="7ed8c2c790aa83d6c3e404b5368f6832c18d46a0e98b9c7a7a5e3ef823e2c9f0e310abbf6f7ea9d9d883ccb64ec2736a"
    $a3="5d61c1cc3d79cd7f3667e544fdb52d28f0f612f21a371f7829b2eccede68abd33a4d3bd9d7830392c534626af31b88c4"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule sha224_hashed_default_creds_celerity
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for celerity. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="db91cc04dd0f28d4449ff9c475ef0a8d0b129f414f0653ddef42c04e"
    $a1="db91cc04dd0f28d4449ff9c475ef0a8d0b129f414f0653ddef42c04e"
    $a2="871ce144069ea0816545f52f09cd135d1182262c3b235808fa5a3281"
    $a3="a66fe10d2ccf30b0e04081ce304db4670cc631d7ddf3ca5c41848b43"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule sha512_hashed_default_creds_celerity
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for celerity. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="116dc22a3af6a6f6e3d4e64c22b3d6d384d7819257043c3c7d82c74c17addf146aa38a5c11f7eced518faf90b94ccd87a5e183cd228889e2d09e11dc0edd6655"
    $a1="116dc22a3af6a6f6e3d4e64c22b3d6d384d7819257043c3c7d82c74c17addf146aa38a5c11f7eced518faf90b94ccd87a5e183cd228889e2d09e11dc0edd6655"
    $a2="99adc231b045331e514a516b4b7680f588e3823213abe901738bc3ad67b2f6fcb3c64efb93d18002588d3ccc1a49efbae1ce20cb43df36b38651f11fa75678e8"
    $a3="ead37dfccbcb3c075bd1380bd5ca94a590207b2779819eafbb4de534be08cd518c9a92f2d9006a2f8e1b1c6378cf799aab6cbb19ccb47b3a1a5116e1aa97b485"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule sha256_hashed_default_creds_celerity
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for celerity. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="213e88ec8794cce8b7803294ec0992ffacf88abef89f6aa4faaa3db80e792383"
    $a1="213e88ec8794cce8b7803294ec0992ffacf88abef89f6aa4faaa3db80e792383"
    $a2="4813494d137e1631bba301d5acab6e7bb7aa74ce1185d456565ef51d737677b2"
    $a3="a3c4ff03c78ff2ede7e8942527a9cb80e95956cbe0d92fe5772890fbc28d492b"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule blake2b_hashed_default_creds_celerity
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for celerity. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="4d5e70857236af965ee93b8e260157c93e30d29252ded4e689507991566b49056115715af73ec6e8094e78d6bfce5d0f76879c47d969ae20196107c0ffec0bf2"
    $a1="4d5e70857236af965ee93b8e260157c93e30d29252ded4e689507991566b49056115715af73ec6e8094e78d6bfce5d0f76879c47d969ae20196107c0ffec0bf2"
    $a2="da23f3a4e096b0816ec2070050eac6cd9243240dad0b5cde6573e41d6852939ac5468aa9d81b5fbe156feb231a069f5afe8a5146630abc7807b1e0dcdaeb049a"
    $a3="94c543f416cd2b4b9c06c31a745b5b578f0b71317cc20d6b18abbad48ff5e664bde6e71e89bf68d22bcc84578b9867abb549d1b3e51b1633ab3b922e3e5800d4"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule blake2s_hashed_default_creds_celerity
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for celerity. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="3b6f88188f890d6d57a648821f8a11f4b796b891a0626d1244a97a3253ee594a"
    $a1="3b6f88188f890d6d57a648821f8a11f4b796b891a0626d1244a97a3253ee594a"
    $a2="0cb8a879dc5d94ed67eb49cc7a4d3052d6a346f2e28fcd9e10e5822aba92eb39"
    $a3="5db25a2ebabbf148ae0af5027e9f3eed87e325b935fce924719af02565800644"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule sha3_224_hashed_default_creds_celerity
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for celerity. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="2268df243f3ba7aec970f4326b184d5db233b57082c465d9ffcbc185"
    $a1="2268df243f3ba7aec970f4326b184d5db233b57082c465d9ffcbc185"
    $a2="3e42295e89a3a84ce7ee38e2ba317aeb57ca3164459bdf48f4da0e92"
    $a3="5789eaaa22f199b60eb6fbf90898db050c4c9b34059f7f5a0efecf23"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule sha3_256_hashed_default_creds_celerity
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for celerity. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="ad02dd5acc3bf0c2af65d421c9fb4623bd65a9d03d5e6aadca4d64df57fe721e"
    $a1="ad02dd5acc3bf0c2af65d421c9fb4623bd65a9d03d5e6aadca4d64df57fe721e"
    $a2="a00e4d3b352e9d11979549b9eef5dc951592f594488451e6cd86fdc4bce76a53"
    $a3="73e65939b85d51c320db19b9d127680484d860ce45f3e8bfbfb318c4c29c0640"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule sha3_384_hashed_default_creds_celerity
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for celerity. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="d1ead38489a10222f7aecbf07399721e4d243c8e56fcb0a780b966f905a1d4165402284b852bdcd046a193ff6fb0e519"
    $a1="d1ead38489a10222f7aecbf07399721e4d243c8e56fcb0a780b966f905a1d4165402284b852bdcd046a193ff6fb0e519"
    $a2="aac595410801e93eadb099ac575ccc12e43be2c15e31e7991e908329e5beb0729881b3be9ccdb0eeb6eb79335ea38b6d"
    $a3="1f9c692c2766f2abbee9a8e26e5e3fc0b9fdbb721ccd67bb333078eabbcb8e680eb4f8a8c2cbd5fe8d17390a7eb358e1"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule sha3_512_hashed_default_creds_celerity
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for celerity. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="b0e44564bad963a5b8fd84494303289fd068cb6bbdf14f5e70c2d2d20778c7be94a50cf79671add9f3c30354bda46461f9eba1e9934a9038cbc25c9d29b5822a"
    $a1="b0e44564bad963a5b8fd84494303289fd068cb6bbdf14f5e70c2d2d20778c7be94a50cf79671add9f3c30354bda46461f9eba1e9934a9038cbc25c9d29b5822a"
    $a2="8cd824c700eb0c125fff40c8c185d14c5dfe7f32814afac079ba7c20d93bc3c082193243c420fed22ef2474fbb85880e7bc1ca772150a1f759f8ddebca77711f"
    $a3="01bf3a32baa45fd9dddcdb8b37c4983a4ac7ade9e753cf4373c64cbad34393c2718aa6685adff535922f983128aaa73ca19df4330f46392f2cb89d203bcbafbb"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule base64_hashed_default_creds_celerity
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for celerity. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="bWVkaWF0b3I="
    $a1="bWVkaWF0b3I="
    $a2="cm9vdA=="
    $a3="TXVhJ2RpYg=="
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

