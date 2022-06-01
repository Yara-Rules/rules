/*This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as long as you use it under this license.*/

rule md5_hashed_default_creds_sun
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for sun. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="21232f297a57a5a743894a0e4a801fc3"
    $a1="21232f297a57a5a743894a0e4a801fc3"
    $a2="63a9f0ea7bb98050796b649e85481845"
    $a3="4cb9c8a8048fd02294477fcb1a41191a"
    $a4="63a9f0ea7bb98050796b649e85481845"
    $a5="6035d7a170ff97458068c79e64310a38"
    $a6="63a9f0ea7bb98050796b649e85481845"
    $a7="3b1c5bbbbff8515f6e7daeedd5c9b573"
    $a8="97c9c694d99f729e1a48940d0b386a9b"
    $a9="97c9c694d99f729e1a48940d0b386a9b"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9)
}

rule sha1_hashed_default_creds_sun
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for sun. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="d033e22ae348aeb5660fc2140aec35850c4da997"
    $a1="d033e22ae348aeb5660fc2140aec35850c4da997"
    $a2="dc76e9f0c0006e8f919e0c515c66dbba3982f785"
    $a3="fa9beb99e4029ad5a6615399e7bbae21356086b3"
    $a4="dc76e9f0c0006e8f919e0c515c66dbba3982f785"
    $a5="f7a84e1338146bbf4b25a27d14b138848c991fff"
    $a6="dc76e9f0c0006e8f919e0c515c66dbba3982f785"
    $a7="cbcbc77f56a31cdcf98d7b7315e647dd21ceb8e9"
    $a8="793d0520344d4e35ae49bc18fd51c9131b00bd2a"
    $a9="793d0520344d4e35ae49bc18fd51c9131b00bd2a"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9)
}

rule sha384_hashed_default_creds_sun
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for sun. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="9ca694a90285c034432c9550421b7b9dbd5c0f4b6673f05f6dbce58052ba20e4248041956ee8c9a2ec9f10290cdc0782"
    $a1="9ca694a90285c034432c9550421b7b9dbd5c0f4b6673f05f6dbce58052ba20e4248041956ee8c9a2ec9f10290cdc0782"
    $a2="7ed8c2c790aa83d6c3e404b5368f6832c18d46a0e98b9c7a7a5e3ef823e2c9f0e310abbf6f7ea9d9d883ccb64ec2736a"
    $a3="7d49d02c105312b2b69de69141b27de1f4f4c202b4afb19d7ff7ab9849e9ce2da165a87eeec971bca66c8eb8a9243f5e"
    $a4="7ed8c2c790aa83d6c3e404b5368f6832c18d46a0e98b9c7a7a5e3ef823e2c9f0e310abbf6f7ea9d9d883ccb64ec2736a"
    $a5="fcedfb9c8a81fc4e3fed3b538192ec2c4833400459db0987ddd68a097caaf43aaadd25f76bd4bc7e83d958f628d0bfc7"
    $a6="7ed8c2c790aa83d6c3e404b5368f6832c18d46a0e98b9c7a7a5e3ef823e2c9f0e310abbf6f7ea9d9d883ccb64ec2736a"
    $a7="863a40e8172ab8cc10f35ec8292b49f7a9cc065bd40d99820836f90e83f187b149227a26cb0de22cbd15491c59a518b2"
    $a8="0ad723fce2fa1a269d14fda8a3ca2e4c1a9881fa9a1a3f087243c39d3d1f8d8023d234ef1cae8202c5d9fa8c59c775f2"
    $a9="0ad723fce2fa1a269d14fda8a3ca2e4c1a9881fa9a1a3f087243c39d3d1f8d8023d234ef1cae8202c5d9fa8c59c775f2"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9)
}

rule sha224_hashed_default_creds_sun
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for sun. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="58acb7acccce58ffa8b953b12b5a7702bd42dae441c1ad85057fa70b"
    $a1="58acb7acccce58ffa8b953b12b5a7702bd42dae441c1ad85057fa70b"
    $a2="871ce144069ea0816545f52f09cd135d1182262c3b235808fa5a3281"
    $a3="d44d697d0b8ad27b1d3b323b1b438db88058ec1f0f21cef6a6629875"
    $a4="871ce144069ea0816545f52f09cd135d1182262c3b235808fa5a3281"
    $a5="432c12b9bd30adc1cdf98985953a9af1c17e25fa6df183056583ad31"
    $a6="871ce144069ea0816545f52f09cd135d1182262c3b235808fa5a3281"
    $a7="cffe0ece075a3924ccd9adbc21ce32260b0088307e587e3938a377af"
    $a8="f5e5cf522be63f36322027ac57951409e28a73c7a65e015d152251fd"
    $a9="f5e5cf522be63f36322027ac57951409e28a73c7a65e015d152251fd"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9)
}

rule sha512_hashed_default_creds_sun
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for sun. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="c7ad44cbad762a5da0a452f9e854fdc1e0e7a52a38015f23f3eab1d80b931dd472634dfac71cd34ebc35d16ab7fb8a90c81f975113d6c7538dc69dd8de9077ec"
    $a1="c7ad44cbad762a5da0a452f9e854fdc1e0e7a52a38015f23f3eab1d80b931dd472634dfac71cd34ebc35d16ab7fb8a90c81f975113d6c7538dc69dd8de9077ec"
    $a2="99adc231b045331e514a516b4b7680f588e3823213abe901738bc3ad67b2f6fcb3c64efb93d18002588d3ccc1a49efbae1ce20cb43df36b38651f11fa75678e8"
    $a3="f1891cea80fc05e433c943254c6bdabc159577a02a7395dfebbfbc4f7661d4af56f2d372131a45936de40160007368a56ef216a30cb202c66d3145fd24380906"
    $a4="99adc231b045331e514a516b4b7680f588e3823213abe901738bc3ad67b2f6fcb3c64efb93d18002588d3ccc1a49efbae1ce20cb43df36b38651f11fa75678e8"
    $a5="e4abe26a2eb7ca8d3367154a89262f44e4c20b6e67b62dc43a54cdb311c5843cebee8b72e8c04dc5b2c0158e2fcfcc75da41b157a3457c83dafd720550171531"
    $a6="99adc231b045331e514a516b4b7680f588e3823213abe901738bc3ad67b2f6fcb3c64efb93d18002588d3ccc1a49efbae1ce20cb43df36b38651f11fa75678e8"
    $a7="39538def457c5d9ca7f23b1d4fdd0b05256571fdd612888000987f3fcf23a029a0b48f9abe28cccd97279e74530ef75a5e838eb05261a5807f7df1eb9f9e6efa"
    $a8="96c9a03ea4a916aa903f271b24bfc8fae161c996ab11a4d6a91fde2691ee4e9e735e166e335fc85e7f11beac7ec3c689150eaf71199900b2424e799b3cd94bb7"
    $a9="96c9a03ea4a916aa903f271b24bfc8fae161c996ab11a4d6a91fde2691ee4e9e735e166e335fc85e7f11beac7ec3c689150eaf71199900b2424e799b3cd94bb7"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9)
}

rule sha256_hashed_default_creds_sun
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for sun. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="8c6976e5b5410415bde908bd4dee15dfb167a9c873fc4bb8a81f6f2ab448a918"
    $a1="8c6976e5b5410415bde908bd4dee15dfb167a9c873fc4bb8a81f6f2ab448a918"
    $a2="4813494d137e1631bba301d5acab6e7bb7aa74ce1185d456565ef51d737677b2"
    $a3="057ba03d6c44104863dc7361fe4578965d1887360f90a0895882e58a6248fc86"
    $a4="4813494d137e1631bba301d5acab6e7bb7aa74ce1185d456565ef51d737677b2"
    $a5="30108c4c21bbf2a0e7445efb1724c2abdb8aafa65ec8333cfef61fb5b7140804"
    $a6="4813494d137e1631bba301d5acab6e7bb7aa74ce1185d456565ef51d737677b2"
    $a7="030b17b2169a535bdaa0a4eb355aa17604851ff96e4b94629f9c458ac524a0bd"
    $a8="007d831ea2e8e1d080b31e33c50b89ea07f9b694bccad998c8cf5cb1a087f889"
    $a9="007d831ea2e8e1d080b31e33c50b89ea07f9b694bccad998c8cf5cb1a087f889"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9)
}

rule blake2b_hashed_default_creds_sun
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for sun. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="bfcce2c19c8563fd4aa66f6ec607341ff25e5f6fe7fa520d7d1242d871385f23a3e8e80093120b4877d79535e10b182ae2ec8937d1f72f091e7178c9e4ff0f11"
    $a1="bfcce2c19c8563fd4aa66f6ec607341ff25e5f6fe7fa520d7d1242d871385f23a3e8e80093120b4877d79535e10b182ae2ec8937d1f72f091e7178c9e4ff0f11"
    $a2="da23f3a4e096b0816ec2070050eac6cd9243240dad0b5cde6573e41d6852939ac5468aa9d81b5fbe156feb231a069f5afe8a5146630abc7807b1e0dcdaeb049a"
    $a3="bc8653499aba9b909eecec568e20a1855cfc87f30ef8e109ef4e6d4cb9fff8aa9461d5c3092fb1e5f3950ca5fdf986cc52927a2b1d7bb30af201f2ff95f34d42"
    $a4="da23f3a4e096b0816ec2070050eac6cd9243240dad0b5cde6573e41d6852939ac5468aa9d81b5fbe156feb231a069f5afe8a5146630abc7807b1e0dcdaeb049a"
    $a5="e454bd0fe83d5f20b070ea83fba63e221781bf538009ba7617a7cd2feb4480108e5f5d6bef574a4693e429888c4435a46a315d274b601fd6c36a0b006887f949"
    $a6="da23f3a4e096b0816ec2070050eac6cd9243240dad0b5cde6573e41d6852939ac5468aa9d81b5fbe156feb231a069f5afe8a5146630abc7807b1e0dcdaeb049a"
    $a7="56227212607c670601e3494b649ac570a4ad1914641537d58e12a047d92e00932dae905504a57420e1d7dfabee59de9dacad3faef9e16a834086168bd02a172e"
    $a8="e6de0b487a78bbeada86a22cec60cc4fade47168a34051824f87e99b0dbc4aa9e0fa51d111c43d91cf895558e196e95ea945d8fdeace67240e3185e54537c691"
    $a9="e6de0b487a78bbeada86a22cec60cc4fade47168a34051824f87e99b0dbc4aa9e0fa51d111c43d91cf895558e196e95ea945d8fdeace67240e3185e54537c691"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9)
}

rule blake2s_hashed_default_creds_sun
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for sun. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="327e7e3821f5f6d33c090137f979bf48ee62e9051c1610e1d6468ecb3c67a124"
    $a1="327e7e3821f5f6d33c090137f979bf48ee62e9051c1610e1d6468ecb3c67a124"
    $a2="0cb8a879dc5d94ed67eb49cc7a4d3052d6a346f2e28fcd9e10e5822aba92eb39"
    $a3="3f7eae1ee1e4295ab992391eea5d33a45e869e50fabf367779086eec821b2698"
    $a4="0cb8a879dc5d94ed67eb49cc7a4d3052d6a346f2e28fcd9e10e5822aba92eb39"
    $a5="1a907fa4e672895f840ba727f7e8462aa7ee9d697a879fe0c6b68576b8745ec1"
    $a6="0cb8a879dc5d94ed67eb49cc7a4d3052d6a346f2e28fcd9e10e5822aba92eb39"
    $a7="1b2b990aaf29f39ae5b6ca8682aae265c157e9fdcf945a91e38f03da827f762d"
    $a8="c290609813c61da32a782afb032648c5e0666a7c93ff47e950577ab96c440bfb"
    $a9="c290609813c61da32a782afb032648c5e0666a7c93ff47e950577ab96c440bfb"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9)
}

rule sha3_224_hashed_default_creds_sun
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for sun. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="a53fff8dd075bed169e164743231ff533d8b9260b0b8073f0a4c1d20"
    $a1="a53fff8dd075bed169e164743231ff533d8b9260b0b8073f0a4c1d20"
    $a2="3e42295e89a3a84ce7ee38e2ba317aeb57ca3164459bdf48f4da0e92"
    $a3="3580d8fca5a3d7def6d1bbb076d8192b806ba4155c7569c89713d606"
    $a4="3e42295e89a3a84ce7ee38e2ba317aeb57ca3164459bdf48f4da0e92"
    $a5="0688cbd2ee273d4a359b5bc0a8c45c00cda485ef5f36c2914a7b3bd5"
    $a6="3e42295e89a3a84ce7ee38e2ba317aeb57ca3164459bdf48f4da0e92"
    $a7="d723259e7c7a2518098db34b7edb9051af9f2307c55657b32af461ad"
    $a8="3db1415f3179b66da0e34acacfc4a542eb2e5ae067b4d13446387907"
    $a9="3db1415f3179b66da0e34acacfc4a542eb2e5ae067b4d13446387907"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9)
}

rule sha3_256_hashed_default_creds_sun
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for sun. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="fb001dfcffd1c899f3297871406242f097aecf1a5342ccf3ebcd116146188e4b"
    $a1="fb001dfcffd1c899f3297871406242f097aecf1a5342ccf3ebcd116146188e4b"
    $a2="a00e4d3b352e9d11979549b9eef5dc951592f594488451e6cd86fdc4bce76a53"
    $a3="f4d6ed1b56b50792c161e7b440f2931279901d1fc97791c69af7d3d2381980f2"
    $a4="a00e4d3b352e9d11979549b9eef5dc951592f594488451e6cd86fdc4bce76a53"
    $a5="76d9c8341c138b2b9b35b1f114508618fc24875214dd4a26a104d2e85b66ff77"
    $a6="a00e4d3b352e9d11979549b9eef5dc951592f594488451e6cd86fdc4bce76a53"
    $a7="0e29c3a44f1a80037916bd6fd0e787aa06c9297a7dd17b3908b80f9578611cb1"
    $a8="f7b6747cf2fd176ef521a1633de2e751f516bd7de30a1962130a2b0b694929b0"
    $a9="f7b6747cf2fd176ef521a1633de2e751f516bd7de30a1962130a2b0b694929b0"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9)
}

rule sha3_384_hashed_default_creds_sun
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for sun. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="9765a57f2010506383de91052915ce8bafbdb39f3e5a8c1a1693a0076365d37abbfd3305881ea3b5fa1426316afd7df3"
    $a1="9765a57f2010506383de91052915ce8bafbdb39f3e5a8c1a1693a0076365d37abbfd3305881ea3b5fa1426316afd7df3"
    $a2="aac595410801e93eadb099ac575ccc12e43be2c15e31e7991e908329e5beb0729881b3be9ccdb0eeb6eb79335ea38b6d"
    $a3="4d58bfd306307b517f58bda7326e3570b9e38ca9cff807e9023d8c3af94c89c0cb1c5216038bc235e8ff6fcfb86fcf6c"
    $a4="aac595410801e93eadb099ac575ccc12e43be2c15e31e7991e908329e5beb0729881b3be9ccdb0eeb6eb79335ea38b6d"
    $a5="5394abf6a1e1c7b032e9c65d091a00e63ae5e4ffb93d5f2903d7082c147121c9f04064295e68978f0a1c427b9f3a163a"
    $a6="aac595410801e93eadb099ac575ccc12e43be2c15e31e7991e908329e5beb0729881b3be9ccdb0eeb6eb79335ea38b6d"
    $a7="2fc9d5abb5853fc431c303d438a5601e7d300daa650d37599ac69e44d8a2a1a81ebf6aca5d38063181e53ec312fbc69b"
    $a8="e2832687c2b360db06ada9649c10ec15be4b70a105abbd0a116141ef906bd326ce81fe6691e89bd2b94bbbad5ef5c9fe"
    $a9="e2832687c2b360db06ada9649c10ec15be4b70a105abbd0a116141ef906bd326ce81fe6691e89bd2b94bbbad5ef5c9fe"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9)
}

rule sha3_512_hashed_default_creds_sun
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for sun. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="5a38afb1a18d408e6cd367f9db91e2ab9bce834cdad3da24183cc174956c20ce35dd39c2bd36aae907111ae3d6ada353f7697a5f1a8fc567aae9e4ca41a9d19d"
    $a1="5a38afb1a18d408e6cd367f9db91e2ab9bce834cdad3da24183cc174956c20ce35dd39c2bd36aae907111ae3d6ada353f7697a5f1a8fc567aae9e4ca41a9d19d"
    $a2="8cd824c700eb0c125fff40c8c185d14c5dfe7f32814afac079ba7c20d93bc3c082193243c420fed22ef2474fbb85880e7bc1ca772150a1f759f8ddebca77711f"
    $a3="83ed150dbcc9700521ccc2f7d67243c3d4000c8228281488dccd6c6753f48515dcb24714d5a294df27eeda834e9242e1ce4014fc38df3e0439b999fe3efa0765"
    $a4="8cd824c700eb0c125fff40c8c185d14c5dfe7f32814afac079ba7c20d93bc3c082193243c420fed22ef2474fbb85880e7bc1ca772150a1f759f8ddebca77711f"
    $a5="fb324354599ef86a212637dac66f9f47bffa0865b6c8af259e9d46477425459c7ed61fe889b5ac9ae2e11d8971acba1b0b50963c7a40d2fc88ba13cdcb9fce8f"
    $a6="8cd824c700eb0c125fff40c8c185d14c5dfe7f32814afac079ba7c20d93bc3c082193243c420fed22ef2474fbb85880e7bc1ca772150a1f759f8ddebca77711f"
    $a7="465a56680a7d5850f07b4f786d3331bf28d6ca64764bcc8e481edc861b345f65e02f8605280c22667498385bf5db22d7dadd425b3a2f544e2e1c0af3a4501fd1"
    $a8="1840b381398b9340c7f3040183a5d1ca79d0b38de07b903f9d9167c77c64c25affcf08664807d094e1a6d97b355b92081ff0f6921fca8b8948cc2caa07f9a5dd"
    $a9="1840b381398b9340c7f3040183a5d1ca79d0b38de07b903f9d9167c77c64c25affcf08664807d094e1a6d97b355b92081ff0f6921fca8b8948cc2caa07f9a5dd"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9)
}

rule base64_hashed_default_creds_sun
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for sun. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="YWRtaW4="
    $a1="YWRtaW4="
    $a2="cm9vdA=="
    $a3="Y2hhbmdlbWU="
    $a4="cm9vdA=="
    $a5="c3VuMTIz"
    $a6="cm9vdA=="
    $a7="dDAwbGsxdA=="
    $a8="c3Nw"
    $a9="c3Nw"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9)
}

