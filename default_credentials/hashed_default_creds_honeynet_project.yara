/*This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as long as you use it under this license.*/

rule md5_hashed_default_creds_honeynet_project
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for honeynet_project. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="6606afc4c696fa1b4f0f68408726649d"
    $a1="b60eb83bf533eecf1bde65940925a981"
    $a2="63a9f0ea7bb98050796b649e85481845"
    $a3="b60eb83bf533eecf1bde65940925a981"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule sha1_hashed_default_creds_honeynet_project
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for honeynet_project. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="1f251d9a37a279c268cc5091445e4a4b381aa4e7"
    $a1="9d75342c103a050cfb09b05960bb95d6dc1335b6"
    $a2="dc76e9f0c0006e8f919e0c515c66dbba3982f785"
    $a3="9d75342c103a050cfb09b05960bb95d6dc1335b6"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule sha384_hashed_default_creds_honeynet_project
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for honeynet_project. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="4f8ef699d789423ef99cfe82e7bace4663b029346936c9cdc1d596fb8bdb2e2ff243cec999d510fd0998ad07fca27c0a"
    $a1="f8f3517cf93f00d50e006c6b250f94eb69fbed4232701e9d780eb3877b75ab336add20d2484188247e43396eb1e9a36c"
    $a2="7ed8c2c790aa83d6c3e404b5368f6832c18d46a0e98b9c7a7a5e3ef823e2c9f0e310abbf6f7ea9d9d883ccb64ec2736a"
    $a3="f8f3517cf93f00d50e006c6b250f94eb69fbed4232701e9d780eb3877b75ab336add20d2484188247e43396eb1e9a36c"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule sha224_hashed_default_creds_honeynet_project
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for honeynet_project. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="f1f21ea3df92906c45090ef120acd534336ee4f9ae440eaefcf6b0a9"
    $a1="f13509df7748da4564145a66d4f7e30313a4cf0be791d98c344301e8"
    $a2="871ce144069ea0816545f52f09cd135d1182262c3b235808fa5a3281"
    $a3="f13509df7748da4564145a66d4f7e30313a4cf0be791d98c344301e8"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule sha512_hashed_default_creds_honeynet_project
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for honeynet_project. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="2c0272a79ece6ef78b052cefcd027a98f2c50eb0b8f06774ebd69954922f01d8803d1aec89e03c8982d504dcb7aededb6a8b24afd6359c5605b6f4da4585beda"
    $a1="8c9fdcde3a92c52699eaf579fca9d0fc3602852552b67b4d0a9f4a07429835d6f34f375196d73b169d55e313fc3c3e81a2db28779e3a45814704188a40221078"
    $a2="99adc231b045331e514a516b4b7680f588e3823213abe901738bc3ad67b2f6fcb3c64efb93d18002588d3ccc1a49efbae1ce20cb43df36b38651f11fa75678e8"
    $a3="8c9fdcde3a92c52699eaf579fca9d0fc3602852552b67b4d0a9f4a07429835d6f34f375196d73b169d55e313fc3c3e81a2db28779e3a45814704188a40221078"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule sha256_hashed_default_creds_honeynet_project
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for honeynet_project. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="3e7085367457fdba220d870c6532bcc04ff45e8a0a3866af37e1467a0a1498d1"
    $a1="a55e2e3846a51f6ad0abfdfbdea2ba0e5e0c76b5ccfa8a920895fedeae89a8b6"
    $a2="4813494d137e1631bba301d5acab6e7bb7aa74ce1185d456565ef51d737677b2"
    $a3="a55e2e3846a51f6ad0abfdfbdea2ba0e5e0c76b5ccfa8a920895fedeae89a8b6"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule blake2b_hashed_default_creds_honeynet_project
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for honeynet_project. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="b5196bdc9583819e00561ee1a613cdb1b258f31f362e8d3253f413d161616c5ecccd9ac60dd3135ced80657ffc4afa28fca9e7fa96895f8c4c3f263592c8abc9"
    $a1="5e759101c609f4b740ef80e765ae365b2af502d28946ffdb14a008ba3b8f3b38d22724597db1a2727631e47be95bf3dbc91421426b178885abb756996aa2ed28"
    $a2="da23f3a4e096b0816ec2070050eac6cd9243240dad0b5cde6573e41d6852939ac5468aa9d81b5fbe156feb231a069f5afe8a5146630abc7807b1e0dcdaeb049a"
    $a3="5e759101c609f4b740ef80e765ae365b2af502d28946ffdb14a008ba3b8f3b38d22724597db1a2727631e47be95bf3dbc91421426b178885abb756996aa2ed28"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule blake2s_hashed_default_creds_honeynet_project
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for honeynet_project. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="8597330256742755b1f10862228843b547be0411d2fc915dcaa116c655f5dd90"
    $a1="97366c98ecc5c51c039bf7d2aba720a0c348e5843f136182fa72337c61e28a26"
    $a2="0cb8a879dc5d94ed67eb49cc7a4d3052d6a346f2e28fcd9e10e5822aba92eb39"
    $a3="97366c98ecc5c51c039bf7d2aba720a0c348e5843f136182fa72337c61e28a26"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule sha3_224_hashed_default_creds_honeynet_project
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for honeynet_project. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="f827bb66e86eb5c3951b42a81455a25394dae272d6f16a72ee723220"
    $a1="0452aba97190537aa9211a1911b2384fc81a7f013238c0ef118f6284"
    $a2="3e42295e89a3a84ce7ee38e2ba317aeb57ca3164459bdf48f4da0e92"
    $a3="0452aba97190537aa9211a1911b2384fc81a7f013238c0ef118f6284"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule sha3_256_hashed_default_creds_honeynet_project
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for honeynet_project. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="aa281762e4013f45fa8dd62f4720076f6c499d9d8c7ea434cc56b3bc03e8c562"
    $a1="4c678c8303c73293bfcccd1ac543ead33636fbb80427383371699c1cbfb339a3"
    $a2="a00e4d3b352e9d11979549b9eef5dc951592f594488451e6cd86fdc4bce76a53"
    $a3="4c678c8303c73293bfcccd1ac543ead33636fbb80427383371699c1cbfb339a3"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule sha3_384_hashed_default_creds_honeynet_project
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for honeynet_project. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="f061a66a80ddebc82e99efb271aa6ada1d75460fc82aa9457baee6c612f33aaaf06cc5dcd79dc5100043916ae4eaad29"
    $a1="c3e535e3b57e3b4f9dbb9fe73e0fe8553c95693a26c069f26ffcffa2fd86e82fe2ad78de17cfd110a14e26e8df3ee511"
    $a2="aac595410801e93eadb099ac575ccc12e43be2c15e31e7991e908329e5beb0729881b3be9ccdb0eeb6eb79335ea38b6d"
    $a3="c3e535e3b57e3b4f9dbb9fe73e0fe8553c95693a26c069f26ffcffa2fd86e82fe2ad78de17cfd110a14e26e8df3ee511"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule sha3_512_hashed_default_creds_honeynet_project
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for honeynet_project. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="24233f2a810a5f885f30dca512fa21e54407dd6adee36938324d6d46d8d6b44b052f7b325d31e4f64014ad0be37854c52f9f026c27f20405231c088e1edbde69"
    $a1="7ebf2ec2873c61214592fda44f3b6d2117867a908545d19677179219aed9251622b222ca60e3555d2685ede7e8227affd37404dffa5f54acdb269387ded70896"
    $a2="8cd824c700eb0c125fff40c8c185d14c5dfe7f32814afac079ba7c20d93bc3c082193243c420fed22ef2474fbb85880e7bc1ca772150a1f759f8ddebca77711f"
    $a3="7ebf2ec2873c61214592fda44f3b6d2117867a908545d19677179219aed9251622b222ca60e3555d2685ede7e8227affd37404dffa5f54acdb269387ded70896"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule base64_hashed_default_creds_honeynet_project
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for honeynet_project. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="cm9v"
    $a1="aG9uZXk="
    $a2="cm9vdA=="
    $a3="aG9uZXk="
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

