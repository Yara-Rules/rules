/*This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as long as you use it under this license.*/

rule md5_hashed_default_creds_apache
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for apache. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="21232f297a57a5a743894a0e4a801fc3"
    $a1="21232f297a57a5a743894a0e4a801fc3"
    $a2="21232f297a57a5a743894a0e4a801fc3"
    $a3="d41d8cd98f00b204e9800998ecf8427e"
    $a4="21232f297a57a5a743894a0e4a801fc3"
    $a5="e1c759add0bfa882387a1bc56b31e8e4"
    $a6="21232f297a57a5a743894a0e4a801fc3"
    $a7="714b393f4b2c29561d44c5e0a90ffdb9"
    $a8="21232f297a57a5a743894a0e4a801fc3"
    $a9="1b359d8753858b55befa0441067aaed3"
    $a10="f6cb3e816496528d4187db53bc66567f"
    $a11="1b359d8753858b55befa0441067aaed3"
    $a12="31b864b5546913dd928a49416a10bad1"
    $a13="31b864b5546913dd928a49416a10bad1"
    $a14="31b864b5546913dd928a49416a10bad1"
    $a15="1b359d8753858b55befa0441067aaed3"
    $a16="29a7e96467b69a9f5a93332e29e9b0de"
    $a17="925ad2679b095816cfc0cf772f467229"
    $a18="63a9f0ea7bb98050796b649e85481845"
    $a19="925ad2679b095816cfc0cf772f467229"
    $a20="63a9f0ea7bb98050796b649e85481845"
    $a21="63a9f0ea7bb98050796b649e85481845"
    $a22="1b359d8753858b55befa0441067aaed3"
    $a23="925ad2679b095816cfc0cf772f467229"
    $a24="1b359d8753858b55befa0441067aaed3"
    $a25="1b359d8753858b55befa0441067aaed3"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13) or ($a14 and $a15) or ($a16 and $a17) or ($a18 and $a19) or ($a20 and $a21) or ($a22 and $a23) or ($a24 and $a25)
}

rule sha1_hashed_default_creds_apache
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for apache. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="d033e22ae348aeb5660fc2140aec35850c4da997"
    $a1="d033e22ae348aeb5660fc2140aec35850c4da997"
    $a2="d033e22ae348aeb5660fc2140aec35850c4da997"
    $a3="da39a3ee5e6b4b0d3255bfef95601890afd80709"
    $a4="d033e22ae348aeb5660fc2140aec35850c4da997"
    $a5="44f4f26e7ac9a4ef1ec6e87df92e1dcf27bab738"
    $a6="d033e22ae348aeb5660fc2140aec35850c4da997"
    $a7="f35249adca11603f3229272cfe3f6c95a1ae08ff"
    $a8="d033e22ae348aeb5660fc2140aec35850c4da997"
    $a9="536c0b339345616c1b33caf454454d8b8a190d6c"
    $a10="fc39b18f287d8bbfaceae020f4a4eb32ac5c1e70"
    $a11="536c0b339345616c1b33caf454454d8b8a190d6c"
    $a12="91b1a5369590bab100066e1c83e2317a1adb2a76"
    $a13="91b1a5369590bab100066e1c83e2317a1adb2a76"
    $a14="91b1a5369590bab100066e1c83e2317a1adb2a76"
    $a15="536c0b339345616c1b33caf454454d8b8a190d6c"
    $a16="8dca46428d005a2f4c2e039fb250964d6139a8b2"
    $a17="cdb0e76c1a69873cbdcdbe0a142d56c023dc9f22"
    $a18="dc76e9f0c0006e8f919e0c515c66dbba3982f785"
    $a19="cdb0e76c1a69873cbdcdbe0a142d56c023dc9f22"
    $a20="dc76e9f0c0006e8f919e0c515c66dbba3982f785"
    $a21="dc76e9f0c0006e8f919e0c515c66dbba3982f785"
    $a22="536c0b339345616c1b33caf454454d8b8a190d6c"
    $a23="cdb0e76c1a69873cbdcdbe0a142d56c023dc9f22"
    $a24="536c0b339345616c1b33caf454454d8b8a190d6c"
    $a25="536c0b339345616c1b33caf454454d8b8a190d6c"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13) or ($a14 and $a15) or ($a16 and $a17) or ($a18 and $a19) or ($a20 and $a21) or ($a22 and $a23) or ($a24 and $a25)
}

rule sha384_hashed_default_creds_apache
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for apache. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="9ca694a90285c034432c9550421b7b9dbd5c0f4b6673f05f6dbce58052ba20e4248041956ee8c9a2ec9f10290cdc0782"
    $a1="9ca694a90285c034432c9550421b7b9dbd5c0f4b6673f05f6dbce58052ba20e4248041956ee8c9a2ec9f10290cdc0782"
    $a2="9ca694a90285c034432c9550421b7b9dbd5c0f4b6673f05f6dbce58052ba20e4248041956ee8c9a2ec9f10290cdc0782"
    $a3="38b060a751ac96384cd9327eb1b1e36a21fdb71114be07434c0cc7bf63f6e1da274edebfe76f65fbd51ad2f14898b95b"
    $a4="9ca694a90285c034432c9550421b7b9dbd5c0f4b6673f05f6dbce58052ba20e4248041956ee8c9a2ec9f10290cdc0782"
    $a5="e59dc20e2eeb258a8347a590a2e40be973fc018899a47190925c5dd88bab783e8017d201e4f8fb3dffc8489c81787b7d"
    $a6="9ca694a90285c034432c9550421b7b9dbd5c0f4b6673f05f6dbce58052ba20e4248041956ee8c9a2ec9f10290cdc0782"
    $a7="c849e711ad8b1bed6e23bb4cac212e4bd8b4ff3a9a3fbcece8525b783e3cc0821c2011ac8cd939a27a098480a28aef14"
    $a8="9ca694a90285c034432c9550421b7b9dbd5c0f4b6673f05f6dbce58052ba20e4248041956ee8c9a2ec9f10290cdc0782"
    $a9="8844314f91950ac7ef0d2dd510edf08ee2ee760c8ff0baff3b61fde2b49155ad65e9ac2ffe3a1f1879b53ba6336ad8e6"
    $a10="6f9e97f59673406a33ebfe62c041d77c782ffc3187b90d0d7d9523be81e2430250d2753eb2d6bdf94e0a96414ee0d76e"
    $a11="8844314f91950ac7ef0d2dd510edf08ee2ee760c8ff0baff3b61fde2b49155ad65e9ac2ffe3a1f1879b53ba6336ad8e6"
    $a12="a490369260a3a7c150bb597583110c7f0c8c99812ea4ca73760920b8ff18a7c3f9943d3c3203cc13cea0a19fc222d0e6"
    $a13="a490369260a3a7c150bb597583110c7f0c8c99812ea4ca73760920b8ff18a7c3f9943d3c3203cc13cea0a19fc222d0e6"
    $a14="a490369260a3a7c150bb597583110c7f0c8c99812ea4ca73760920b8ff18a7c3f9943d3c3203cc13cea0a19fc222d0e6"
    $a15="8844314f91950ac7ef0d2dd510edf08ee2ee760c8ff0baff3b61fde2b49155ad65e9ac2ffe3a1f1879b53ba6336ad8e6"
    $a16="b4a85c5c35a16d6e36c16b21834b1b21c68a263499fc3092ff27c1ca1a2a5c88d0344b31130a03b8b74317754cf2d9aa"
    $a17="06398a1556e8b7890d09872506ba5bd4f262cb8f21b244f792d5511e4e9d73e8e7de8ceef7fa497b730b0d7a4b24c3d1"
    $a18="7ed8c2c790aa83d6c3e404b5368f6832c18d46a0e98b9c7a7a5e3ef823e2c9f0e310abbf6f7ea9d9d883ccb64ec2736a"
    $a19="06398a1556e8b7890d09872506ba5bd4f262cb8f21b244f792d5511e4e9d73e8e7de8ceef7fa497b730b0d7a4b24c3d1"
    $a20="7ed8c2c790aa83d6c3e404b5368f6832c18d46a0e98b9c7a7a5e3ef823e2c9f0e310abbf6f7ea9d9d883ccb64ec2736a"
    $a21="7ed8c2c790aa83d6c3e404b5368f6832c18d46a0e98b9c7a7a5e3ef823e2c9f0e310abbf6f7ea9d9d883ccb64ec2736a"
    $a22="8844314f91950ac7ef0d2dd510edf08ee2ee760c8ff0baff3b61fde2b49155ad65e9ac2ffe3a1f1879b53ba6336ad8e6"
    $a23="06398a1556e8b7890d09872506ba5bd4f262cb8f21b244f792d5511e4e9d73e8e7de8ceef7fa497b730b0d7a4b24c3d1"
    $a24="8844314f91950ac7ef0d2dd510edf08ee2ee760c8ff0baff3b61fde2b49155ad65e9ac2ffe3a1f1879b53ba6336ad8e6"
    $a25="8844314f91950ac7ef0d2dd510edf08ee2ee760c8ff0baff3b61fde2b49155ad65e9ac2ffe3a1f1879b53ba6336ad8e6"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13) or ($a14 and $a15) or ($a16 and $a17) or ($a18 and $a19) or ($a20 and $a21) or ($a22 and $a23) or ($a24 and $a25)
}

rule sha224_hashed_default_creds_apache
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for apache. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="58acb7acccce58ffa8b953b12b5a7702bd42dae441c1ad85057fa70b"
    $a1="58acb7acccce58ffa8b953b12b5a7702bd42dae441c1ad85057fa70b"
    $a2="58acb7acccce58ffa8b953b12b5a7702bd42dae441c1ad85057fa70b"
    $a3="d14a028c2a3a2bc9476102bb288234c415a2b01f828ea62ac5b3e42f"
    $a4="58acb7acccce58ffa8b953b12b5a7702bd42dae441c1ad85057fa70b"
    $a5="f7b6d21913933d111b7d38a6f2554e86b76d128acc15a588310f0f15"
    $a6="58acb7acccce58ffa8b953b12b5a7702bd42dae441c1ad85057fa70b"
    $a7="4289543e5f9bb50dfbed9a8ce4fd47d2b9d5a8af87d46b9eae6dad0f"
    $a8="58acb7acccce58ffa8b953b12b5a7702bd42dae441c1ad85057fa70b"
    $a9="408610bc629bf7ebae9f88a6fe484b702acfd2acdfb5c172aa3a581f"
    $a10="b8af66a764892e747457a74abb87bee75c0818f70c364c72e1e51ee2"
    $a11="408610bc629bf7ebae9f88a6fe484b702acfd2acdfb5c172aa3a581f"
    $a12="d61b015e13032015cf9630b6d4d156bd163b33865c5630653976b965"
    $a13="d61b015e13032015cf9630b6d4d156bd163b33865c5630653976b965"
    $a14="d61b015e13032015cf9630b6d4d156bd163b33865c5630653976b965"
    $a15="408610bc629bf7ebae9f88a6fe484b702acfd2acdfb5c172aa3a581f"
    $a16="81dab7300100a9e496e95d1194690fe14401c3ae8dae4b1f79addf23"
    $a17="4f262d752cac96a9ada895719bb1ffc3c0e916c16fff93db5e716b7c"
    $a18="871ce144069ea0816545f52f09cd135d1182262c3b235808fa5a3281"
    $a19="4f262d752cac96a9ada895719bb1ffc3c0e916c16fff93db5e716b7c"
    $a20="871ce144069ea0816545f52f09cd135d1182262c3b235808fa5a3281"
    $a21="871ce144069ea0816545f52f09cd135d1182262c3b235808fa5a3281"
    $a22="408610bc629bf7ebae9f88a6fe484b702acfd2acdfb5c172aa3a581f"
    $a23="4f262d752cac96a9ada895719bb1ffc3c0e916c16fff93db5e716b7c"
    $a24="408610bc629bf7ebae9f88a6fe484b702acfd2acdfb5c172aa3a581f"
    $a25="408610bc629bf7ebae9f88a6fe484b702acfd2acdfb5c172aa3a581f"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13) or ($a14 and $a15) or ($a16 and $a17) or ($a18 and $a19) or ($a20 and $a21) or ($a22 and $a23) or ($a24 and $a25)
}

rule sha512_hashed_default_creds_apache
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for apache. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="c7ad44cbad762a5da0a452f9e854fdc1e0e7a52a38015f23f3eab1d80b931dd472634dfac71cd34ebc35d16ab7fb8a90c81f975113d6c7538dc69dd8de9077ec"
    $a1="c7ad44cbad762a5da0a452f9e854fdc1e0e7a52a38015f23f3eab1d80b931dd472634dfac71cd34ebc35d16ab7fb8a90c81f975113d6c7538dc69dd8de9077ec"
    $a2="c7ad44cbad762a5da0a452f9e854fdc1e0e7a52a38015f23f3eab1d80b931dd472634dfac71cd34ebc35d16ab7fb8a90c81f975113d6c7538dc69dd8de9077ec"
    $a3="cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e"
    $a4="c7ad44cbad762a5da0a452f9e854fdc1e0e7a52a38015f23f3eab1d80b931dd472634dfac71cd34ebc35d16ab7fb8a90c81f975113d6c7538dc69dd8de9077ec"
    $a5="12e56030fa27a05d2576a19fe7ad93812cc18a5b25cf8d24c87be64dbf8bc27b44f0890e7dae2ae21dcb2a6fa2b942cedc448c1fefd58db7dd84b93a22285c8b"
    $a6="c7ad44cbad762a5da0a452f9e854fdc1e0e7a52a38015f23f3eab1d80b931dd472634dfac71cd34ebc35d16ab7fb8a90c81f975113d6c7538dc69dd8de9077ec"
    $a7="277ae7881360f9b763d0ad7d591b7d3d40f3477845db64001eeec1dd01ff6f54a91a4092ee90c300cebabdac73c46f11ab7175de1d1eb6579789ffedd48b8ef5"
    $a8="c7ad44cbad762a5da0a452f9e854fdc1e0e7a52a38015f23f3eab1d80b931dd472634dfac71cd34ebc35d16ab7fb8a90c81f975113d6c7538dc69dd8de9077ec"
    $a9="dbfb11615e2c89588580cc564adad47794662d667bf92e47e14a493b4935ce171fde035e2799a22fa388a0e0e163afaaf6a6605d288ef2b631df38ca8916fd02"
    $a10="c07be648d2567a2f9f2f4111480bfcc72cba9f216e52502f6d7521825781bd0ad18322e38f0b56593802665be05584dcaeb7803f3cebf7eabe494e65ebdabe3f"
    $a11="dbfb11615e2c89588580cc564adad47794662d667bf92e47e14a493b4935ce171fde035e2799a22fa388a0e0e163afaaf6a6605d288ef2b631df38ca8916fd02"
    $a12="baffb97f439eead41b57785cc3fd39c30d4c3e8794828f468875bc2c9f89deba60721a2b758176fda4b014c7e704150e95901ea3f8c233dc4ba3cdd8788ea974"
    $a13="baffb97f439eead41b57785cc3fd39c30d4c3e8794828f468875bc2c9f89deba60721a2b758176fda4b014c7e704150e95901ea3f8c233dc4ba3cdd8788ea974"
    $a14="baffb97f439eead41b57785cc3fd39c30d4c3e8794828f468875bc2c9f89deba60721a2b758176fda4b014c7e704150e95901ea3f8c233dc4ba3cdd8788ea974"
    $a15="dbfb11615e2c89588580cc564adad47794662d667bf92e47e14a493b4935ce171fde035e2799a22fa388a0e0e163afaaf6a6605d288ef2b631df38ca8916fd02"
    $a16="1d10da3967b0efd570cdee10a68a8eb08fbbce0985e838fa82e8f24cd439c308649b550e9e843ed2aa478b903b00ac8d5f28b97db7ed3ee1d0ea06274e86e9fa"
    $a17="3f9c78835c19cd6ebf0cc32f889002a38df51cda21bc8a1c063ba380c223dfbdd4934a7f723b38041f4cb4b44ab90b711e6feed23241241de47a1cc72e430e25"
    $a18="99adc231b045331e514a516b4b7680f588e3823213abe901738bc3ad67b2f6fcb3c64efb93d18002588d3ccc1a49efbae1ce20cb43df36b38651f11fa75678e8"
    $a19="3f9c78835c19cd6ebf0cc32f889002a38df51cda21bc8a1c063ba380c223dfbdd4934a7f723b38041f4cb4b44ab90b711e6feed23241241de47a1cc72e430e25"
    $a20="99adc231b045331e514a516b4b7680f588e3823213abe901738bc3ad67b2f6fcb3c64efb93d18002588d3ccc1a49efbae1ce20cb43df36b38651f11fa75678e8"
    $a21="99adc231b045331e514a516b4b7680f588e3823213abe901738bc3ad67b2f6fcb3c64efb93d18002588d3ccc1a49efbae1ce20cb43df36b38651f11fa75678e8"
    $a22="dbfb11615e2c89588580cc564adad47794662d667bf92e47e14a493b4935ce171fde035e2799a22fa388a0e0e163afaaf6a6605d288ef2b631df38ca8916fd02"
    $a23="3f9c78835c19cd6ebf0cc32f889002a38df51cda21bc8a1c063ba380c223dfbdd4934a7f723b38041f4cb4b44ab90b711e6feed23241241de47a1cc72e430e25"
    $a24="dbfb11615e2c89588580cc564adad47794662d667bf92e47e14a493b4935ce171fde035e2799a22fa388a0e0e163afaaf6a6605d288ef2b631df38ca8916fd02"
    $a25="dbfb11615e2c89588580cc564adad47794662d667bf92e47e14a493b4935ce171fde035e2799a22fa388a0e0e163afaaf6a6605d288ef2b631df38ca8916fd02"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13) or ($a14 and $a15) or ($a16 and $a17) or ($a18 and $a19) or ($a20 and $a21) or ($a22 and $a23) or ($a24 and $a25)
}

rule sha256_hashed_default_creds_apache
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for apache. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="8c6976e5b5410415bde908bd4dee15dfb167a9c873fc4bb8a81f6f2ab448a918"
    $a1="8c6976e5b5410415bde908bd4dee15dfb167a9c873fc4bb8a81f6f2ab448a918"
    $a2="8c6976e5b5410415bde908bd4dee15dfb167a9c873fc4bb8a81f6f2ab448a918"
    $a3="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    $a4="8c6976e5b5410415bde908bd4dee15dfb167a9c873fc4bb8a81f6f2ab448a918"
    $a5="56c38f358879bb1795ed9207167936d94710eee6d6380798ec62c9d10e40ec01"
    $a6="8c6976e5b5410415bde908bd4dee15dfb167a9c873fc4bb8a81f6f2ab448a918"
    $a7="51352afa310882a95a923680d65d44fd33fb1468849914882b474273ddf506c9"
    $a8="8c6976e5b5410415bde908bd4dee15dfb167a9c873fc4bb8a81f6f2ab448a918"
    $a9="51b912f34ae18b4e5ad349f50bc6fdd8d9a605d09bab4f302a09c7f790854296"
    $a10="ff7772053abf7d817d6eec229a09e14f0d1552f1cb0aeedb2ac73784ac2d2e39"
    $a11="51b912f34ae18b4e5ad349f50bc6fdd8d9a605d09bab4f302a09c7f790854296"
    $a12="07ffa23817eb0c999f8e126a39db481e61fe4cd14a47b700ddf8c9b31718f912"
    $a13="07ffa23817eb0c999f8e126a39db481e61fe4cd14a47b700ddf8c9b31718f912"
    $a14="07ffa23817eb0c999f8e126a39db481e61fe4cd14a47b700ddf8c9b31718f912"
    $a15="51b912f34ae18b4e5ad349f50bc6fdd8d9a605d09bab4f302a09c7f790854296"
    $a16="4b168d88dc872a7753c2bc35b36a2d4249487af55baf78f247f38cae2fe962da"
    $a17="62f196fe59c6f78d7f332ae80f55e6e869d8e7fbc589855b5a1a21b9249408ca"
    $a18="4813494d137e1631bba301d5acab6e7bb7aa74ce1185d456565ef51d737677b2"
    $a19="62f196fe59c6f78d7f332ae80f55e6e869d8e7fbc589855b5a1a21b9249408ca"
    $a20="4813494d137e1631bba301d5acab6e7bb7aa74ce1185d456565ef51d737677b2"
    $a21="4813494d137e1631bba301d5acab6e7bb7aa74ce1185d456565ef51d737677b2"
    $a22="51b912f34ae18b4e5ad349f50bc6fdd8d9a605d09bab4f302a09c7f790854296"
    $a23="62f196fe59c6f78d7f332ae80f55e6e869d8e7fbc589855b5a1a21b9249408ca"
    $a24="51b912f34ae18b4e5ad349f50bc6fdd8d9a605d09bab4f302a09c7f790854296"
    $a25="51b912f34ae18b4e5ad349f50bc6fdd8d9a605d09bab4f302a09c7f790854296"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13) or ($a14 and $a15) or ($a16 and $a17) or ($a18 and $a19) or ($a20 and $a21) or ($a22 and $a23) or ($a24 and $a25)
}

rule blake2b_hashed_default_creds_apache
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for apache. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="bfcce2c19c8563fd4aa66f6ec607341ff25e5f6fe7fa520d7d1242d871385f23a3e8e80093120b4877d79535e10b182ae2ec8937d1f72f091e7178c9e4ff0f11"
    $a1="bfcce2c19c8563fd4aa66f6ec607341ff25e5f6fe7fa520d7d1242d871385f23a3e8e80093120b4877d79535e10b182ae2ec8937d1f72f091e7178c9e4ff0f11"
    $a2="bfcce2c19c8563fd4aa66f6ec607341ff25e5f6fe7fa520d7d1242d871385f23a3e8e80093120b4877d79535e10b182ae2ec8937d1f72f091e7178c9e4ff0f11"
    $a3="786a02f742015903c6c6fd852552d272912f4740e15847618a86e217f71f5419d25e1031afee585313896444934eb04b903a685b1448b755d56f701afe9be2ce"
    $a4="bfcce2c19c8563fd4aa66f6ec607341ff25e5f6fe7fa520d7d1242d871385f23a3e8e80093120b4877d79535e10b182ae2ec8937d1f72f091e7178c9e4ff0f11"
    $a5="18f12f5c1a56ccdfda8d9b94593dfd95933277247e65293e4a415a2b4d554920f46e1022d13e0b06df11d44558e424976e30a6f2eecb23513b72a2c35c5da540"
    $a6="bfcce2c19c8563fd4aa66f6ec607341ff25e5f6fe7fa520d7d1242d871385f23a3e8e80093120b4877d79535e10b182ae2ec8937d1f72f091e7178c9e4ff0f11"
    $a7="ad90c64d728bd62d04b5903c2d4f1a0ec3fbc685905f80c234b617843748729e4877c4ce57b59e391cd60d43001c405b8a9628af327f220320c5165b1fee8cb6"
    $a8="bfcce2c19c8563fd4aa66f6ec607341ff25e5f6fe7fa520d7d1242d871385f23a3e8e80093120b4877d79535e10b182ae2ec8937d1f72f091e7178c9e4ff0f11"
    $a9="079ecd5104845415dc3618be63202470f82c2b3e323535d5ce98fa37b89dae3cedbc9715f1172749b3b5210743fec7f7db0eb8ec8e768d16663f092cb4501b32"
    $a10="b5c0a1fb41ff07364f22cd7b2ef91593d568dcd262c1085f9ff62f2fa353d1f47cd760a24a1aac67f6c17bb453b7f54495058cd0c6277086ef5841a7cf7f5f6f"
    $a11="079ecd5104845415dc3618be63202470f82c2b3e323535d5ce98fa37b89dae3cedbc9715f1172749b3b5210743fec7f7db0eb8ec8e768d16663f092cb4501b32"
    $a12="9578fb2c4c1889028b0f2685c1a1001c37589dfb2198c6f09c7fd2ad0de7ffc77440cc529beb502c925789bd01325c96065adf46f630e8a0213fa69418e505cc"
    $a13="9578fb2c4c1889028b0f2685c1a1001c37589dfb2198c6f09c7fd2ad0de7ffc77440cc529beb502c925789bd01325c96065adf46f630e8a0213fa69418e505cc"
    $a14="9578fb2c4c1889028b0f2685c1a1001c37589dfb2198c6f09c7fd2ad0de7ffc77440cc529beb502c925789bd01325c96065adf46f630e8a0213fa69418e505cc"
    $a15="079ecd5104845415dc3618be63202470f82c2b3e323535d5ce98fa37b89dae3cedbc9715f1172749b3b5210743fec7f7db0eb8ec8e768d16663f092cb4501b32"
    $a16="56135c23154561911ab76716e839d99ff7bc440bfa17317632bda26498c66612d72d65dd4c37c8b5b8998ba9c1ca5ced5c812f9e269fb655dae2251ad8b93800"
    $a17="3f54213631a128a35fe7e3db6caaad1fd3ce615bcfa681fcd223f455cffeb7a553bfa5cd8a6c8d2bf087c94b600fc72e76972282af2de24e6ef9a70c88a283d3"
    $a18="da23f3a4e096b0816ec2070050eac6cd9243240dad0b5cde6573e41d6852939ac5468aa9d81b5fbe156feb231a069f5afe8a5146630abc7807b1e0dcdaeb049a"
    $a19="3f54213631a128a35fe7e3db6caaad1fd3ce615bcfa681fcd223f455cffeb7a553bfa5cd8a6c8d2bf087c94b600fc72e76972282af2de24e6ef9a70c88a283d3"
    $a20="da23f3a4e096b0816ec2070050eac6cd9243240dad0b5cde6573e41d6852939ac5468aa9d81b5fbe156feb231a069f5afe8a5146630abc7807b1e0dcdaeb049a"
    $a21="da23f3a4e096b0816ec2070050eac6cd9243240dad0b5cde6573e41d6852939ac5468aa9d81b5fbe156feb231a069f5afe8a5146630abc7807b1e0dcdaeb049a"
    $a22="079ecd5104845415dc3618be63202470f82c2b3e323535d5ce98fa37b89dae3cedbc9715f1172749b3b5210743fec7f7db0eb8ec8e768d16663f092cb4501b32"
    $a23="3f54213631a128a35fe7e3db6caaad1fd3ce615bcfa681fcd223f455cffeb7a553bfa5cd8a6c8d2bf087c94b600fc72e76972282af2de24e6ef9a70c88a283d3"
    $a24="079ecd5104845415dc3618be63202470f82c2b3e323535d5ce98fa37b89dae3cedbc9715f1172749b3b5210743fec7f7db0eb8ec8e768d16663f092cb4501b32"
    $a25="079ecd5104845415dc3618be63202470f82c2b3e323535d5ce98fa37b89dae3cedbc9715f1172749b3b5210743fec7f7db0eb8ec8e768d16663f092cb4501b32"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13) or ($a14 and $a15) or ($a16 and $a17) or ($a18 and $a19) or ($a20 and $a21) or ($a22 and $a23) or ($a24 and $a25)
}

rule blake2s_hashed_default_creds_apache
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for apache. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="327e7e3821f5f6d33c090137f979bf48ee62e9051c1610e1d6468ecb3c67a124"
    $a1="327e7e3821f5f6d33c090137f979bf48ee62e9051c1610e1d6468ecb3c67a124"
    $a2="327e7e3821f5f6d33c090137f979bf48ee62e9051c1610e1d6468ecb3c67a124"
    $a3="69217a3079908094e11121d042354a7c1f55b6482ca1a51e1b250dfd1ed0eef9"
    $a4="327e7e3821f5f6d33c090137f979bf48ee62e9051c1610e1d6468ecb3c67a124"
    $a5="3316201dbb4e7f02221ac4d3a884b1807e10ef8c799f21f6db4e46fc8ad668f9"
    $a6="327e7e3821f5f6d33c090137f979bf48ee62e9051c1610e1d6468ecb3c67a124"
    $a7="884b1ebe0f69d6c8963abec594114c57dcb5eef5570cbce561fe52131d82e7aa"
    $a8="327e7e3821f5f6d33c090137f979bf48ee62e9051c1610e1d6468ecb3c67a124"
    $a9="6842e2f9d41bd74a4bca6730a202f3720a636871346da27a9d66a67f0b2c21d6"
    $a10="b247485de967c91c22381477ffd22f6d6a47d17840838f9bc82d59ce194ee86b"
    $a11="6842e2f9d41bd74a4bca6730a202f3720a636871346da27a9d66a67f0b2c21d6"
    $a12="27f8b4c1066188eb30730d02a4f8107738f6a25b43ea0b1e973f0cd5820c7bf5"
    $a13="27f8b4c1066188eb30730d02a4f8107738f6a25b43ea0b1e973f0cd5820c7bf5"
    $a14="27f8b4c1066188eb30730d02a4f8107738f6a25b43ea0b1e973f0cd5820c7bf5"
    $a15="6842e2f9d41bd74a4bca6730a202f3720a636871346da27a9d66a67f0b2c21d6"
    $a16="caeb6513252c04f10b19e00da9f5942a05f888c15793bfe513194f3ec22f034b"
    $a17="5211573598417a43a6cc4faffbe9eecc5e1588a7a26b7068cc6a3bed4d2f1647"
    $a18="0cb8a879dc5d94ed67eb49cc7a4d3052d6a346f2e28fcd9e10e5822aba92eb39"
    $a19="5211573598417a43a6cc4faffbe9eecc5e1588a7a26b7068cc6a3bed4d2f1647"
    $a20="0cb8a879dc5d94ed67eb49cc7a4d3052d6a346f2e28fcd9e10e5822aba92eb39"
    $a21="0cb8a879dc5d94ed67eb49cc7a4d3052d6a346f2e28fcd9e10e5822aba92eb39"
    $a22="6842e2f9d41bd74a4bca6730a202f3720a636871346da27a9d66a67f0b2c21d6"
    $a23="5211573598417a43a6cc4faffbe9eecc5e1588a7a26b7068cc6a3bed4d2f1647"
    $a24="6842e2f9d41bd74a4bca6730a202f3720a636871346da27a9d66a67f0b2c21d6"
    $a25="6842e2f9d41bd74a4bca6730a202f3720a636871346da27a9d66a67f0b2c21d6"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13) or ($a14 and $a15) or ($a16 and $a17) or ($a18 and $a19) or ($a20 and $a21) or ($a22 and $a23) or ($a24 and $a25)
}

rule sha3_224_hashed_default_creds_apache
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for apache. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="a53fff8dd075bed169e164743231ff533d8b9260b0b8073f0a4c1d20"
    $a1="a53fff8dd075bed169e164743231ff533d8b9260b0b8073f0a4c1d20"
    $a2="a53fff8dd075bed169e164743231ff533d8b9260b0b8073f0a4c1d20"
    $a3="6b4e03423667dbb73b6e15454f0eb1abd4597f9a1b078e3f5b5a6bc7"
    $a4="a53fff8dd075bed169e164743231ff533d8b9260b0b8073f0a4c1d20"
    $a5="0d8e7588707fba48daee7d5c84183abba58d4f50c6e15088642f010f"
    $a6="a53fff8dd075bed169e164743231ff533d8b9260b0b8073f0a4c1d20"
    $a7="31565b1d31eafd54b573745efeae3b76f95ada17305cb7e21d0c2450"
    $a8="a53fff8dd075bed169e164743231ff533d8b9260b0b8073f0a4c1d20"
    $a9="9d8cbed9a6bb66e170ef71639d4d29778a0ee1fb7155e648b9b4954c"
    $a10="ad46837af4f88a6dac6ebe92cd110b90db1f097a90408c319d4f29e0"
    $a11="9d8cbed9a6bb66e170ef71639d4d29778a0ee1fb7155e648b9b4954c"
    $a12="6d83e0f1cd0affb9f25b7e774dae50debaddaf4fdaaf34ad317a0b3b"
    $a13="6d83e0f1cd0affb9f25b7e774dae50debaddaf4fdaaf34ad317a0b3b"
    $a14="6d83e0f1cd0affb9f25b7e774dae50debaddaf4fdaaf34ad317a0b3b"
    $a15="9d8cbed9a6bb66e170ef71639d4d29778a0ee1fb7155e648b9b4954c"
    $a16="3de8fdca6bf5a52ee0ab0c0245531ffae08c7d3e758cec41cd919cac"
    $a17="ed42fc69ab147f031e6e8dd087c0a6fcb5b85a09629d74d265759807"
    $a18="3e42295e89a3a84ce7ee38e2ba317aeb57ca3164459bdf48f4da0e92"
    $a19="ed42fc69ab147f031e6e8dd087c0a6fcb5b85a09629d74d265759807"
    $a20="3e42295e89a3a84ce7ee38e2ba317aeb57ca3164459bdf48f4da0e92"
    $a21="3e42295e89a3a84ce7ee38e2ba317aeb57ca3164459bdf48f4da0e92"
    $a22="9d8cbed9a6bb66e170ef71639d4d29778a0ee1fb7155e648b9b4954c"
    $a23="ed42fc69ab147f031e6e8dd087c0a6fcb5b85a09629d74d265759807"
    $a24="9d8cbed9a6bb66e170ef71639d4d29778a0ee1fb7155e648b9b4954c"
    $a25="9d8cbed9a6bb66e170ef71639d4d29778a0ee1fb7155e648b9b4954c"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13) or ($a14 and $a15) or ($a16 and $a17) or ($a18 and $a19) or ($a20 and $a21) or ($a22 and $a23) or ($a24 and $a25)
}

rule sha3_256_hashed_default_creds_apache
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for apache. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="fb001dfcffd1c899f3297871406242f097aecf1a5342ccf3ebcd116146188e4b"
    $a1="fb001dfcffd1c899f3297871406242f097aecf1a5342ccf3ebcd116146188e4b"
    $a2="fb001dfcffd1c899f3297871406242f097aecf1a5342ccf3ebcd116146188e4b"
    $a3="a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a"
    $a4="fb001dfcffd1c899f3297871406242f097aecf1a5342ccf3ebcd116146188e4b"
    $a5="4dc8b05b12cd3c49153ec4ab9f8181be5320719e24e2e8f15ef90d3a9912221b"
    $a6="fb001dfcffd1c899f3297871406242f097aecf1a5342ccf3ebcd116146188e4b"
    $a7="4cfc76b600f6959e2a215fc5c54330e22f698050841e21b90c4088ca30f164f0"
    $a8="fb001dfcffd1c899f3297871406242f097aecf1a5342ccf3ebcd116146188e4b"
    $a9="85aee8bedf1098a3f4b1a92ea65824982e362fff3411d4505dba8dc43fa4274a"
    $a10="cc46ba5c3e77e1b482801597d5d672d8e2e7bb01228c8faa44110b3d6189aac1"
    $a11="85aee8bedf1098a3f4b1a92ea65824982e362fff3411d4505dba8dc43fa4274a"
    $a12="dac10a69404388ad62ac4485b200db1e14d043e7a8d2c128ae69c2c1de068f5b"
    $a13="dac10a69404388ad62ac4485b200db1e14d043e7a8d2c128ae69c2c1de068f5b"
    $a14="dac10a69404388ad62ac4485b200db1e14d043e7a8d2c128ae69c2c1de068f5b"
    $a15="85aee8bedf1098a3f4b1a92ea65824982e362fff3411d4505dba8dc43fa4274a"
    $a16="78a5fe483b9c1de67f7342ce57fb58e17ce69c949d8ff857e2cc531c323d61bc"
    $a17="df6c9c0063d293b2b582b84e6f3c993a4cc358f6cf049d06ec19e00a95059690"
    $a18="a00e4d3b352e9d11979549b9eef5dc951592f594488451e6cd86fdc4bce76a53"
    $a19="df6c9c0063d293b2b582b84e6f3c993a4cc358f6cf049d06ec19e00a95059690"
    $a20="a00e4d3b352e9d11979549b9eef5dc951592f594488451e6cd86fdc4bce76a53"
    $a21="a00e4d3b352e9d11979549b9eef5dc951592f594488451e6cd86fdc4bce76a53"
    $a22="85aee8bedf1098a3f4b1a92ea65824982e362fff3411d4505dba8dc43fa4274a"
    $a23="df6c9c0063d293b2b582b84e6f3c993a4cc358f6cf049d06ec19e00a95059690"
    $a24="85aee8bedf1098a3f4b1a92ea65824982e362fff3411d4505dba8dc43fa4274a"
    $a25="85aee8bedf1098a3f4b1a92ea65824982e362fff3411d4505dba8dc43fa4274a"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13) or ($a14 and $a15) or ($a16 and $a17) or ($a18 and $a19) or ($a20 and $a21) or ($a22 and $a23) or ($a24 and $a25)
}

rule sha3_384_hashed_default_creds_apache
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for apache. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="9765a57f2010506383de91052915ce8bafbdb39f3e5a8c1a1693a0076365d37abbfd3305881ea3b5fa1426316afd7df3"
    $a1="9765a57f2010506383de91052915ce8bafbdb39f3e5a8c1a1693a0076365d37abbfd3305881ea3b5fa1426316afd7df3"
    $a2="9765a57f2010506383de91052915ce8bafbdb39f3e5a8c1a1693a0076365d37abbfd3305881ea3b5fa1426316afd7df3"
    $a3="0c63a75b845e4f7d01107d852e4c2485c51a50aaaa94fc61995e71bbee983a2ac3713831264adb47fb6bd1e058d5f004"
    $a4="9765a57f2010506383de91052915ce8bafbdb39f3e5a8c1a1693a0076365d37abbfd3305881ea3b5fa1426316afd7df3"
    $a5="fbea380be13719486a2bf0e03a60152bc75d89e7c3e9ac25397af9cdb54fd75294ace3b5402452f1e6a02070c71dd2f7"
    $a6="9765a57f2010506383de91052915ce8bafbdb39f3e5a8c1a1693a0076365d37abbfd3305881ea3b5fa1426316afd7df3"
    $a7="60b3eef0d556ad8db1b1911e337527ae834b29f518a447088c72c4bcc515892f7b1e01a3746b0eb091fa78f797007bab"
    $a8="9765a57f2010506383de91052915ce8bafbdb39f3e5a8c1a1693a0076365d37abbfd3305881ea3b5fa1426316afd7df3"
    $a9="09d437fba875a597a6d2a4715c2a5650fe66611c10a306e12453cb7343ff02e1a30b1cba523a6deae1f252ae2f60cb55"
    $a10="a1f5255687bf673ce2b0274732b948132c9e2795ace12b986c5ca721bc80c4283ba6edf00b620c887abe4220d5d57def"
    $a11="09d437fba875a597a6d2a4715c2a5650fe66611c10a306e12453cb7343ff02e1a30b1cba523a6deae1f252ae2f60cb55"
    $a12="2e3919ec48ad5159368a56e09764a055dffd3371d8b1505058d2870fd6254f22c85ef6fa2d02084b6b74db20e74ace4b"
    $a13="2e3919ec48ad5159368a56e09764a055dffd3371d8b1505058d2870fd6254f22c85ef6fa2d02084b6b74db20e74ace4b"
    $a14="2e3919ec48ad5159368a56e09764a055dffd3371d8b1505058d2870fd6254f22c85ef6fa2d02084b6b74db20e74ace4b"
    $a15="09d437fba875a597a6d2a4715c2a5650fe66611c10a306e12453cb7343ff02e1a30b1cba523a6deae1f252ae2f60cb55"
    $a16="ac99676e05cf6a08437d21843ea0824dbe23e8a1e399b04bbb21d4a2ca04f3bcc1eb70356f8251702c4cb75ce74b732a"
    $a17="435f09fa12c71aac27c792a47a224b24f5affe8b99b3b183e26bbea0802179e9b7c96c24aa2fd9fd93d359a2f801fb87"
    $a18="aac595410801e93eadb099ac575ccc12e43be2c15e31e7991e908329e5beb0729881b3be9ccdb0eeb6eb79335ea38b6d"
    $a19="435f09fa12c71aac27c792a47a224b24f5affe8b99b3b183e26bbea0802179e9b7c96c24aa2fd9fd93d359a2f801fb87"
    $a20="aac595410801e93eadb099ac575ccc12e43be2c15e31e7991e908329e5beb0729881b3be9ccdb0eeb6eb79335ea38b6d"
    $a21="aac595410801e93eadb099ac575ccc12e43be2c15e31e7991e908329e5beb0729881b3be9ccdb0eeb6eb79335ea38b6d"
    $a22="09d437fba875a597a6d2a4715c2a5650fe66611c10a306e12453cb7343ff02e1a30b1cba523a6deae1f252ae2f60cb55"
    $a23="435f09fa12c71aac27c792a47a224b24f5affe8b99b3b183e26bbea0802179e9b7c96c24aa2fd9fd93d359a2f801fb87"
    $a24="09d437fba875a597a6d2a4715c2a5650fe66611c10a306e12453cb7343ff02e1a30b1cba523a6deae1f252ae2f60cb55"
    $a25="09d437fba875a597a6d2a4715c2a5650fe66611c10a306e12453cb7343ff02e1a30b1cba523a6deae1f252ae2f60cb55"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13) or ($a14 and $a15) or ($a16 and $a17) or ($a18 and $a19) or ($a20 and $a21) or ($a22 and $a23) or ($a24 and $a25)
}

rule sha3_512_hashed_default_creds_apache
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for apache. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="5a38afb1a18d408e6cd367f9db91e2ab9bce834cdad3da24183cc174956c20ce35dd39c2bd36aae907111ae3d6ada353f7697a5f1a8fc567aae9e4ca41a9d19d"
    $a1="5a38afb1a18d408e6cd367f9db91e2ab9bce834cdad3da24183cc174956c20ce35dd39c2bd36aae907111ae3d6ada353f7697a5f1a8fc567aae9e4ca41a9d19d"
    $a2="5a38afb1a18d408e6cd367f9db91e2ab9bce834cdad3da24183cc174956c20ce35dd39c2bd36aae907111ae3d6ada353f7697a5f1a8fc567aae9e4ca41a9d19d"
    $a3="a69f73cca23a9ac5c8b567dc185a756e97c982164fe25859e0d1dcc1475c80a615b2123af1f5f94c11e3e9402c3ac558f500199d95b6d3e301758586281dcd26"
    $a4="5a38afb1a18d408e6cd367f9db91e2ab9bce834cdad3da24183cc174956c20ce35dd39c2bd36aae907111ae3d6ada353f7697a5f1a8fc567aae9e4ca41a9d19d"
    $a5="53c1261f538e5549dbd4a7e6a517bf4d4c9b376ef37c9d1f21a8e2b8442293cb25caa679c8340afb3eedf6ffd95b67f6f513041e60f4688d8be2c9cfe00a8a12"
    $a6="5a38afb1a18d408e6cd367f9db91e2ab9bce834cdad3da24183cc174956c20ce35dd39c2bd36aae907111ae3d6ada353f7697a5f1a8fc567aae9e4ca41a9d19d"
    $a7="12abcaefa70d2aafa25bde31d10ec1da1f651162ef56a7d72ca6f5b980287190fe2c9fdc9323fa340148d0972623b20d35129d731251067a53ded768353376dd"
    $a8="5a38afb1a18d408e6cd367f9db91e2ab9bce834cdad3da24183cc174956c20ce35dd39c2bd36aae907111ae3d6ada353f7697a5f1a8fc567aae9e4ca41a9d19d"
    $a9="c88285cd2d822ce855c61d9028b33255bf4db6542b9ffd442865b75576a4c7dbd44c1d3607eb7a74c909958fb14acf3d6581dbd1dee340077e25fab39bd8c6b1"
    $a10="214792f4d4eef8c51da4491670ae8bbfd1ddce01cac0b04e0f216fa49997e199b24cf15903a548705ddf18dd489994ecc7e5f4b4f235a5a60192f7bc9ae45552"
    $a11="c88285cd2d822ce855c61d9028b33255bf4db6542b9ffd442865b75576a4c7dbd44c1d3607eb7a74c909958fb14acf3d6581dbd1dee340077e25fab39bd8c6b1"
    $a12="e41c62cf3ce76d6755bef884a70f2c805530dcb475aa46d38e3b7a5bb9437fcf9f10f0e5dcaf0d372af8a803079f1f55fe5415c5c3ebdda99d730949800de3a0"
    $a13="e41c62cf3ce76d6755bef884a70f2c805530dcb475aa46d38e3b7a5bb9437fcf9f10f0e5dcaf0d372af8a803079f1f55fe5415c5c3ebdda99d730949800de3a0"
    $a14="e41c62cf3ce76d6755bef884a70f2c805530dcb475aa46d38e3b7a5bb9437fcf9f10f0e5dcaf0d372af8a803079f1f55fe5415c5c3ebdda99d730949800de3a0"
    $a15="c88285cd2d822ce855c61d9028b33255bf4db6542b9ffd442865b75576a4c7dbd44c1d3607eb7a74c909958fb14acf3d6581dbd1dee340077e25fab39bd8c6b1"
    $a16="acbc23336b1e3c84f06eccd8fc0ecf0a9d470570559965c24038948e7a873b3f03208e509f22120098396e7fc3aeb26d4400471c536f7bd670fd2a9bcb3987c8"
    $a17="0096acfe21d72e5b3e141d5a49068288b1926882b06ecfeae7d86c260bdc83371ad93175dea3d3ba01846e8acc3eb5bbc61d1cf5ba75fa9acef42c22946f9228"
    $a18="8cd824c700eb0c125fff40c8c185d14c5dfe7f32814afac079ba7c20d93bc3c082193243c420fed22ef2474fbb85880e7bc1ca772150a1f759f8ddebca77711f"
    $a19="0096acfe21d72e5b3e141d5a49068288b1926882b06ecfeae7d86c260bdc83371ad93175dea3d3ba01846e8acc3eb5bbc61d1cf5ba75fa9acef42c22946f9228"
    $a20="8cd824c700eb0c125fff40c8c185d14c5dfe7f32814afac079ba7c20d93bc3c082193243c420fed22ef2474fbb85880e7bc1ca772150a1f759f8ddebca77711f"
    $a21="8cd824c700eb0c125fff40c8c185d14c5dfe7f32814afac079ba7c20d93bc3c082193243c420fed22ef2474fbb85880e7bc1ca772150a1f759f8ddebca77711f"
    $a22="c88285cd2d822ce855c61d9028b33255bf4db6542b9ffd442865b75576a4c7dbd44c1d3607eb7a74c909958fb14acf3d6581dbd1dee340077e25fab39bd8c6b1"
    $a23="0096acfe21d72e5b3e141d5a49068288b1926882b06ecfeae7d86c260bdc83371ad93175dea3d3ba01846e8acc3eb5bbc61d1cf5ba75fa9acef42c22946f9228"
    $a24="c88285cd2d822ce855c61d9028b33255bf4db6542b9ffd442865b75576a4c7dbd44c1d3607eb7a74c909958fb14acf3d6581dbd1dee340077e25fab39bd8c6b1"
    $a25="c88285cd2d822ce855c61d9028b33255bf4db6542b9ffd442865b75576a4c7dbd44c1d3607eb7a74c909958fb14acf3d6581dbd1dee340077e25fab39bd8c6b1"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13) or ($a14 and $a15) or ($a16 and $a17) or ($a18 and $a19) or ($a20 and $a21) or ($a22 and $a23) or ($a24 and $a25)
}

rule base64_hashed_default_creds_apache
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for apache. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="YWRtaW4="
    $a1="YWRtaW4="
    $a2="YWRtaW4="
    $a3="===="
    $a4="YWRtaW4="
    $a5="ajVCcm45"
    $a6="YWRtaW4="
    $a7="amJvc3M0"
    $a8="YWRtaW4="
    $a9="dG9tY2F0"
    $a10="Ym90aA=="
    $a11="dG9tY2F0"
    $a12="cm9sZTE="
    $a13="cm9sZTE="
    $a14="cm9sZTE="
    $a15="dG9tY2F0"
    $a16="cm9sZQ=="
    $a17="Y2hhbmdldGhpcw=="
    $a18="cm9vdA=="
    $a19="Y2hhbmdldGhpcw=="
    $a20="cm9vdA=="
    $a21="cm9vdA=="
    $a22="dG9tY2F0"
    $a23="Y2hhbmdldGhpcw=="
    $a24="dG9tY2F0"
    $a25="dG9tY2F0"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13) or ($a14 and $a15) or ($a16 and $a17) or ($a18 and $a19) or ($a20 and $a21) or ($a22 and $a23) or ($a24 and $a25)
}

