/*This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as long as you use it under this license.*/

rule md5_hashed_default_creds_intel
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for intel. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="21232f297a57a5a743894a0e4a801fc3"
    $a1="d41d8cd98f00b204e9800998ecf8427e"
    $a2="d41d8cd98f00b204e9800998ecf8427e"
    $a3="d41d8cd98f00b204e9800998ecf8427e"
    $a4="d41d8cd98f00b204e9800998ecf8427e"
    $a5="ff97a9fdede09eaf6e1c8ec9f6a61dd5"
    $a6="d41d8cd98f00b204e9800998ecf8427e"
    $a7="4dd3b03fa4bcecf34c516ebfc43e7719"
    $a8="d41d8cd98f00b204e9800998ecf8427e"
    $a9="69f404925df883e0e5579d65b7768e7c"
    $a10="adb831a7fdd83dd1e2a309ce7591dff8"
    $a11="d41d8cd98f00b204e9800998ecf8427e"
    $a12="4e5bbaeafc82ab7aa1385bea8ef5d30a"
    $a13="4e5bbaeafc82ab7aa1385bea8ef5d30a"
    $a14="9e95f6d797987b7da0fb293a760fe57e"
    $a15="b123bc09e72c15d85ec90e1f1adcbd80"
    $a16="64438be651abb0d321f728f8ffdb75c5"
    $a17="64438be651abb0d321f728f8ffdb75c5"
    $a18="63a9f0ea7bb98050796b649e85481845"
    $a19="21232f297a57a5a743894a0e4a801fc3"
    $a20="63a9f0ea7bb98050796b649e85481845"
    $a21="d41d8cd98f00b204e9800998ecf8427e"
    $a22="a0f848942ce863cf53c0fa6cc684007d"
    $a23="a0f848942ce863cf53c0fa6cc684007d"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13) or ($a14 and $a15) or ($a16 and $a17) or ($a18 and $a19) or ($a20 and $a21) or ($a22 and $a23)
}

rule sha1_hashed_default_creds_intel
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for intel. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="d033e22ae348aeb5660fc2140aec35850c4da997"
    $a1="da39a3ee5e6b4b0d3255bfef95601890afd80709"
    $a2="da39a3ee5e6b4b0d3255bfef95601890afd80709"
    $a3="da39a3ee5e6b4b0d3255bfef95601890afd80709"
    $a4="da39a3ee5e6b4b0d3255bfef95601890afd80709"
    $a5="5cb70e4c165b861dee8d7db21f58c2d61f187be7"
    $a6="da39a3ee5e6b4b0d3255bfef95601890afd80709"
    $a7="4ee64af0b2223831d706d10af4775feb24fca81c"
    $a8="da39a3ee5e6b4b0d3255bfef95601890afd80709"
    $a9="848b186485107266a3807096d328690f86a22c05"
    $a10="face83ee3014bdc8f98203cc94e2e89222452e90"
    $a11="da39a3ee5e6b4b0d3255bfef95601890afd80709"
    $a12="eecddd10d7bd87d3d765bf65504605117c02ea2e"
    $a13="eecddd10d7bd87d3d765bf65504605117c02ea2e"
    $a14="eba082ff45517c06bd365c2fde1fc77cda7a8f6f"
    $a15="2c84d7a4c96c3d76f7b2b21861abb5ec39423f6d"
    $a16="6ee3c2907b311f04efecd9f7352918a970a4fe0d"
    $a17="6ee3c2907b311f04efecd9f7352918a970a4fe0d"
    $a18="dc76e9f0c0006e8f919e0c515c66dbba3982f785"
    $a19="d033e22ae348aeb5660fc2140aec35850c4da997"
    $a20="dc76e9f0c0006e8f919e0c515c66dbba3982f785"
    $a21="da39a3ee5e6b4b0d3255bfef95601890afd80709"
    $a22="80437a44a661d141174209119d54125a59a64b2a"
    $a23="80437a44a661d141174209119d54125a59a64b2a"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13) or ($a14 and $a15) or ($a16 and $a17) or ($a18 and $a19) or ($a20 and $a21) or ($a22 and $a23)
}

rule sha384_hashed_default_creds_intel
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for intel. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="9ca694a90285c034432c9550421b7b9dbd5c0f4b6673f05f6dbce58052ba20e4248041956ee8c9a2ec9f10290cdc0782"
    $a1="38b060a751ac96384cd9327eb1b1e36a21fdb71114be07434c0cc7bf63f6e1da274edebfe76f65fbd51ad2f14898b95b"
    $a2="38b060a751ac96384cd9327eb1b1e36a21fdb71114be07434c0cc7bf63f6e1da274edebfe76f65fbd51ad2f14898b95b"
    $a3="38b060a751ac96384cd9327eb1b1e36a21fdb71114be07434c0cc7bf63f6e1da274edebfe76f65fbd51ad2f14898b95b"
    $a4="38b060a751ac96384cd9327eb1b1e36a21fdb71114be07434c0cc7bf63f6e1da274edebfe76f65fbd51ad2f14898b95b"
    $a5="7db4594d021d5a28d7e46dce0fd5c71e945b7a88c25a6c9b56659a29cab6ee30964d6e9be308348383e8f561b74360d9"
    $a6="38b060a751ac96384cd9327eb1b1e36a21fdb71114be07434c0cc7bf63f6e1da274edebfe76f65fbd51ad2f14898b95b"
    $a7="516e8a4fb9b4b8dda02b4de696369abde59a78e3e64d426acb59d4469e440d6badd276cff2ce2b2ae413e5556efb0504"
    $a8="38b060a751ac96384cd9327eb1b1e36a21fdb71114be07434c0cc7bf63f6e1da274edebfe76f65fbd51ad2f14898b95b"
    $a9="4ee3d3cae10f033ead10d46925f21bd628f70d586b512de098a14e65e8f4bf260af2d5131a3055c4df96e8bf73949519"
    $a10="4477d2e5351a588186edc3371e30f1cfb64ad5f01aac0c504340342e70dafc3343c0b3e878327a8263e11ecf8dd33b30"
    $a11="38b060a751ac96384cd9327eb1b1e36a21fdb71114be07434c0cc7bf63f6e1da274edebfe76f65fbd51ad2f14898b95b"
    $a12="c901c28c86086170664e7f141cee6c27274093935d179003f14dc73f282f96da5ed0ad5609c68d035a12ea2f7ebb1b68"
    $a13="c901c28c86086170664e7f141cee6c27274093935d179003f14dc73f282f96da5ed0ad5609c68d035a12ea2f7ebb1b68"
    $a14="fba4a3defbe0652995f93f9d8be36443b67d1d959f31f6c9cfcb95f75efd14a0a0f2e67651ec90a3adb7ee7e47aa7c9d"
    $a15="eaa2adcd989acbb07569f45d3175b6c04619ffcedb57b01d741b171364c530f76972a0fc915f1a6929833a6f55df2015"
    $a16="3d7c953602338bb1e6a178791c0f9aad85184e41481c5dbcc36687ac3b1b946d9a87e9b247309bcbe76c825871a551cd"
    $a17="3d7c953602338bb1e6a178791c0f9aad85184e41481c5dbcc36687ac3b1b946d9a87e9b247309bcbe76c825871a551cd"
    $a18="7ed8c2c790aa83d6c3e404b5368f6832c18d46a0e98b9c7a7a5e3ef823e2c9f0e310abbf6f7ea9d9d883ccb64ec2736a"
    $a19="9ca694a90285c034432c9550421b7b9dbd5c0f4b6673f05f6dbce58052ba20e4248041956ee8c9a2ec9f10290cdc0782"
    $a20="7ed8c2c790aa83d6c3e404b5368f6832c18d46a0e98b9c7a7a5e3ef823e2c9f0e310abbf6f7ea9d9d883ccb64ec2736a"
    $a21="38b060a751ac96384cd9327eb1b1e36a21fdb71114be07434c0cc7bf63f6e1da274edebfe76f65fbd51ad2f14898b95b"
    $a22="daead2f5d798969185c0b94acb330300f835db65a2d91cd4095104d96b469515fce7ab29373dc30cc9ca851059e33e4f"
    $a23="daead2f5d798969185c0b94acb330300f835db65a2d91cd4095104d96b469515fce7ab29373dc30cc9ca851059e33e4f"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13) or ($a14 and $a15) or ($a16 and $a17) or ($a18 and $a19) or ($a20 and $a21) or ($a22 and $a23)
}

rule sha224_hashed_default_creds_intel
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for intel. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="58acb7acccce58ffa8b953b12b5a7702bd42dae441c1ad85057fa70b"
    $a1="d14a028c2a3a2bc9476102bb288234c415a2b01f828ea62ac5b3e42f"
    $a2="d14a028c2a3a2bc9476102bb288234c415a2b01f828ea62ac5b3e42f"
    $a3="d14a028c2a3a2bc9476102bb288234c415a2b01f828ea62ac5b3e42f"
    $a4="d14a028c2a3a2bc9476102bb288234c415a2b01f828ea62ac5b3e42f"
    $a5="de9a08365749c5f2011dcd30b1e99d3bb3081a5ccd6d0996de2b3495"
    $a6="d14a028c2a3a2bc9476102bb288234c415a2b01f828ea62ac5b3e42f"
    $a7="574398b96bd8e72a0537d6f664e1855e50264d0988bf2e9b699112f5"
    $a8="d14a028c2a3a2bc9476102bb288234c415a2b01f828ea62ac5b3e42f"
    $a9="2f02d9aab1faee97c38d1255f57c566a4d0bba679c31d9d4eb68bcf9"
    $a10="1c95d70b4960a674e2c8a0e86c3a2ada419b9b7534912790666ed9bb"
    $a11="d14a028c2a3a2bc9476102bb288234c415a2b01f828ea62ac5b3e42f"
    $a12="6eaa7e19d383862d4e6fab499b0ebf952b1ff87fb6db646f53d36d63"
    $a13="6eaa7e19d383862d4e6fab499b0ebf952b1ff87fb6db646f53d36d63"
    $a14="8c1cc174e604952e5354221d4c6294b63059e873daf690b2cc88a481"
    $a15="4676d443ce4e95237fb5ac3e499bcbc18316d1232a9aeec234ce9f92"
    $a16="a2f3de94b2cdb6e42bccdbddb2a49b9044d5a99d5c850a2f2d1ec4be"
    $a17="a2f3de94b2cdb6e42bccdbddb2a49b9044d5a99d5c850a2f2d1ec4be"
    $a18="871ce144069ea0816545f52f09cd135d1182262c3b235808fa5a3281"
    $a19="58acb7acccce58ffa8b953b12b5a7702bd42dae441c1ad85057fa70b"
    $a20="871ce144069ea0816545f52f09cd135d1182262c3b235808fa5a3281"
    $a21="d14a028c2a3a2bc9476102bb288234c415a2b01f828ea62ac5b3e42f"
    $a22="4d8f45908245b2a55cc49ddd019c70e37b4c49f2e7e948539b942ffe"
    $a23="4d8f45908245b2a55cc49ddd019c70e37b4c49f2e7e948539b942ffe"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13) or ($a14 and $a15) or ($a16 and $a17) or ($a18 and $a19) or ($a20 and $a21) or ($a22 and $a23)
}

rule sha512_hashed_default_creds_intel
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for intel. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="c7ad44cbad762a5da0a452f9e854fdc1e0e7a52a38015f23f3eab1d80b931dd472634dfac71cd34ebc35d16ab7fb8a90c81f975113d6c7538dc69dd8de9077ec"
    $a1="cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e"
    $a2="cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e"
    $a3="cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e"
    $a4="cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e"
    $a5="c405f97e2d9475a39cee82eb997bcf3442dd578167f033ca381524e1fc204174ac3e4ee0c0083a32fb3e52a58dc450149aed4a625c9b0cd44fdd93e8e22eebb8"
    $a6="cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e"
    $a7="eb4f73188666622a9c83fe6ba24c884a78062ee7b6b92345c717936a012fa2eb21ca70aa7de9af0fbabcaa65f97d8c82e80cf603c55de8117d172eee44eddbcd"
    $a8="cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e"
    $a9="6e47cbc4c9812176c609cf16c4b4ed2c97d5ba4137758bd255af780204e85ff048ebd9911f2fb9d2cefe13491c740f7b50eb5979ddae8ffd2f40520b7fea5705"
    $a10="cc5ec2b61fbbdd18d85dd14ab60db397b21b5548999a6afd3ce9557b19c300494a5fd29987e03a6f06677c209b88de47684388de8250671cdd778799eecd018a"
    $a11="cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e"
    $a12="5a738c9b375511f3219c3b866b10a3aa787dd69d259d756926b5fe6d6ced540cb6671db78b429b14542f89616367c3a4b553c28249ddbf7a5a283dd8db4399aa"
    $a13="5a738c9b375511f3219c3b866b10a3aa787dd69d259d756926b5fe6d6ced540cb6671db78b429b14542f89616367c3a4b553c28249ddbf7a5a283dd8db4399aa"
    $a14="6d9aceb1053bed5fca83b3fe6bdbb38389f2d952631668e2447615dd1e3100f49445060216879540f96e99b444715e0e2b84075e2dec6d2720c81acd3551676c"
    $a15="a5d335fa30ced7505dba4e2c87196c752dc9c6395b03fdfa1097378ede971ce78a0ee4709b75a2a625b74da29952fc01997ac61d619b29216330030094011b69"
    $a16="07a31c3f230c522b53af20859631a510635ec7e75e107f29298d5f05a988a4c7905d06edfa155ae57162a72fd7cf7ac9c1dffa658a18e8529ece6d3efb0fb05a"
    $a17="07a31c3f230c522b53af20859631a510635ec7e75e107f29298d5f05a988a4c7905d06edfa155ae57162a72fd7cf7ac9c1dffa658a18e8529ece6d3efb0fb05a"
    $a18="99adc231b045331e514a516b4b7680f588e3823213abe901738bc3ad67b2f6fcb3c64efb93d18002588d3ccc1a49efbae1ce20cb43df36b38651f11fa75678e8"
    $a19="c7ad44cbad762a5da0a452f9e854fdc1e0e7a52a38015f23f3eab1d80b931dd472634dfac71cd34ebc35d16ab7fb8a90c81f975113d6c7538dc69dd8de9077ec"
    $a20="99adc231b045331e514a516b4b7680f588e3823213abe901738bc3ad67b2f6fcb3c64efb93d18002588d3ccc1a49efbae1ce20cb43df36b38651f11fa75678e8"
    $a21="cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e"
    $a22="cd714d8864b22e5b5e0f05576843058225ee4303c3bb3b34234333f88fb4d136d93a58ecdceefd78246736cbbc35152051104e9f0397e4cc8de7b7582231fa15"
    $a23="cd714d8864b22e5b5e0f05576843058225ee4303c3bb3b34234333f88fb4d136d93a58ecdceefd78246736cbbc35152051104e9f0397e4cc8de7b7582231fa15"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13) or ($a14 and $a15) or ($a16 and $a17) or ($a18 and $a19) or ($a20 and $a21) or ($a22 and $a23)
}

rule sha256_hashed_default_creds_intel
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for intel. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="8c6976e5b5410415bde908bd4dee15dfb167a9c873fc4bb8a81f6f2ab448a918"
    $a1="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    $a2="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    $a3="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    $a4="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    $a5="9dbe1a97a6b445eaf33dad0eaefd2f5fcf997b64feda47d28f6b7352fd028171"
    $a6="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    $a7="3624d3181d5c4f8abf2f25fa708f5efa04236b79d0deafe9f292b590b2ca0f7e"
    $a8="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    $a9="eba6fd0e1aec9c8bda8e4b8f7e4e540bf0bdd03a1e95217a2f096ac66a7fa1ae"
    $a10="5ed8944a85a9763fd315852f448cb7de36c5e928e13b3be427f98f7dc455f141"
    $a11="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    $a12="96eebba49dbbf422d245f02290f9d4ed0eb02da9daa6bbceefb162800ff42481"
    $a13="96eebba49dbbf422d245f02290f9d4ed0eb02da9daa6bbceefb162800ff42481"
    $a14="1ef393f2c0772064cae9403f23e7f8fc6d49bb2939f463f23c4e637231e84da4"
    $a15="1c9aeebe6972c1fed27aae8896682b01cd3a1f035405f59b3702d8c5c90f5857"
    $a16="2d0ab8eb2fb9d408d646c1375f788b31b8b5030b5d5052f52d42cd8c375e8e68"
    $a17="2d0ab8eb2fb9d408d646c1375f788b31b8b5030b5d5052f52d42cd8c375e8e68"
    $a18="4813494d137e1631bba301d5acab6e7bb7aa74ce1185d456565ef51d737677b2"
    $a19="8c6976e5b5410415bde908bd4dee15dfb167a9c873fc4bb8a81f6f2ab448a918"
    $a20="4813494d137e1631bba301d5acab6e7bb7aa74ce1185d456565ef51d737677b2"
    $a21="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    $a22="8fb6d5f37e8055ce720bd0b1d56587f88c0071f285966ba17e72b2b12672aa73"
    $a23="8fb6d5f37e8055ce720bd0b1d56587f88c0071f285966ba17e72b2b12672aa73"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13) or ($a14 and $a15) or ($a16 and $a17) or ($a18 and $a19) or ($a20 and $a21) or ($a22 and $a23)
}

rule blake2b_hashed_default_creds_intel
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for intel. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="bfcce2c19c8563fd4aa66f6ec607341ff25e5f6fe7fa520d7d1242d871385f23a3e8e80093120b4877d79535e10b182ae2ec8937d1f72f091e7178c9e4ff0f11"
    $a1="786a02f742015903c6c6fd852552d272912f4740e15847618a86e217f71f5419d25e1031afee585313896444934eb04b903a685b1448b755d56f701afe9be2ce"
    $a2="786a02f742015903c6c6fd852552d272912f4740e15847618a86e217f71f5419d25e1031afee585313896444934eb04b903a685b1448b755d56f701afe9be2ce"
    $a3="786a02f742015903c6c6fd852552d272912f4740e15847618a86e217f71f5419d25e1031afee585313896444934eb04b903a685b1448b755d56f701afe9be2ce"
    $a4="786a02f742015903c6c6fd852552d272912f4740e15847618a86e217f71f5419d25e1031afee585313896444934eb04b903a685b1448b755d56f701afe9be2ce"
    $a5="e58b83e5870e825e1d4b8a6a372e46bfb5b6e3f450de38edebf9cf12372e02cb42e66c1d937779d44cf80e273c7c14f16de5724e965d332b4947fde839196f65"
    $a6="786a02f742015903c6c6fd852552d272912f4740e15847618a86e217f71f5419d25e1031afee585313896444934eb04b903a685b1448b755d56f701afe9be2ce"
    $a7="7371acc3e4ca80f60cce2038c5987724f16aa951b434d93d86845bc9967dcd2a5875c6dd3c2e62f0f787e268dcdbb2d1a3d1bce6d3bae52730958c9791a98e02"
    $a8="786a02f742015903c6c6fd852552d272912f4740e15847618a86e217f71f5419d25e1031afee585313896444934eb04b903a685b1448b755d56f701afe9be2ce"
    $a9="75968b520d1e5f95c5c9ecefb93b43164ada7698000cb8e368e513ef0879937b5a5848f1bce72928e7a10e8007b957b0b3c30e090b5c06db7939e6a90d8d1cf0"
    $a10="0b38c93bb2e46b2037c88ddccad59cbe1092f2ee7eb24ece6381de92d02f323865d52ac3d5a2a7da513661224b910c258184a1bbe405c9ebe1eabd83633f1e5d"
    $a11="786a02f742015903c6c6fd852552d272912f4740e15847618a86e217f71f5419d25e1031afee585313896444934eb04b903a685b1448b755d56f701afe9be2ce"
    $a12="095d371fbfeafb14db15d7875d19eac6a9b33389d79981669b888632d19d3abaa257cc5f00e836e614948735a3b63f2acd91ad6ce441ee8a0a25e0a50f7bd286"
    $a13="095d371fbfeafb14db15d7875d19eac6a9b33389d79981669b888632d19d3abaa257cc5f00e836e614948735a3b63f2acd91ad6ce441ee8a0a25e0a50f7bd286"
    $a14="42a2aa7db9e0866c30bf5765c025781ff1aa2dd444c0a3c3bf175ee7ec604d0ca47a860ac0310deaeb97da88a6657e09c11002884fc188e1117e599e185643a3"
    $a15="caecd7a0664919ab04a5dba41f0c7e43fc339feb003acd177dcda8bfacbee3fc8a2a570d28a7b072f85fe35b6b5c69380c631befecca190bc52aa9ea83c766b9"
    $a16="ff54c248b22fe064ec7b2affef94d665a565fb42237cfb86e2faf029ab2bba0bbda8a67c7de04c4ca90bc8016e7afa96e9d8522ad4e572ef308fc98df80689d2"
    $a17="ff54c248b22fe064ec7b2affef94d665a565fb42237cfb86e2faf029ab2bba0bbda8a67c7de04c4ca90bc8016e7afa96e9d8522ad4e572ef308fc98df80689d2"
    $a18="da23f3a4e096b0816ec2070050eac6cd9243240dad0b5cde6573e41d6852939ac5468aa9d81b5fbe156feb231a069f5afe8a5146630abc7807b1e0dcdaeb049a"
    $a19="bfcce2c19c8563fd4aa66f6ec607341ff25e5f6fe7fa520d7d1242d871385f23a3e8e80093120b4877d79535e10b182ae2ec8937d1f72f091e7178c9e4ff0f11"
    $a20="da23f3a4e096b0816ec2070050eac6cd9243240dad0b5cde6573e41d6852939ac5468aa9d81b5fbe156feb231a069f5afe8a5146630abc7807b1e0dcdaeb049a"
    $a21="786a02f742015903c6c6fd852552d272912f4740e15847618a86e217f71f5419d25e1031afee585313896444934eb04b903a685b1448b755d56f701afe9be2ce"
    $a22="f5b72cdd6f114cdfac80d23f52b9ccbb12c0d065362b039f392391effe37224748a410db32229647bc0bc876292b2bfdecba4a63209398354a665bed6ceb4427"
    $a23="f5b72cdd6f114cdfac80d23f52b9ccbb12c0d065362b039f392391effe37224748a410db32229647bc0bc876292b2bfdecba4a63209398354a665bed6ceb4427"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13) or ($a14 and $a15) or ($a16 and $a17) or ($a18 and $a19) or ($a20 and $a21) or ($a22 and $a23)
}

rule blake2s_hashed_default_creds_intel
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for intel. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="327e7e3821f5f6d33c090137f979bf48ee62e9051c1610e1d6468ecb3c67a124"
    $a1="69217a3079908094e11121d042354a7c1f55b6482ca1a51e1b250dfd1ed0eef9"
    $a2="69217a3079908094e11121d042354a7c1f55b6482ca1a51e1b250dfd1ed0eef9"
    $a3="69217a3079908094e11121d042354a7c1f55b6482ca1a51e1b250dfd1ed0eef9"
    $a4="69217a3079908094e11121d042354a7c1f55b6482ca1a51e1b250dfd1ed0eef9"
    $a5="f429c8ace7c98a41f255ab7d5bbdcc52cfe441bb98fd56254fb484cbae45a3a4"
    $a6="69217a3079908094e11121d042354a7c1f55b6482ca1a51e1b250dfd1ed0eef9"
    $a7="d671d236a443bfc30713dde6d10c8d8e83075db7d89a690fb873cc09a9e3119b"
    $a8="69217a3079908094e11121d042354a7c1f55b6482ca1a51e1b250dfd1ed0eef9"
    $a9="9dcee1170128943b9c951c0f34e1d248aab0945c85e39a9388bb24578173b596"
    $a10="df4738b4ed2274b73722607a4d1cc2158eb209ef16b350087d867393f98db685"
    $a11="69217a3079908094e11121d042354a7c1f55b6482ca1a51e1b250dfd1ed0eef9"
    $a12="200fbc796d214e93d09679b5547e73badd85b1a31f2d21262aea7f82bb654208"
    $a13="200fbc796d214e93d09679b5547e73badd85b1a31f2d21262aea7f82bb654208"
    $a14="5966fc4f2b086214ecfbbe85022bd4f06e8c38a60fb3120ea219a29165ded62c"
    $a15="5117f649a9ea85aa30f5aee09a0350b3276dcd11cff0f372f96f321ca3536dfc"
    $a16="a9ffe918d233b301489e98159551a7ead6fa05a96a3148c1ac998aec9ac4dd7d"
    $a17="a9ffe918d233b301489e98159551a7ead6fa05a96a3148c1ac998aec9ac4dd7d"
    $a18="0cb8a879dc5d94ed67eb49cc7a4d3052d6a346f2e28fcd9e10e5822aba92eb39"
    $a19="327e7e3821f5f6d33c090137f979bf48ee62e9051c1610e1d6468ecb3c67a124"
    $a20="0cb8a879dc5d94ed67eb49cc7a4d3052d6a346f2e28fcd9e10e5822aba92eb39"
    $a21="69217a3079908094e11121d042354a7c1f55b6482ca1a51e1b250dfd1ed0eef9"
    $a22="b78b08cff2216891738ec4218298c908949df667f4de983be128fd9c14b1c279"
    $a23="b78b08cff2216891738ec4218298c908949df667f4de983be128fd9c14b1c279"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13) or ($a14 and $a15) or ($a16 and $a17) or ($a18 and $a19) or ($a20 and $a21) or ($a22 and $a23)
}

rule sha3_224_hashed_default_creds_intel
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for intel. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="a53fff8dd075bed169e164743231ff533d8b9260b0b8073f0a4c1d20"
    $a1="6b4e03423667dbb73b6e15454f0eb1abd4597f9a1b078e3f5b5a6bc7"
    $a2="6b4e03423667dbb73b6e15454f0eb1abd4597f9a1b078e3f5b5a6bc7"
    $a3="6b4e03423667dbb73b6e15454f0eb1abd4597f9a1b078e3f5b5a6bc7"
    $a4="6b4e03423667dbb73b6e15454f0eb1abd4597f9a1b078e3f5b5a6bc7"
    $a5="1c79b8551d444054616f68f0f1c4f451a4a4622648cbffd2a4eefa84"
    $a6="6b4e03423667dbb73b6e15454f0eb1abd4597f9a1b078e3f5b5a6bc7"
    $a7="45b02faa4bc688e009bf707a7085a0dce35cda8b48ab7bdf700d38d6"
    $a8="6b4e03423667dbb73b6e15454f0eb1abd4597f9a1b078e3f5b5a6bc7"
    $a9="1bce69f340a0412e96f20406f637c1a2d8850b62142c8bee6cd45023"
    $a10="e810597249305f414f75eb5a9d2644820de439bc4647bbbdd90f702d"
    $a11="6b4e03423667dbb73b6e15454f0eb1abd4597f9a1b078e3f5b5a6bc7"
    $a12="319ab48e6fdd5134a5381dbe1d85ae88df203f87993aab3708cfdf28"
    $a13="319ab48e6fdd5134a5381dbe1d85ae88df203f87993aab3708cfdf28"
    $a14="7f1727d8c6a704406c8e4e1de7d4d19b339a8612ecb67342ba65a571"
    $a15="47074cf4234a97b93f1df3b473877a1485bde791a82dd441684bd8fa"
    $a16="55c9a58ca4eb087e81629c41e4eff494ee391919138d7f26530dc03c"
    $a17="55c9a58ca4eb087e81629c41e4eff494ee391919138d7f26530dc03c"
    $a18="3e42295e89a3a84ce7ee38e2ba317aeb57ca3164459bdf48f4da0e92"
    $a19="a53fff8dd075bed169e164743231ff533d8b9260b0b8073f0a4c1d20"
    $a20="3e42295e89a3a84ce7ee38e2ba317aeb57ca3164459bdf48f4da0e92"
    $a21="6b4e03423667dbb73b6e15454f0eb1abd4597f9a1b078e3f5b5a6bc7"
    $a22="17b113d0e0afe1192c18bd1d612632793d346184c7daf31bf98f9af0"
    $a23="17b113d0e0afe1192c18bd1d612632793d346184c7daf31bf98f9af0"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13) or ($a14 and $a15) or ($a16 and $a17) or ($a18 and $a19) or ($a20 and $a21) or ($a22 and $a23)
}

rule sha3_256_hashed_default_creds_intel
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for intel. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="fb001dfcffd1c899f3297871406242f097aecf1a5342ccf3ebcd116146188e4b"
    $a1="a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a"
    $a2="a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a"
    $a3="a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a"
    $a4="a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a"
    $a5="0705b6bcabd065ad5f42f4737b35a2a584ee93b21f5f492f81090cc18c196478"
    $a6="a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a"
    $a7="fc7bda90ae735beee34747fa2eb681c5b4327532ba28385ec34dffe42b59217c"
    $a8="a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a"
    $a9="fbe9a43315a0a7395b8ceede18815c82d1ca3243e1de4c2a94aa2640947c915e"
    $a10="2848f07d55acfdd67caf77f276e1f0a529e4026f1708356d77b1ced98326836e"
    $a11="a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a"
    $a12="75bd51a194f52e0f8f26344c29821b4ba21488db601f06111ea67258c9dc9535"
    $a13="75bd51a194f52e0f8f26344c29821b4ba21488db601f06111ea67258c9dc9535"
    $a14="dd51340386dced8be57309ebdd0a92fae5ad55e1013bca1d19d3e210230229d6"
    $a15="46b8aa14f3a5fe5aee4be26c5e33903e1c67df5a8bb35fec5332f8585b2eb6a7"
    $a16="ee94029bafba2122214a9d310dbea3b88153e18c03e74ea9ace80fa66f20f38b"
    $a17="ee94029bafba2122214a9d310dbea3b88153e18c03e74ea9ace80fa66f20f38b"
    $a18="a00e4d3b352e9d11979549b9eef5dc951592f594488451e6cd86fdc4bce76a53"
    $a19="fb001dfcffd1c899f3297871406242f097aecf1a5342ccf3ebcd116146188e4b"
    $a20="a00e4d3b352e9d11979549b9eef5dc951592f594488451e6cd86fdc4bce76a53"
    $a21="a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a"
    $a22="639fc370f71c08ba6077574a8239dab4aafdf0583852320b944cc75b9cbbb944"
    $a23="639fc370f71c08ba6077574a8239dab4aafdf0583852320b944cc75b9cbbb944"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13) or ($a14 and $a15) or ($a16 and $a17) or ($a18 and $a19) or ($a20 and $a21) or ($a22 and $a23)
}

rule sha3_384_hashed_default_creds_intel
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for intel. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="9765a57f2010506383de91052915ce8bafbdb39f3e5a8c1a1693a0076365d37abbfd3305881ea3b5fa1426316afd7df3"
    $a1="0c63a75b845e4f7d01107d852e4c2485c51a50aaaa94fc61995e71bbee983a2ac3713831264adb47fb6bd1e058d5f004"
    $a2="0c63a75b845e4f7d01107d852e4c2485c51a50aaaa94fc61995e71bbee983a2ac3713831264adb47fb6bd1e058d5f004"
    $a3="0c63a75b845e4f7d01107d852e4c2485c51a50aaaa94fc61995e71bbee983a2ac3713831264adb47fb6bd1e058d5f004"
    $a4="0c63a75b845e4f7d01107d852e4c2485c51a50aaaa94fc61995e71bbee983a2ac3713831264adb47fb6bd1e058d5f004"
    $a5="a31c18b20492b487884b7748c04ab277eb2e492bb5ddcbb6018e24158862eba62175683fb58bb84832ee92b4e10da2ec"
    $a6="0c63a75b845e4f7d01107d852e4c2485c51a50aaaa94fc61995e71bbee983a2ac3713831264adb47fb6bd1e058d5f004"
    $a7="d0f7d68e445472d25bcf25397698f56e3176e1d61d8aa7b54bdba364c5fe223c37d18b2125a5b61528f0897f44380254"
    $a8="0c63a75b845e4f7d01107d852e4c2485c51a50aaaa94fc61995e71bbee983a2ac3713831264adb47fb6bd1e058d5f004"
    $a9="37736b3ec33d6cff58c944220df571a473f7f868147954c9ec05bd01d1c12c1616a26357d6f50685130932fc64e11978"
    $a10="6d2bddea82451f8471ec7642ce69af08a2be6845ab02b2d5094fd89640037515a544044c7fbe733a7d26d6758892e60a"
    $a11="0c63a75b845e4f7d01107d852e4c2485c51a50aaaa94fc61995e71bbee983a2ac3713831264adb47fb6bd1e058d5f004"
    $a12="6c71a396a1be305d3f903d32b0639fe5162d594048a93cd940ac4c536a42d495febf2196478b8dab28b3fa5ed4752915"
    $a13="6c71a396a1be305d3f903d32b0639fe5162d594048a93cd940ac4c536a42d495febf2196478b8dab28b3fa5ed4752915"
    $a14="1b9bfc4a37fe08188b1a0183be30ee8669002bd2012eda9636f8718bcd389bc7c3612b6c4d8ee2a627d354977c364a55"
    $a15="e073fc2dcd9ab5ec92b8aba9a77fea6e75646cfa25c9033a30ad0928367dbf240588a9f5ed0107ddb6eeedfa0115b3a5"
    $a16="fe42f6d891df10ae003a6b3e1ddd8ecadfe95588224ea50002d617efdc2410d00c2fe169f5dc0e6e583b35d91e95947d"
    $a17="fe42f6d891df10ae003a6b3e1ddd8ecadfe95588224ea50002d617efdc2410d00c2fe169f5dc0e6e583b35d91e95947d"
    $a18="aac595410801e93eadb099ac575ccc12e43be2c15e31e7991e908329e5beb0729881b3be9ccdb0eeb6eb79335ea38b6d"
    $a19="9765a57f2010506383de91052915ce8bafbdb39f3e5a8c1a1693a0076365d37abbfd3305881ea3b5fa1426316afd7df3"
    $a20="aac595410801e93eadb099ac575ccc12e43be2c15e31e7991e908329e5beb0729881b3be9ccdb0eeb6eb79335ea38b6d"
    $a21="0c63a75b845e4f7d01107d852e4c2485c51a50aaaa94fc61995e71bbee983a2ac3713831264adb47fb6bd1e058d5f004"
    $a22="2a353fed17cc1f251167abd4921a2f11817a257ba9a6736a9bee067d95ccead16fba1311aeb59528b350331b95d30ac4"
    $a23="2a353fed17cc1f251167abd4921a2f11817a257ba9a6736a9bee067d95ccead16fba1311aeb59528b350331b95d30ac4"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13) or ($a14 and $a15) or ($a16 and $a17) or ($a18 and $a19) or ($a20 and $a21) or ($a22 and $a23)
}

rule sha3_512_hashed_default_creds_intel
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for intel. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="5a38afb1a18d408e6cd367f9db91e2ab9bce834cdad3da24183cc174956c20ce35dd39c2bd36aae907111ae3d6ada353f7697a5f1a8fc567aae9e4ca41a9d19d"
    $a1="a69f73cca23a9ac5c8b567dc185a756e97c982164fe25859e0d1dcc1475c80a615b2123af1f5f94c11e3e9402c3ac558f500199d95b6d3e301758586281dcd26"
    $a2="a69f73cca23a9ac5c8b567dc185a756e97c982164fe25859e0d1dcc1475c80a615b2123af1f5f94c11e3e9402c3ac558f500199d95b6d3e301758586281dcd26"
    $a3="a69f73cca23a9ac5c8b567dc185a756e97c982164fe25859e0d1dcc1475c80a615b2123af1f5f94c11e3e9402c3ac558f500199d95b6d3e301758586281dcd26"
    $a4="a69f73cca23a9ac5c8b567dc185a756e97c982164fe25859e0d1dcc1475c80a615b2123af1f5f94c11e3e9402c3ac558f500199d95b6d3e301758586281dcd26"
    $a5="2756def0067dbb3144e25efcf3fa68daa223563eb30c9ed832b0d8577d34e342147564fd0b9a30ce44b6f69717e78e254cdf9e1abda4091eab9d57af6445b442"
    $a6="a69f73cca23a9ac5c8b567dc185a756e97c982164fe25859e0d1dcc1475c80a615b2123af1f5f94c11e3e9402c3ac558f500199d95b6d3e301758586281dcd26"
    $a7="73c1913eac1039bcc543d9f379457dd0865151d09f5c69615189835b98b5da6ac2bb944543ef3735710cffcfc21ddfe1ba4c92d65778c8849e016c997c358732"
    $a8="a69f73cca23a9ac5c8b567dc185a756e97c982164fe25859e0d1dcc1475c80a615b2123af1f5f94c11e3e9402c3ac558f500199d95b6d3e301758586281dcd26"
    $a9="e25747434f67d356d910f19b45b18d5ba0d6a81b1bd3c34f740a3b4bb6dfc09852ee2f9441044a7f9b92a74366b7e2128fcf5bde92968a0ac36ffad4465208b1"
    $a10="90f2e09d2bbcaec0bf162a060461aa3f49647fec9cd87f0df9ea028e723ce3723fd47026b152f9fadf7af211cec81c285b8223199bce57ceb7aeafa60752a100"
    $a11="a69f73cca23a9ac5c8b567dc185a756e97c982164fe25859e0d1dcc1475c80a615b2123af1f5f94c11e3e9402c3ac558f500199d95b6d3e301758586281dcd26"
    $a12="3d7f62b722396d23601c47721a8a83e88d733b4662bcb83da676be4604200c24fec1db69232bff6b861e65fc8ae736d38f7ee22127b574b4d5df330fd9a8d976"
    $a13="3d7f62b722396d23601c47721a8a83e88d733b4662bcb83da676be4604200c24fec1db69232bff6b861e65fc8ae736d38f7ee22127b574b4d5df330fd9a8d976"
    $a14="1b99a6598299e157490ac8e5f71b5254b3a01796a03aa11e0dad34d1bc69a3b080ba58695cd88d49f17ff855035647d964d1617bbb38dd693adb0b0953e75b9e"
    $a15="1c6daab50a77e6e9afd594657a053c60091f1560df238156a58444d71765a88dfcd69f2df94f3bf865f67c251168e897507921b7fe31a3f1376c404e8c3a0f67"
    $a16="65582c103cfe2fa6e4e23596c7d51ed0da89c9b73252d895699ae657ed44852d1f28817bd30eb0702f3b7704be8e7516c850f1c33a16352cff75e492754f643f"
    $a17="65582c103cfe2fa6e4e23596c7d51ed0da89c9b73252d895699ae657ed44852d1f28817bd30eb0702f3b7704be8e7516c850f1c33a16352cff75e492754f643f"
    $a18="8cd824c700eb0c125fff40c8c185d14c5dfe7f32814afac079ba7c20d93bc3c082193243c420fed22ef2474fbb85880e7bc1ca772150a1f759f8ddebca77711f"
    $a19="5a38afb1a18d408e6cd367f9db91e2ab9bce834cdad3da24183cc174956c20ce35dd39c2bd36aae907111ae3d6ada353f7697a5f1a8fc567aae9e4ca41a9d19d"
    $a20="8cd824c700eb0c125fff40c8c185d14c5dfe7f32814afac079ba7c20d93bc3c082193243c420fed22ef2474fbb85880e7bc1ca772150a1f759f8ddebca77711f"
    $a21="a69f73cca23a9ac5c8b567dc185a756e97c982164fe25859e0d1dcc1475c80a615b2123af1f5f94c11e3e9402c3ac558f500199d95b6d3e301758586281dcd26"
    $a22="ae0380de40c9c59e8e0455a4272e9f74bad7dd08108e5fd44c09eaef705ef5b8ee2aba8152b186f067c2235a197f3c88af2010bba3a610ff60c7ac2f8c35b4b7"
    $a23="ae0380de40c9c59e8e0455a4272e9f74bad7dd08108e5fd44c09eaef705ef5b8ee2aba8152b186f067c2235a197f3c88af2010bba3a610ff60c7ac2f8c35b4b7"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13) or ($a14 and $a15) or ($a16 and $a17) or ($a18 and $a19) or ($a20 and $a21) or ($a22 and $a23)
}

rule base64_hashed_default_creds_intel
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for intel. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="YWRtaW4="
    $a1="===="
    $a2="===="
    $a3="===="
    $a4="===="
    $a5="SW50ZWw="
    $a6="===="
    $a7="aXNvbGF0aW9u"
    $a8="===="
    $a9="c2hpdmE="
    $a10="R3Vlc3Q="
    $a11="===="
    $a12="aW50ZWw="
    $a13="aW50ZWw="
    $a14="a2hhbg=="
    $a15="a2Fobg=="
    $a16="TklDT05FWA=="
    $a17="TklDT05FWA=="
    $a18="cm9vdA=="
    $a19="YWRtaW4="
    $a20="cm9vdA=="
    $a21="===="
    $a22="c2V0dXA="
    $a23="c2V0dXA="
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13) or ($a14 and $a15) or ($a16 and $a17) or ($a18 and $a19) or ($a20 and $a21) or ($a22 and $a23)
}

