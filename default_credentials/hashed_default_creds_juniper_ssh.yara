/*This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as long as you use it under this license.*/

rule md5_hashed_default_creds_juniper_ssh
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for juniper_ssh. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="21232f297a57a5a743894a0e4a801fc3"
    $a1="e99a18c428cb38d5f260853678922e03"
    $a2="21232f297a57a5a743894a0e4a801fc3"
    $a3="f222b9ec8469d27230ef4201f95e3d46"
    $a4="21232f297a57a5a743894a0e4a801fc3"
    $a5="0ae2415b0a3d8a58ab71d9e608af351b"
    $a6="21232f297a57a5a743894a0e4a801fc3"
    $a7="37d8db13549d3e84317182ea1594145c"
    $a8="f222b9ec8469d27230ef4201f95e3d46"
    $a9="f222b9ec8469d27230ef4201f95e3d46"
    $a10="29f58ed4a99ee32fc64c25f9670e0f4e"
    $a11="29f58ed4a99ee32fc64c25f9670e0f4e"
    $a12="bba034891e3d3b8e4ddd34f5c028b7dc"
    $a13="bba034891e3d3b8e4ddd34f5c028b7dc"
    $a14="1b3231655cebb7a1f783eddf27d254ca"
    $a15="a24f3d36f6baa87c72b521ec3fc01e2e"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13) or ($a14 and $a15)
}

rule sha1_hashed_default_creds_juniper_ssh
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for juniper_ssh. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="d033e22ae348aeb5660fc2140aec35850c4da997"
    $a1="6367c48dd193d56ea7b0baad25b19455e529f5ee"
    $a2="d033e22ae348aeb5660fc2140aec35850c4da997"
    $a3="82579efda5bd6ce6047b0903ffa462f2c1e1da65"
    $a4="d033e22ae348aeb5660fc2140aec35850c4da997"
    $a5="a2c50c8c74330c5b54ea0b61e6fbfeea207f639a"
    $a6="d033e22ae348aeb5660fc2140aec35850c4da997"
    $a7="b38ecbc85018d2dfc2c9611afa1e6b1e48201f3c"
    $a8="82579efda5bd6ce6047b0903ffa462f2c1e1da65"
    $a9="82579efda5bd6ce6047b0903ffa462f2c1e1da65"
    $a10="25878cbc384641c1d5cf52ff89358495bb34e65c"
    $a11="25878cbc384641c1d5cf52ff89358495bb34e65c"
    $a12="e5cfb68ab0067618655b00c68d873363fe12b723"
    $a13="e5cfb68ab0067618655b00c68d873363fe12b723"
    $a14="8451ba8a14d79753d34cb33b51ba46b4b025eb81"
    $a15="d6c5389f22de5dbb33df723a3309b4273a9d2ce7"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13) or ($a14 and $a15)
}

rule sha384_hashed_default_creds_juniper_ssh
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for juniper_ssh. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="9ca694a90285c034432c9550421b7b9dbd5c0f4b6673f05f6dbce58052ba20e4248041956ee8c9a2ec9f10290cdc0782"
    $a1="a31d79891919cad24f3264479d76884f581bee32e86778373db3a124de975dd86a40fc7f399b331133b281ab4b11a6ca"
    $a2="9ca694a90285c034432c9550421b7b9dbd5c0f4b6673f05f6dbce58052ba20e4248041956ee8c9a2ec9f10290cdc0782"
    $a3="f78bd52b7538fb7ee4c57c995a1bbf476fca33e2adce23d5b114ac159d2616187ac1f2f292e7062d163cdefe5434835f"
    $a4="9ca694a90285c034432c9550421b7b9dbd5c0f4b6673f05f6dbce58052ba20e4248041956ee8c9a2ec9f10290cdc0782"
    $a5="6942407cc2d2ceff0e0ab598bc7d6341363dd2182e5ee8d30355402eac065efdcaea8ed734f6cb6e4cbf36d786cd3d06"
    $a6="9ca694a90285c034432c9550421b7b9dbd5c0f4b6673f05f6dbce58052ba20e4248041956ee8c9a2ec9f10290cdc0782"
    $a7="88cbc8f176c42bdf9618201e176b386eb48487ff7772f25fffabf36bee8cd4272fdbbcb34d88976ef362ff43a3c684b9"
    $a8="f78bd52b7538fb7ee4c57c995a1bbf476fca33e2adce23d5b114ac159d2616187ac1f2f292e7062d163cdefe5434835f"
    $a9="f78bd52b7538fb7ee4c57c995a1bbf476fca33e2adce23d5b114ac159d2616187ac1f2f292e7062d163cdefe5434835f"
    $a10="073ab580db3ec877d60b05b08f33795ffce78c4f265ad8d30a3e84b8881789d5755483b2a26308943b536da2619f6cc8"
    $a11="073ab580db3ec877d60b05b08f33795ffce78c4f265ad8d30a3e84b8881789d5755483b2a26308943b536da2619f6cc8"
    $a12="f29d9083823cd602c0cc12705238aa5e4ab626e558331698f40b170a1a3152837faea8ccb8566b1129e30d057a84ff5d"
    $a13="f29d9083823cd602c0cc12705238aa5e4ab626e558331698f40b170a1a3152837faea8ccb8566b1129e30d057a84ff5d"
    $a14="4092bc3d8a0d7a293f438e15d1a039db25c54342ad87c3d97b4d0554fd6df01bf61704aa1bfe6fdc51c077212a1841e8"
    $a15="4e8af95e7fda722d8aa8d194dec4b4a1f0ab4b936afa00cb3a8c3f2b8556a05c920849e731b98e96549707440efbf14c"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13) or ($a14 and $a15)
}

rule sha224_hashed_default_creds_juniper_ssh
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for juniper_ssh. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="58acb7acccce58ffa8b953b12b5a7702bd42dae441c1ad85057fa70b"
    $a1="5c69bb695cc29b93d655e1a4bb5656cda624080d686f74477ea09349"
    $a2="58acb7acccce58ffa8b953b12b5a7702bd42dae441c1ad85057fa70b"
    $a3="dd7ed3ca1388703a69f0932c659b7ef08dd1e48ba64cd93a5949e6f0"
    $a4="58acb7acccce58ffa8b953b12b5a7702bd42dae441c1ad85057fa70b"
    $a5="41d8ab51aa117d8121cca391219c4c9adf1fd888417cf07504197a27"
    $a6="58acb7acccce58ffa8b953b12b5a7702bd42dae441c1ad85057fa70b"
    $a7="68212142ff3ae0ebcc316b443512d20f8efed0fdd62a1f8d24617043"
    $a8="dd7ed3ca1388703a69f0932c659b7ef08dd1e48ba64cd93a5949e6f0"
    $a9="dd7ed3ca1388703a69f0932c659b7ef08dd1e48ba64cd93a5949e6f0"
    $a10="43779d1eda1cd9654de397b9311958b739d4ccef98e7f1e9c43d94ad"
    $a11="43779d1eda1cd9654de397b9311958b739d4ccef98e7f1e9c43d94ad"
    $a12="4279fbe1067b40837bc33323de5d6fd1785fd7f7606a79251879e99c"
    $a13="4279fbe1067b40837bc33323de5d6fd1785fd7f7606a79251879e99c"
    $a14="0f726b72946abd860c0972fa8b50fc3c7ee6edcdeb23b42d6684e708"
    $a15="e12503cafeb0fe81c90cb7be772832c6b1bd22fb9329425e936b8cbd"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13) or ($a14 and $a15)
}

rule sha512_hashed_default_creds_juniper_ssh
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for juniper_ssh. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="c7ad44cbad762a5da0a452f9e854fdc1e0e7a52a38015f23f3eab1d80b931dd472634dfac71cd34ebc35d16ab7fb8a90c81f975113d6c7538dc69dd8de9077ec"
    $a1="c70b5dd9ebfb6f51d09d4132b7170c9d20750a7852f00680f65658f0310e810056e6763c34c9a00b0e940076f54495c169fc2302cceb312039271c43469507dc"
    $a2="c7ad44cbad762a5da0a452f9e854fdc1e0e7a52a38015f23f3eab1d80b931dd472634dfac71cd34ebc35d16ab7fb8a90c81f975113d6c7538dc69dd8de9077ec"
    $a3="a057d693d382ea522c9614ead06120a4a8ad74c23f9785af2ee64935b9f95848ad8d0eaf1088d14183cb71a0e1d51aceeccd218d3d270741ab9aa1fa3c0d79d6"
    $a4="c7ad44cbad762a5da0a452f9e854fdc1e0e7a52a38015f23f3eab1d80b931dd472634dfac71cd34ebc35d16ab7fb8a90c81f975113d6c7538dc69dd8de9077ec"
    $a5="cb247e9bbd901879f1112bdfb6cddc4899538ed68097e2b4a4d40a71ff90bf9ba26b0cf455bbe295563c61b5e6df122f9e8dd0afac5a599904cd19fe61308ae9"
    $a6="c7ad44cbad762a5da0a452f9e854fdc1e0e7a52a38015f23f3eab1d80b931dd472634dfac71cd34ebc35d16ab7fb8a90c81f975113d6c7538dc69dd8de9077ec"
    $a7="150386d84fda17875e52d1918c2310d195a2b315223148dd56aacf2aef5759e0b948310737226fbe121052075533a028a432db35260947da66747e641c7048c3"
    $a8="a057d693d382ea522c9614ead06120a4a8ad74c23f9785af2ee64935b9f95848ad8d0eaf1088d14183cb71a0e1d51aceeccd218d3d270741ab9aa1fa3c0d79d6"
    $a9="a057d693d382ea522c9614ead06120a4a8ad74c23f9785af2ee64935b9f95848ad8d0eaf1088d14183cb71a0e1d51aceeccd218d3d270741ab9aa1fa3c0d79d6"
    $a10="fcd78f7be6deef8efef818081b6a9bd1f09e65d7a9f874192fb5fa6627defa0912fc62957a722a3e99e117369495c2e3d492eadda3e3918e887f31c6940f0eda"
    $a11="fcd78f7be6deef8efef818081b6a9bd1f09e65d7a9f874192fb5fa6627defa0912fc62957a722a3e99e117369495c2e3d492eadda3e3918e887f31c6940f0eda"
    $a12="7ce0ba2ea55e20401498f76450481d6d40829c024d70a8317efc91d1477487571e1415bbe8f4ae0e5aaed4c46750f6770d0dab4e24d52d7b68a7c8cad60f2e2a"
    $a13="7ce0ba2ea55e20401498f76450481d6d40829c024d70a8317efc91d1477487571e1415bbe8f4ae0e5aaed4c46750f6770d0dab4e24d52d7b68a7c8cad60f2e2a"
    $a14="36379d8584770820d95741c8efe571cc0ab37e2021c505fd8f384724d0676020ebc6d4f318e2533acf708fab8ede09c950a8daef54299ab9ea5ba1e1fd4b73bf"
    $a15="e6793def3f019b4bcf8450de68864668b63c2ed36c93fc62cc06904d091db6ba9e399d7db4093bb79b9e7cf1c046cf0d20292222eec90666ec8168a77c2bb803"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13) or ($a14 and $a15)
}

rule sha256_hashed_default_creds_juniper_ssh
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for juniper_ssh. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="8c6976e5b5410415bde908bd4dee15dfb167a9c873fc4bb8a81f6f2ab448a918"
    $a1="6ca13d52ca70c883e0f0bb101e425a89e8624de51db2d2392593af6a84118090"
    $a2="8c6976e5b5410415bde908bd4dee15dfb167a9c873fc4bb8a81f6f2ab448a918"
    $a3="23bb8b463e0de9b386c62fd5916c01d811a110be4cd2f882c2ab0a920fad19c7"
    $a4="8c6976e5b5410415bde908bd4dee15dfb167a9c873fc4bb8a81f6f2ab448a918"
    $a5="b5fec6a11b2236e2c5bd760dd50cfcdba47407dfce613681c05dcd6fb75f7acc"
    $a6="8c6976e5b5410415bde908bd4dee15dfb167a9c873fc4bb8a81f6f2ab448a918"
    $a7="f0668481b3e4634d99db969ca4d30790524cfb90a4bd15ecf6bca2cb770e7bec"
    $a8="23bb8b463e0de9b386c62fd5916c01d811a110be4cd2f882c2ab0a920fad19c7"
    $a9="23bb8b463e0de9b386c62fd5916c01d811a110be4cd2f882c2ab0a920fad19c7"
    $a10="7f411c23e7d9d268b51470b27920d362905e71fca86a2ef5c70747984b30a29a"
    $a11="7f411c23e7d9d268b51470b27920d362905e71fca86a2ef5c70747984b30a29a"
    $a12="0a2b6aed9a29e267b2d2f7898e42316d36a027848755b946c1e9ea42649e69e0"
    $a13="0a2b6aed9a29e267b2d2f7898e42316d36a027848755b946c1e9ea42649e69e0"
    $a14="73d1b1b1bc1dabfb97f216d897b7968e44b06457920f00f2dc6c1ed3be25ad4c"
    $a15="58dd311734e74638f99c93265713b03c391561c6ce626f8a745d1c7ece7675fa"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13) or ($a14 and $a15)
}

rule blake2b_hashed_default_creds_juniper_ssh
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for juniper_ssh. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="bfcce2c19c8563fd4aa66f6ec607341ff25e5f6fe7fa520d7d1242d871385f23a3e8e80093120b4877d79535e10b182ae2ec8937d1f72f091e7178c9e4ff0f11"
    $a1="585f3b691b374d85d6883348aaad9d63b4cb6b1c9c01aa1ccd2fcb880b27d2e1023c71be0213f161f3caec468178f9266ce06c0517491feb0f181cb4a0c9e67a"
    $a2="bfcce2c19c8563fd4aa66f6ec607341ff25e5f6fe7fa520d7d1242d871385f23a3e8e80093120b4877d79535e10b182ae2ec8937d1f72f091e7178c9e4ff0f11"
    $a3="b63fd22eb6fa67b5764bd701c2bca5ecf545e600402cdbcf319859767693d8077bf8513ead89cb0e62dbcb0fe57650cfa948126aef5f039e36863882a4348e6a"
    $a4="bfcce2c19c8563fd4aa66f6ec607341ff25e5f6fe7fa520d7d1242d871385f23a3e8e80093120b4877d79535e10b182ae2ec8937d1f72f091e7178c9e4ff0f11"
    $a5="11eaf240b60d40159e0757b56fc4999737b5c9f7eb67ee0cca555c1a46a2cc9b5e7ab62c8513751f968ef466af723bbb39a0ed5ea3bd7693b5de8b8f6745a996"
    $a6="bfcce2c19c8563fd4aa66f6ec607341ff25e5f6fe7fa520d7d1242d871385f23a3e8e80093120b4877d79535e10b182ae2ec8937d1f72f091e7178c9e4ff0f11"
    $a7="e4627e92a870465064cbca233f4183f756ebfec40a3969a3ab8f2db04f63c2f8f4f12c988226ac06b60d2dca1aa907ac9e6179b1df74e9132cfd7af849698ef1"
    $a8="b63fd22eb6fa67b5764bd701c2bca5ecf545e600402cdbcf319859767693d8077bf8513ead89cb0e62dbcb0fe57650cfa948126aef5f039e36863882a4348e6a"
    $a9="b63fd22eb6fa67b5764bd701c2bca5ecf545e600402cdbcf319859767693d8077bf8513ead89cb0e62dbcb0fe57650cfa948126aef5f039e36863882a4348e6a"
    $a10="b9722577230d64d1f0481b3fc1eb29352f0b3640a967dd9276d8f1b417b2f7dd0dafdfb94cfac7adaeede0e830fcacb427517ae73953dfaa8bceac4ace86b254"
    $a11="b9722577230d64d1f0481b3fc1eb29352f0b3640a967dd9276d8f1b417b2f7dd0dafdfb94cfac7adaeede0e830fcacb427517ae73953dfaa8bceac4ace86b254"
    $a12="8cc249a7d8ec1963c391ae0a8538e62321ba92d9d713ac6eaca8608ed1a25617da77be496ecbfc6773d4000f6cef1dea523118592b45a59f1b50c301e5a89009"
    $a13="8cc249a7d8ec1963c391ae0a8538e62321ba92d9d713ac6eaca8608ed1a25617da77be496ecbfc6773d4000f6cef1dea523118592b45a59f1b50c301e5a89009"
    $a14="da8d291e0916119783bb03757c6252fb55ea1d51bfb05e3044d676a827ad9afd002fcfdc5706406cb66b61cea06b9ba64f895d7e66b8aedd5bd84182b9b46fe0"
    $a15="ff4339a67d0d9692d46206e9a2ec2054b48e73c0e03b364bcbba76b84560b7df10d8616b3347dcf51ba795ebefef9271cad0f75492b16c8114189593f2d345cf"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13) or ($a14 and $a15)
}

rule blake2s_hashed_default_creds_juniper_ssh
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for juniper_ssh. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="327e7e3821f5f6d33c090137f979bf48ee62e9051c1610e1d6468ecb3c67a124"
    $a1="bb48bdae67206a493787b69821008fcd6249d013125972db3660e75ab6f3c884"
    $a2="327e7e3821f5f6d33c090137f979bf48ee62e9051c1610e1d6468ecb3c67a124"
    $a3="9ca80bd0953938baf509f7bd03fb009d336cbef99edb07037ffde53afef33d26"
    $a4="327e7e3821f5f6d33c090137f979bf48ee62e9051c1610e1d6468ecb3c67a124"
    $a5="e1bcef28ec1e2de5e2dcb74a5c8b52190c44c17ded9c8f4a2482e8cb8299459a"
    $a6="327e7e3821f5f6d33c090137f979bf48ee62e9051c1610e1d6468ecb3c67a124"
    $a7="52e11196f15877fc6365eb4e355da26accd1d50735788a3fb884c3c3f4060285"
    $a8="9ca80bd0953938baf509f7bd03fb009d336cbef99edb07037ffde53afef33d26"
    $a9="9ca80bd0953938baf509f7bd03fb009d336cbef99edb07037ffde53afef33d26"
    $a10="64e6c635432e4f47869c2d062ac7738cc60facd584184c89e2e5614b9d00d666"
    $a11="64e6c635432e4f47869c2d062ac7738cc60facd584184c89e2e5614b9d00d666"
    $a12="6cf89fc9d03c853b527101b230e9c407518587ea1e5a02acf8a04d503011a009"
    $a13="6cf89fc9d03c853b527101b230e9c407518587ea1e5a02acf8a04d503011a009"
    $a14="7b866d188933ccc5dfc6f79bd6366c759f7661ff500626bc1b013b6947eb5831"
    $a15="eb43801c2bbc902aa1a198866e32ded43c5004c7c47954b04f003d287d2356cd"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13) or ($a14 and $a15)
}

rule sha3_224_hashed_default_creds_juniper_ssh
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for juniper_ssh. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="a53fff8dd075bed169e164743231ff533d8b9260b0b8073f0a4c1d20"
    $a1="026727ec105a060b02a0086a2181748f6b9ac3cea3fc347ca8675984"
    $a2="a53fff8dd075bed169e164743231ff533d8b9260b0b8073f0a4c1d20"
    $a3="b158b1d74cf4c3c13d914034055183bad8697f81868ba01cf9c656ab"
    $a4="a53fff8dd075bed169e164743231ff533d8b9260b0b8073f0a4c1d20"
    $a5="e75cf98e6e8fc6775e99d9d2563f172f1855b3f1788c9a7db0932704"
    $a6="a53fff8dd075bed169e164743231ff533d8b9260b0b8073f0a4c1d20"
    $a7="7a28b75582997ecb75460dbcc4ffa6cd11cc84cf0c73ee52cf4a450a"
    $a8="b158b1d74cf4c3c13d914034055183bad8697f81868ba01cf9c656ab"
    $a9="b158b1d74cf4c3c13d914034055183bad8697f81868ba01cf9c656ab"
    $a10="56279de09aff6b05fc30a9e345a3602f03b12fbcc48b3f21bf76cbf6"
    $a11="56279de09aff6b05fc30a9e345a3602f03b12fbcc48b3f21bf76cbf6"
    $a12="aa37e818a70652b92859f6fcb4a017e719f83d07039457447c61037b"
    $a13="aa37e818a70652b92859f6fcb4a017e719f83d07039457447c61037b"
    $a14="1bbdd3ab361d7fd9a47de72543e337093aaa664a02248557615675c4"
    $a15="a9ae02a96da3643414ad2a9fb3d76d6a6d441c84f745edf5e0aea1c7"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13) or ($a14 and $a15)
}

rule sha3_256_hashed_default_creds_juniper_ssh
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for juniper_ssh. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="fb001dfcffd1c899f3297871406242f097aecf1a5342ccf3ebcd116146188e4b"
    $a1="f58fa3df820114f56e1544354379820cff464c9c41cb3ca0ad0b0843c9bb67ee"
    $a2="fb001dfcffd1c899f3297871406242f097aecf1a5342ccf3ebcd116146188e4b"
    $a3="9f2dc58fe82d1f53a48ef3c0d8b0237125012949b7c159e4d0a78e741840b410"
    $a4="fb001dfcffd1c899f3297871406242f097aecf1a5342ccf3ebcd116146188e4b"
    $a5="91f679a7fe843734184eb5e5b53a3cb82401336c7750fae790fd6b594619d853"
    $a6="fb001dfcffd1c899f3297871406242f097aecf1a5342ccf3ebcd116146188e4b"
    $a7="a3cc1ddc674c0b4e80cbceb0ec80001487ab7c1259137b14962c7c4b11ee79e4"
    $a8="9f2dc58fe82d1f53a48ef3c0d8b0237125012949b7c159e4d0a78e741840b410"
    $a9="9f2dc58fe82d1f53a48ef3c0d8b0237125012949b7c159e4d0a78e741840b410"
    $a10="ef10231f890a38ce1fb470f7c566b2fdb713ff364f9253c5b838e73bf8d8c55d"
    $a11="ef10231f890a38ce1fb470f7c566b2fdb713ff364f9253c5b838e73bf8d8c55d"
    $a12="b521ec75f7cab7a2f3aff2631c89a706ff899eb3f81f1457199c73e371272568"
    $a13="b521ec75f7cab7a2f3aff2631c89a706ff899eb3f81f1457199c73e371272568"
    $a14="79de1c617efcf3d784ca3b5d1be7fefb1d1287b079fe4527640c36446cd29ea0"
    $a15="6673b63f3a87b427a12cdbf510ac140b227d458666f7d6ee2a0dea4526a4dd39"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13) or ($a14 and $a15)
}

rule sha3_384_hashed_default_creds_juniper_ssh
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for juniper_ssh. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="9765a57f2010506383de91052915ce8bafbdb39f3e5a8c1a1693a0076365d37abbfd3305881ea3b5fa1426316afd7df3"
    $a1="e07300227b15a724fdf6555569e38282022d106d778aa2268898dc21639b24e1e00fcc0a6d96ffc8b3a97c7fa7296305"
    $a2="9765a57f2010506383de91052915ce8bafbdb39f3e5a8c1a1693a0076365d37abbfd3305881ea3b5fa1426316afd7df3"
    $a3="c5953e0f9d2f428cc2e39d004c4e3fce7383c4a94b08fb5d2847ec5e60073b669c9b9ea515ec173bb23bf366b5f56f29"
    $a4="9765a57f2010506383de91052915ce8bafbdb39f3e5a8c1a1693a0076365d37abbfd3305881ea3b5fa1426316afd7df3"
    $a5="8ec9de56e89a5103fc2307816c7ec4b5b3c4ad29a2ba8d219e1864b5ba041798fcef6de0004b155e69ec41975d24f2dc"
    $a6="9765a57f2010506383de91052915ce8bafbdb39f3e5a8c1a1693a0076365d37abbfd3305881ea3b5fa1426316afd7df3"
    $a7="40ca0dc31ca8ed2c80adf24fea86c13931fe369fc0eb5b02fc8ee3c720934b385b821ff02efd369c7e84cc5be7388a02"
    $a8="c5953e0f9d2f428cc2e39d004c4e3fce7383c4a94b08fb5d2847ec5e60073b669c9b9ea515ec173bb23bf366b5f56f29"
    $a9="c5953e0f9d2f428cc2e39d004c4e3fce7383c4a94b08fb5d2847ec5e60073b669c9b9ea515ec173bb23bf366b5f56f29"
    $a10="7402910b87f2e5294a29e2a5388a2908f98aea5a20f1e4e1074bd67e4d11c182c2a709d7772ac1b05c5d66c7011d7ec8"
    $a11="7402910b87f2e5294a29e2a5388a2908f98aea5a20f1e4e1074bd67e4d11c182c2a709d7772ac1b05c5d66c7011d7ec8"
    $a12="33ce5107b40988a8734c41e3cba1b8f6e4f6da52d6799d6387ce87d6f50c4a47041adfecc4fbe88a3b2c2a18764724e3"
    $a13="33ce5107b40988a8734c41e3cba1b8f6e4f6da52d6799d6387ce87d6f50c4a47041adfecc4fbe88a3b2c2a18764724e3"
    $a14="a42d04a5b4a2ea45ecf45279aaf3ec8fd906355e3ab856231ae7815a5df6a96f76fe4987dd638981314c942ba825de69"
    $a15="e571cf56bb1b8c66f560c4f729627feba4863b5ecfd75b7eaa4c5e8b1d92a614214eb0981dfdb5675d39db73b3c0d4ad"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13) or ($a14 and $a15)
}

rule sha3_512_hashed_default_creds_juniper_ssh
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for juniper_ssh. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="5a38afb1a18d408e6cd367f9db91e2ab9bce834cdad3da24183cc174956c20ce35dd39c2bd36aae907111ae3d6ada353f7697a5f1a8fc567aae9e4ca41a9d19d"
    $a1="3274f8455be84b8c7d79f9bd93e6c8520d13f6bd2855f3bb9c006ca9f3cce25d4b924d0370f8af4e27a350fd2baeef58bc37e0f4e4a403fe64c98017fa012757"
    $a2="5a38afb1a18d408e6cd367f9db91e2ab9bce834cdad3da24183cc174956c20ce35dd39c2bd36aae907111ae3d6ada353f7697a5f1a8fc567aae9e4ca41a9d19d"
    $a3="66aefb7dde2dac856807d63d2bda9d71568b7e6ad28c698bcbf0d725e61c72bc790064532977c1f714c9f1be28fa45253b8d91646d9160dc5f9aacd7a2d5ff29"
    $a4="5a38afb1a18d408e6cd367f9db91e2ab9bce834cdad3da24183cc174956c20ce35dd39c2bd36aae907111ae3d6ada353f7697a5f1a8fc567aae9e4ca41a9d19d"
    $a5="343044eba1a91f0d960f6d74515841926409bd574a203089c491cf4591ea7c1b918b4c381c13ee0a77f42d7bb2e04d9e4d75a189db5d20d1c6780ad744d7ec6a"
    $a6="5a38afb1a18d408e6cd367f9db91e2ab9bce834cdad3da24183cc174956c20ce35dd39c2bd36aae907111ae3d6ada353f7697a5f1a8fc567aae9e4ca41a9d19d"
    $a7="7d96e494f2164f9b58c7a97b510d9d19716f0cecf1e1b05eef9fcfa1b90958328e6c7023692c5b11c74c15b49e34855cc2c183d859e893d93d1a12949c3b69f3"
    $a8="66aefb7dde2dac856807d63d2bda9d71568b7e6ad28c698bcbf0d725e61c72bc790064532977c1f714c9f1be28fa45253b8d91646d9160dc5f9aacd7a2d5ff29"
    $a9="66aefb7dde2dac856807d63d2bda9d71568b7e6ad28c698bcbf0d725e61c72bc790064532977c1f714c9f1be28fa45253b8d91646d9160dc5f9aacd7a2d5ff29"
    $a10="cfab24261aacfc33b29081381b843df5e7e5f69f230ac7f91a00f7bfaa468ceb439e2ff659ff401f9961487d379b710b48708a1ffb7538bf75999a3b1e86365e"
    $a11="cfab24261aacfc33b29081381b843df5e7e5f69f230ac7f91a00f7bfaa468ceb439e2ff659ff401f9961487d379b710b48708a1ffb7538bf75999a3b1e86365e"
    $a12="76e7d4dec7414f98d398948e38d0232cfa311fa1053ffd8a977a6a0fc2911ba81debbb577282eded9bf22ac2a7797e2dc2dfa8a1a72352988ceb80e7deb9a1ee"
    $a13="76e7d4dec7414f98d398948e38d0232cfa311fa1053ffd8a977a6a0fc2911ba81debbb577282eded9bf22ac2a7797e2dc2dfa8a1a72352988ceb80e7deb9a1ee"
    $a14="a5cb39ab7a85e70d39ae78b734b0f42660126100c6d458fdd3f8e6b20ab8f73b2db2a02a0ca8d38d40b6b2544be6491243703c5770cbce76385c2e3a9c791f36"
    $a15="f00c644c174825d50278946c432d337ca61c711b102785c9fdfe1fe7f65a8b163d1087ce0f964d31b510a9ef8aef606eb22d0fcbe45f889548649919d3e907b1"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13) or ($a14 and $a15)
}

rule base64_hashed_default_creds_juniper_ssh
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for juniper_ssh. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="YWRtaW4="
    $a1="YWJjMTIz"
    $a2="YWRtaW4="
    $a3="bmV0c2NyZWVu"
    $a4="YWRtaW4="
    $a5="cGVyaWJpdA=="
    $a6="YWRtaW4="
    $a7="PDw8ICVzKHVuPVwnJXNcJykgPSAldS4="
    $a8="bmV0c2NyZWVu"
    $a9="bmV0c2NyZWVu"
    $a10="cmVkbGluZQ=="
    $a11="cmVkbGluZQ=="
    $a12="c2VyaWFsIw=="
    $a13="c2VyaWFsIw=="
    $a14="c3VwZXI="
    $a15="anVuaXBlcjEyMw=="
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13) or ($a14 and $a15)
}

