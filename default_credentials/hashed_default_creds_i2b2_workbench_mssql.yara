/*This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as long as you use it under this license.*/

rule md5_hashed_default_creds_i2b2_workbench_mssql
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for i2b2_workbench_mssql. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="82563c3301fbc3797ffd1702984f0a2c"
    $a1="746a296a2547b1a28ece1d9b45021f0d"
    $a2="384c2f56183aa57a44cc85be4f2e9b11"
    $a3="290aa251e112152e01cb136466980fbe"
    $a4="33f8aadf7000eb8a5c63123c8b993342"
    $a5="4281d43f721b976838f6c7d34a4094f4"
    $a6="75c9e6efa323340cbcb2756a08c40f23"
    $a7="72eec9aaa2014c22df5337ed180030c7"
    $a8="d7d4724929ab5922dcf562fcf2723110"
    $a9="c1673d10dd6922e92f2fce940676b88f"
    $a10="c99776caa9ad70bbd1fd9d79052c3529"
    $a11="6b87bb6786cee7e0ae0036f068270442"
    $a12="9889fd39c16285ffa66a69eb9d524f06"
    $a13="7b5679d2070b773b13f8e68d205670af"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13)
}

rule sha1_hashed_default_creds_i2b2_workbench_mssql
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for i2b2_workbench_mssql. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="7cd0a50ef6014879cfe6c6ebae160fee53b33ffd"
    $a1="9c1d6ccf7a2b3167b1db2558e52575106bac5a6a"
    $a2="0a7fc5876bb1406f4eb4c9259f9edd9c330a6273"
    $a3="b7831f202ee6c562b8373e4cd397bd112c1a1f06"
    $a4="b1803660b09be47086d05904f15c2da0a16a220d"
    $a5="f5c83f7939640ad4dc0b67e858bb1b2aca5ee349"
    $a6="9160017d7861851d9526cc775b3a4f2c039c9d04"
    $a7="a32617d31c27f297ffdc94a0598137495f83b5be"
    $a8="d9884b80682cc7dc3a79d4eca0b6f098a48d3091"
    $a9="43bff6d5cd88da01bc70466d4875a65eafac2b69"
    $a10="ccda840902275a9c7ee8c1c6a179d11e75dece26"
    $a11="e3d61c7d16cfab2980deefd04fecfaebd141723e"
    $a12="b00dcb2894d18b9a791595e3167ade9bfae473c6"
    $a13="69d76e9b02d0abe85fc63e658a5c481f5075bc12"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13)
}

rule sha384_hashed_default_creds_i2b2_workbench_mssql
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for i2b2_workbench_mssql. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="e7aaac9dcee1df8433ae30ed7e73042fee1d28421010ce3c9f415fb50dcf98713b2bb9d869dc68c7ae952b921a5d712e"
    $a1="396a54cef63ff816cfe87d81ed558d592e65edf06688e1c953147a6924eaa5e3dcd811dce01790c66eedcca0f9c29bb9"
    $a2="8e80a1b738a23b5bfcaa65c5e743c6d0bdae57db8c9e2c3be53ba1a657232db1a49c636a37f78fc6ae53ce32181bd095"
    $a3="0e5865cc26cff4ac9e32b8ff5cb848435cf0797159942f20fa1c4308b6ed17f69b10d4fef1a1c3133dfe60d3c10bdfdc"
    $a4="fd3767721e68e94bc6e406b01d603fc8845cb4130707fd155cb534a9c74abb72178d3975a06ffa8a636b2ac216bb9eb5"
    $a5="1f61fb86dfb1a3207057e4fb18e16d6849f3252b49b886d39a528b87690cc345acba5d1c09cf84fc5799fbc593dfd9dc"
    $a6="cd7be9b492fb318865fcef0ec44957e2e655bd16ac286f996ed4d65107c4d1d950e045e2d810e9c05bc103cadfd9ba70"
    $a7="4b63aa0890a32d82ec8740be68b1eb40e2edc7d758807a290a808334fa2e23f745f0db9cb7ebb118e3aa0db917eeaf29"
    $a8="91583deb65c535964f991bc337a01d05057ef11fc58bd3a376cd6232f42e3d362163e83c22349badc3e17e8ef74c60bf"
    $a9="3baff74727f4229e305f4f766fe3e6655d5afa21a3b401bc9f236ba445a9dc4c445286979b0e0eb27f348750e2a28637"
    $a10="d09a2a98508e9bb917e525798684ca0e928c4d3fdb5151c36525839218144f209203fec5ee33d68d7c8180e6ec96ca47"
    $a11="b85c817fbf7950527e0cb7adcd219e3f311ac3d2a906cf0eacd2c2325f351b6350a5f712fbc9f02eaae5363e0cbf56c5"
    $a12="d406093dcaa89c198152569fcdd34c6076f433097a284254baa3753e8fc53a6702b0a9a29bb2cdb4117acca622d9d703"
    $a13="000eb40cd9c39a01d6c2a9100183766762392be6ad2607c67e2494041d2f49ff3f32fec4125ee231ed9cd04034f2d0c2"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13)
}

rule sha224_hashed_default_creds_i2b2_workbench_mssql
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for i2b2_workbench_mssql. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="80761b7d060a9ea0bba1bea618d67aca65a1af591c52dae0b2c8848f"
    $a1="33476bb0e45b3b78bf6ee2c7ee202050a045269ebecf80aea27a7c04"
    $a2="978858a3ac2b429d66169645c7c284ca50e9c8d2a9800d99246f3d99"
    $a3="1367f0b33a863292cf921557e15676e49a9bae6cc0dbdebeed9a219e"
    $a4="f2fd55fc6becff8b352f852235e970896129d1e016331853d1bf6fd9"
    $a5="391572c0204fddbc68e91f0e808f07d4b7e85b341966fda81ec1c831"
    $a6="6a6f517834010ffd590e765b6692f429f3b92ec8a7c3a125fd168866"
    $a7="b367f8059dc59b4d7d54690a47c1622a703db697dac3759a59fa77c5"
    $a8="19f570b0d360fd05abeb1995770514e378acfc95e43ecd82a4252895"
    $a9="c4b4ea2a350d33bfffb202196e405aaad052274d1da74b3f624cc2c3"
    $a10="d8b657ff5a9c6445187c3b6275ea898d1eb3ade5da78b6ef45047ba5"
    $a11="e347e2526a09c43c2385957c095398a9d9dea63691ed9772390d4a07"
    $a12="fcb385f11a378012e72caf864aa4a7deda3f76f24fb4fa72f10afbe4"
    $a13="ecce30ce23e92c71a4268cace9de4cecc564b5b462225242492125e9"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13)
}

rule sha512_hashed_default_creds_i2b2_workbench_mssql
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for i2b2_workbench_mssql. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="e73ddf18db42a20273b827cdc5f961d449f67ad69b852b4a9117249294893dbd3bda2ab12d01ef67c9f624071901f575feb9c3bdbfe0244cdd444b2ffcf1881a"
    $a1="bfa577a60006a87d7bf2b9c2b7817f27e9f2978925db7b0d1c7ac56295da97c61e92ced54a2f55db3be780c2cf04af86d38a51432a09a1fd02a903fd4b8c7c0e"
    $a2="0b2f936c901306956500226972cb2c758f1eda445c08a210f57cdf7e0d0fbc8fb717bd585bad148256f2979044082c0e2ca1563ba11f1a188d372e6b584017b3"
    $a3="96c61a761cbe1cfc0e2948928d2ab7be1df673726bcc0e4d387ffc5bfffe131db7079215e8c2be77c8ed4e660ce2da8abe7b3cb5399e5a991907527b37a78624"
    $a4="31bd9b0adf93bff0c5d564ad73179caf2b834174f687e374a8f6de81b206459ab1fceb564c4f1f0271eaff4a1d607c00168e530550ee7fa82cd71e3b1e509db5"
    $a5="41cf3bcfa71fc6f69dcd6e574c292372eee200eceb4354714bb5ec5c6068a6cd677f1f53596f44faccfb3e0db8176c8a559a9263a6a98d06785900a10df826ac"
    $a6="d037a27439d91601bb5143bb88b259114d1e7a225e9b9c72f26ef0abf5f24dff4461e3850bf4caccafe31c8f3771b693c4add389e0ef495ac1ce56cbad5c4f58"
    $a7="8e59c9c42f5fdeaa315febff657de279d403a6e05bd6afff9baa8d549f9221e3c092cec8088d6b0cbfca45133569441b6503ed3c3a0641c74d851220b408f28a"
    $a8="10d91e298f437c0988c3a5047beac7b6ed67f3fc371aa4d2f8fca36218006ea41735fadd7a7f35824cb0a6972e6560f43700240f43a7326b6fd2b7271fd97dde"
    $a9="3d58ab508d97ed31f5d250f4029707b8eec85652fd2740cba3a1518722eec6eb7a557cace1ab654dd69705998f4c261c422c502dea8a862ce44eacf931f8bb6d"
    $a10="28d2f4839ebcb58804816a6c86b3ed8e5c4cf4215ea652f7b6175e1648b670c251678d0b3fa8b98f9c746c0d916484f8c1da18343a834629edcf5ddd28017d1a"
    $a11="0c5539419a40f2e0431d26e40afc33b4f828eb18c14c70e0f5240f50bbbb1f0be5f8934fe594fca19c4992665c507be1c85cefa5b725e8acc04631723d7b816b"
    $a12="aa03e4b7991b1ded4b6cb339d70371df5d70d9581bc6f554fd33d94a2306268fb2c210ecceb9e27fce913c607addf2a3cedeb53dc36258495ddef0cd7352a93d"
    $a13="d6fb303291e77fdf23037b5756c7b2d6f84cc2f8f2e82d732e0d5a8e50e9477377dee23659c2bdd9bbef97e5e8e9ad77beb7d22e0db83c9282b6de0ae299fc6a"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13)
}

rule sha256_hashed_default_creds_i2b2_workbench_mssql
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for i2b2_workbench_mssql. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="12f31efb95145165dd1716a887e99b851bb8b4e4b2ca31f78bd7654b3d61ac6e"
    $a1="6d27c6a8865fc93b7cdd8a0b63d7b8ededbec82bd52450dea256b94650834876"
    $a2="57183307c7337fb45996bc1fcd633beafe55781a5bbba1b95bd1b5783d0167f9"
    $a3="16773b7fc085b0e55ae98e02e053cb325217f1aaf83d63c9e646a67344a9ecaa"
    $a4="973a801aec5abfb0dd9ab3f429be4b7a7894d23362d049ff63a2687b0a00194d"
    $a5="69f2ee9f38421d43d8bb663bb183b7b1b438db88cbde697441b77cf0367179f9"
    $a6="965c060d0cbd81ed7b673980c46bcb4e01e42354ed6d64ee7354f732099c88be"
    $a7="f03f0760bab3dab7536f951d419198fae0397f704882110d1405c8565922d659"
    $a8="d6a5a0d16e0fcc10849438cd2475300662b916c18bfd8777bf63f05861de9ff2"
    $a9="55ea7d11cabf3c16654164646337c1ee61ad792d20f00ee726c95fdaf2b95040"
    $a10="542e2cdc8c4bb1e815215e587f3f370fad637a6f7cf560f5c825a4640f7612f6"
    $a11="3898ae9dcde0e53faf12cbbbf64799ddad7630000e054af1a32debf907b33066"
    $a12="e3e990bc053688f87de9142738aa9150699805e9637632f0bf9da462d5136a1e"
    $a13="75d2f413abb842c64f8d8fa31d78593afc64bf3a75caa5e1db41d082b92f98b6"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13)
}

rule blake2b_hashed_default_creds_i2b2_workbench_mssql
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for i2b2_workbench_mssql. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="3c19678a1c283c8ff312206654b29709731ae3479f94dabd32e72f5229c8e4ecfd382b69511c54b922f446cb4947ed4a81f8feefce33ee7270493579301db32f"
    $a1="2ef960d5594ac71c239abf7c16ff171fbd72544a30e651af0f1cd4ce232aab67f7438d8e4b3c8f71d4d7ebc5a920c13cd7b091d4666d7c0bf3799fecf1c22d71"
    $a2="103a5f5e1e65885b0f4f4efdd21a5c3946adc273c35c094d883ac39a8d4558af307cdccac070625f5dbd99a621000c6a72824fe36f18b89a235ed8937e6beb4d"
    $a3="17906556916c067fb12714440b640f2910439bbb5ad33df1f7b7795f7d8f29b4dc99cbb186dc2873690cefa9cf144447fe5d15c7e86e34612a9f4231a45adb81"
    $a4="63efc6c2971af6dd669cac7cea02a482540c5aabd76bd9ed46c15ce9db59cd240d9e01410b9bd32a53d22b6f03d6afa3b98b1315cba5617b4a8d6619fca4b110"
    $a5="99600ea71c95fc3dc8f1af0f00d9a548fd832a9e72184450c970b56f0a33ac6364d641b4ca5d6cbe7c13a3084468df5a393c07e376cca0257aa761f7d32ad43f"
    $a6="379b43981b4a753bc61cf2cb68d2cc2227f6512c0722b3564b6e4d7e9634450ae7d85fb8f36afcf93dbac676e92a5b19098acb665f6f0fe60c7ef52d4d9af122"
    $a7="538bb983e427de025c29a6328c9016ff47d08ca1078e108ae19ff6075b1675a24ab30fa566f155dd97f097bd3db3f29f17d09ef4ca2c4166f60e009afe66f334"
    $a8="18b503de6a17acd2e91d0192beb0da7d66b5e0b4a26f69c25049db88cc15545d7d2bfc71005773de1a2642a64795145df9d58e036abd1f2e523ea75e9fa768ce"
    $a9="b4ac6e50c8bfe95c3d30f126fc810bff485f5de02c5bd5dd75d7b7e41241bd7a973dbc2d25ba99297cc45c0bcd64561a557954a890b7a895e2416eebf62b6c0b"
    $a10="fadc0cd4ea62e7b7e7125900d36cc8f7e3855c1ca4d54415658daf17b14968550bc875af8c2224456995b84d21912ba356153cea5977806e356aec140207437d"
    $a11="3f32fda7814cc94a814e4e336e63749be8d087da1852676a2d0a31dc6c4c7c289fc52e8762030abd3dad6482572cc7f67319c21723033ac0f8b5b06f525cc210"
    $a12="b3f3f60624f6a64ae639a257fb46a6c5b94e6c15951800087e377f78b2a565d62d9d0c0f713eeda51ecd7ac676a463803c4c73c808fb34a1ccda8d5016ccc90d"
    $a13="837e01334b036ce17939f3aa51433f6b06b7b9079ce737e12550332cdf36fb16673fa7da7daecde7acc08017f204fe73df690009757734f4f68162c739765585"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13)
}

rule blake2s_hashed_default_creds_i2b2_workbench_mssql
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for i2b2_workbench_mssql. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="0c5f0e9680df8844e5bd9837df1646101ff36ae4c38bd26b0843581694587c26"
    $a1="cadc299bc63226370ced068e55acb4b9327e67aee8f3d73d43029966550c6c26"
    $a2="bfe09a792e7c4f685b48f7d0e7246242d4453e032c305fd01a6dd148637f83ed"
    $a3="a816efc212cc2184870ec5fc4bc758038a0c0971ab17d651c3452c3a5f01a350"
    $a4="332266bbb621eb4f0c252f9bc43a739aab0fcde2fce3f9d139b8a80115811c6f"
    $a5="2c646d78f1e332423b98a4c004c001bc9880f2711e8788173709b2ec7b7e457c"
    $a6="ed26be2b4a908bb9b6b223c524f029f4056a7eacd888858be06095ca8a7a158c"
    $a7="28ecec77d325554e7dc0fc33b5206ffe2e740c028ba0de634491112ce41fa67b"
    $a8="99cc0856147014aeece860b216ac3e742a92660e84331ba29c90352f1d24dc80"
    $a9="afadfd6aeacbdb5b4fd6ba8badc6dc3b844e5689c6512f6d976939cbfdb39a43"
    $a10="451c66440f6521a19cb273ae33a49ffd0e8f3f9919cf58259ed3a91ae67a5a48"
    $a11="1e53810f203f5c01555ebf7d3d838b247ee9b228d5779260b6449245adafed16"
    $a12="7f021dfcdf4ef08cd017340bf199b31ea6d62998508bf693742fda607171e857"
    $a13="b0ef5b598882fd0bb65ec66cd62b4a62d95389bfd9688723f7550feaa21be1f7"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13)
}

rule sha3_224_hashed_default_creds_i2b2_workbench_mssql
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for i2b2_workbench_mssql. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="64beb30422f1ca1ef3e27a39f490a47b1b73765ade570e55b679c4f2"
    $a1="669b40f0b1baa7e730091f1fa2080fbc4f741ccbe305c34c38b41122"
    $a2="ab9776dd3ebf4ff2f26333a785547de0c2bea06780055f82b3e7971d"
    $a3="16f30231f278f6831607e260a81a8535def4c876c1f371d8638bc507"
    $a4="5fd28b327a652f086cb914fd1db55dac441969ff0c58497a93fbded6"
    $a5="cbdbfef69d9bb27a9e3c861433f5ed243d1a24ca2980f9e58b1f92f4"
    $a6="1573c47e310e794267caf0f2f7a72a388cf3ac2f428d7513c7c29a1e"
    $a7="9fd3c18a4f0dbcdddb971fa334aebef2021e6de71c100ddd1c260953"
    $a8="2ce74e8b30a6d813fe179a27998730a6b24cd2a9971703a32a0728cf"
    $a9="a1ddd1a85ef1b80b27802cec7ae879c72dd6db2783446366bab78706"
    $a10="3549b6f9b11a6370848279bef528e6136ee56730174ae1ab537b9dce"
    $a11="759a6a8a9eefedef5f97a22f2f11dd85ddb5fa662af55149c71acbf2"
    $a12="4271fb89cb836139e7d6eb99c30b3339c77b44e0476f45e9d614a6f2"
    $a13="43a6265a5f1ecaf6d48a8a58c4d382d3a6af4e33cb7177e35d95a1b5"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13)
}

rule sha3_256_hashed_default_creds_i2b2_workbench_mssql
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for i2b2_workbench_mssql. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="dc503b4b1c77af67adb2826f965b679054a2b4a8a507ff6d3998768a3231110a"
    $a1="564e5dc4a945c090099282aaec91c7008d1f633b77c54c604e24953d601e238f"
    $a2="ec1a98de88ea78eb5c7c5fcaac2fd46b297985464f027050092968a7127c356d"
    $a3="2f6fafe40e2c9b3cd901b7d33b147f50caab311a64015362096f8ac89dd994bb"
    $a4="c49fe7fcc25d3b10755df66070a98c13b2383f3016a29c8e4eaa4cac4a164388"
    $a5="b1bc5f5e38a9a778917168082f4265f44ab63bef461301dcc24d59a3faa09a25"
    $a6="2d960b67ed7ecced37067d9e0bf3b5921e5958c7c2ab72ae415602de3ef3a991"
    $a7="f94c407aae94e5241a332be5eb4ed728b567eb7314c49959d4144e47041d1200"
    $a8="8816517c6234e6c58242ab0628732b4c18bf8ed5e6663305b032052d36c4738a"
    $a9="bc75743e1d99bf61fce1521c40bfba81e7aec87e9732ad59b617ce36e310631f"
    $a10="03b7e32a3a6c800f30ef0316d54252a6cccb196652afd4c80e2713b6b0593802"
    $a11="100d8c5b945b6ef9260c6654921846de4adafba13c27f3050d77e63c33dbdf11"
    $a12="690583bff134ecba4fffb75f587cc536670dc33aa84626b6bb40dfede59c874c"
    $a13="b8b7fa3269ca681cb93722b14a61ab1ced46d6e3526e1607b9016f2d20fc7634"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13)
}

rule sha3_384_hashed_default_creds_i2b2_workbench_mssql
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for i2b2_workbench_mssql. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="c7bd3a0bb0cdc72a7f6e39a620ea6ed9cbace0d27d492ad577464919bf3be64d35fd4caeea95a71215d52da7fe376be5"
    $a1="5eaff866446a84bcf1842a8fd1c991f9d17c927faf304b6483e8f6d659d63658cf7d864539de4ee97eda9765074b7357"
    $a2="dc33ecf079ab601fb3efeee56e49b810ef8400431056aaf8bb909495e7d89870b271b7f842455a4bdac5806670dcd58d"
    $a3="f2ca92747c0723e835ce642f6a0d11d7d070670627304d66509e1f45430e9260c625b5784d62bbc9c35856394efb4861"
    $a4="855529acb5d476167205f6f7f4ba398d07d5e1efa6043e0c23006ddddd616493dad03cb088a1d2cda10096c26ecf41cc"
    $a5="6be7b773a88d446849a5f562ad58f056468fce2e2e03f025e9f1c3512c4989db1a9be7990ed7462f7c7fabf959694843"
    $a6="02443e35a14c848f5a97fe4ea146071b8089f14fa253d80ce4850ad6910cb16f56976cbd30568256062833508ca32b88"
    $a7="fa51e254e7829ca1759a5e93d38d537f6935af5ec8e0f123f5872f1e203b414e96c63488a0be5b7fbab55529ce016794"
    $a8="4bd853ec48990a0b919317762054e7e4a333abcdef6c5b3b28e23487f77e545d9afb58c07937d7a7c45ea4c2841dce67"
    $a9="4a7423a1ab3019f8b382a77b81225edbece3a3f22e5e52778e5f9396593bc9f261cbafde9200823468d6ea9559408e77"
    $a10="8648e91e15bd6cfca27c29475f37b560587eea33e4cd89cc1f8329e72f735908b783e5a857c963c3b6a231972baaa11d"
    $a11="bff3c4aab81c8b6c7544ab72666eadae5e991761d5e69640ce1cb6039354180159d4ad0ecbc20b1e62c79ba98f2247d3"
    $a12="13cdfc300d59dd907b2da20cafd595ac1b169dd0ecbc70108c75738c8ae6e2cd8f34a6bf4461a05e3520c199fd23184b"
    $a13="2fbdf8834a92a034434c2614ab2c99d7844668f908abd75c135178dbaacf069600ab67d7b257ae19e438117ee28591f9"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13)
}

rule sha3_512_hashed_default_creds_i2b2_workbench_mssql
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for i2b2_workbench_mssql. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="1576de20a88104cc42ef5bceabc041292eb1a93a2498acf32a16294a1866bda98620bd9cbf75041ca98e635987fd1726a60e013291ef516754f8f3e0592cd53d"
    $a1="b31b10f9c15b871145c2088cce3cffa588d96cc690772ba7363bc701e24fc5af98765f01c72bfe615190436cdfa48583f06eced610a74b1485d0ae2283805cbe"
    $a2="f9c0a1522bcf48e876c53c6666cdcbf9483b60dad06a6d10047646ea07355ebe38886371e6085a52aca38ef0a09726a8aebf20d2c721a72a5f13f562dd5d6a80"
    $a3="26526923c588acc54b4f434ebe07ea55052d0c0c0a526312f042523247d7526ffb00bcc910a629c2407df4559872ba3f349bc2170db90e85d63e926b984ca043"
    $a4="0cc96602c0f07c08103df6cd6e3ab0823d2fd0283465fff801fc7ba47eca7e5e834d882375a855ffb9e7e480a95a6d1d65c3c77b9289076aa7eae973d4084c12"
    $a5="7c52c75b0869edfc243acc4c0c57b23369ce8c53d69074ecd2e38e432c2ccee1049c2dabf28efbf4a001a3e277c4cd5b325aa836372e71a1c9af5939a0ad6dd2"
    $a6="1f7ce4d6e35c072dbf4ad27424c4609c0623f0b71eedc08129120f7c10102dc4e0e390d1ddc0870970c438a0273750e0ebbadd0fdca0fbdf870fed88da93f1d1"
    $a7="66ab55371bc9eb2b674b91381afee3d747dda1ed65cbd10cc40ce3a4d9ff69c007f120552056acbf9e50c1b0015fcfcad2cc61bfcd469437825038ad4ab149a1"
    $a8="5387020bbe4c2b2186aa2d9fc7f42e79e9a73322f26a515dc37380ed8b324fb409f535cccc70a9e97f8e857ef9a0bb2f633a74c2ca80409cf6d10b274606662c"
    $a9="7cd5d5cc14b9654557c099ac4423d6192de8485535f6de53841afb8214dbc0b6a4e63abc44ddf8d0c83d743ecd0a90648ffe6ffa5bfbfd17332afb7d33b68062"
    $a10="074631ec072c6777c541bf8d767df7babdb4b00c788e314f09c6eea213fbba7ed1252c5c3e06a0b4be3dd6655d33f6d60f506930af82dd68a366b8150c7f7486"
    $a11="1296b5abc2265fe188d84187df84c4b4d7e672e95aa3a86633e9c58a97f79dcaed9775229734aed3754f169c6b4ed6126bcc8c9802e3858430007a066751e6b8"
    $a12="c6ff872a97f4d8e664d0899821e9ad5421074a15d0c620e2e172c3a230b8dd962598f5e5169deab3e6a8f22d96b9e376272a5a36abec7073e550d2e1d3bbc3d2"
    $a13="0d6f5396dfa139eb971b1fb8860c753e7a5f11dafa68ae814ba487cce8e4bdd310aac4196259fe1810b38f6db51f427d237ec00c2f63f5a6e1e75f4ee3ecc80d"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13)
}

rule base64_hashed_default_creds_i2b2_workbench_mssql
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for i2b2_workbench_mssql. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="STJiMmRlbW9kYXRhMg=="
    $a1="aTJiMmRlbW9kYXRhMg=="
    $a2="STJiMmRlbW9kYXRh"
    $a3="aTJiMmRlbW9kYXRh"
    $a4="STJiMmhpdmU="
    $a5="aTJiMmhpdmU="
    $a6="STJiMm1ldGFkYXRhMg=="
    $a7="aTJiMm1ldGFkYXRhMg=="
    $a8="STJiMm1ldGFkYXRh"
    $a9="aTJiMm1ldGFkYXRh"
    $a10="STJiMndvcmtkYXRhMg=="
    $a11="aTJiMndvcmtkYXRhMg=="
    $a12="STJiMndvcmtkYXRh"
    $a13="aTJiMndvcmtkYXRh"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13)
}

