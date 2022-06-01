/*This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as long as you use it under this license.*/

rule md5_hashed_default_creds_zenitel
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for zenitel. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="21232f297a57a5a743894a0e4a801fc3"
    $a1="2b0939a5d0d3593b0945ca108905c41c"
    $a2="73acd9a5972130b75066c82595a1fae3"
    $a3="ff7d3b88d0c795de27b59f9c245dffa2"
    $a4="d41d8cd98f00b204e9800998ecf8427e"
    $a5="81dc9bdb52d04dc20036dbd8313ed055"
    $a6="d41d8cd98f00b204e9800998ecf8427e"
    $a7="ff1418e8cc993fe8abcfe3ce2003e5c5"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7)
}

rule sha1_hashed_default_creds_zenitel
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for zenitel. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="d033e22ae348aeb5660fc2140aec35850c4da997"
    $a1="03494a24ed5337acd1ebf90252e0456c384040ad"
    $a2="b521caa6e1db82e5a01c924a419870cb72b81635"
    $a3="082d67dc6c68a645871573e4f01807bbc2900da8"
    $a4="da39a3ee5e6b4b0d3255bfef95601890afd80709"
    $a5="7110eda4d09e062aa5e4a390b0a572ac0d2c0220"
    $a6="da39a3ee5e6b4b0d3255bfef95601890afd80709"
    $a7="f4807e7bc0ab85a61203b6e384806efeb08177af"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7)
}

rule sha384_hashed_default_creds_zenitel
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for zenitel. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="9ca694a90285c034432c9550421b7b9dbd5c0f4b6673f05f6dbce58052ba20e4248041956ee8c9a2ec9f10290cdc0782"
    $a1="925869fbc5428e20cc1fa0cb6494b04613d49a86f0e83954675b1f720207b0a725e0ff7cc0b05fe835dab5fb07821a43"
    $a2="63fc52ff0cf52087b8b5fc53850973d288f6982570d4b469c8dac1e963a93772d928ae1350913b121946085f0a63b853"
    $a3="5d62d62372734f5f447cd35304786d0f21f71d2511419eb941aa9b48109109662c0c2d360f5bbcb537f12e0cbb157eff"
    $a4="38b060a751ac96384cd9327eb1b1e36a21fdb71114be07434c0cc7bf63f6e1da274edebfe76f65fbd51ad2f14898b95b"
    $a5="504f008c8fcf8b2ed5dfcde752fc5464ab8ba064215d9c5b5fc486af3d9ab8c81b14785180d2ad7cee1ab792ad44798c"
    $a6="38b060a751ac96384cd9327eb1b1e36a21fdb71114be07434c0cc7bf63f6e1da274edebfe76f65fbd51ad2f14898b95b"
    $a7="7766170b9ab5a3618a4e19c31b66e7c1b2d964909767a3bd5425f38dece2beded940023743d15732c568e2d867614ed4"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7)
}

rule sha224_hashed_default_creds_zenitel
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for zenitel. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="58acb7acccce58ffa8b953b12b5a7702bd42dae441c1ad85057fa70b"
    $a1="0b9a18fade599c043105a30e2fed85636f4e774eb6b5be4cdd6ead7f"
    $a2="c417c5952fa1d63472b612f11e45809ea820ab918be37121fc257e6c"
    $a3="f8af17f5aee0f7da705e922237e1e695bf74b087e189e9cf26d212e9"
    $a4="d14a028c2a3a2bc9476102bb288234c415a2b01f828ea62ac5b3e42f"
    $a5="99fb2f48c6af4761f904fc85f95eb56190e5d40b1f44ec3a9c1fa319"
    $a6="d14a028c2a3a2bc9476102bb288234c415a2b01f828ea62ac5b3e42f"
    $a7="a6cc8fa12ffb11c2902aec6338c422766aab6892ad197315d335edfe"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7)
}

rule sha512_hashed_default_creds_zenitel
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for zenitel. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="c7ad44cbad762a5da0a452f9e854fdc1e0e7a52a38015f23f3eab1d80b931dd472634dfac71cd34ebc35d16ab7fb8a90c81f975113d6c7538dc69dd8de9077ec"
    $a1="4c8f375fb928d6222b51558dc522951ed74509ac57582cc2f2232afb9ab3e88866bcedc74c22391af19355b62de80dd3010cda91df7e415bcde86bd14b4d5cdd"
    $a2="238b90e6e2382ddafadc35266b2fa9a371fb3962b675ccab1b5538321f469070d0f3762f29b21ac7ad772eb6bd299d09f8e75d38ed8b7067965d5d5f26ebc3f5"
    $a3="fe825c0a5afa030658d6d59578d4467b725abd50438693909cd3cf91dd0b408c922fbddf79c3613f63e9327da58db8e02db16fecb6370e52d7fc93a873016052"
    $a4="cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e"
    $a5="d404559f602eab6fd602ac7680dacbfaadd13630335e951f097af3900e9de176b6db28512f2e000b9d04fba5133e8b1c6e8df59db3a8ab9d60be4b97cc9e81db"
    $a6="cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e"
    $a7="b4cd57c88adcb3583684d58449476dbaa7de38dc1caab4c8728d8356d831f7cdd926670e3603d633bbcb452476e028aa4c986ca9fcae01a64d731e62890028ff"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7)
}

rule sha256_hashed_default_creds_zenitel
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for zenitel. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="8c6976e5b5410415bde908bd4dee15dfb167a9c873fc4bb8a81f6f2ab448a918"
    $a1="c54ae6ef075d34df93c7a41ba0a0ca61ea25f0f9caae63cae57190c6633c73da"
    $a2="835d6dc88b708bc646d6db82c853ef4182fabbd4a8de59c213f2b5ab3ae7d9be"
    $a3="ba4e28af35a791f77cb6e6ad50f156651140c18fdb67f93fe18c2a0f6e3c68ae"
    $a4="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    $a5="03ac674216f3e15c761ee1a5e255f067953623c8b388b4459e13f978d7c846f4"
    $a6="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    $a7="871c39835ef093344f55dd14dab9ea54a4e9d76ee5634fff2e2be7d8e656be8b"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7)
}

rule blake2b_hashed_default_creds_zenitel
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for zenitel. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="bfcce2c19c8563fd4aa66f6ec607341ff25e5f6fe7fa520d7d1242d871385f23a3e8e80093120b4877d79535e10b182ae2ec8937d1f72f091e7178c9e4ff0f11"
    $a1="c93919d670505fb3e4671078dad31a8c878dd49d9babc90653d130630f5a0e9654c0bce24459f8fce97533922e0c45e4d6f4c558c25db5abf70677df4fa28181"
    $a2="c389a08ca48765ed7f0303e1823e4c20adf79b08368733b97fcb20b7c23d41e7487f826b4ee7c9c66b8e9d5ea50021271add19e347bfbfe0d5c6a053cf848589"
    $a3="f8216a868585a56bc4dede1138e491e35dadb1efb2c09ea9879b7ce42eabd5edcd57eab030f9d8e817ad44db261f3c3365357a1b9eb4727b55c6abc39bf488a7"
    $a4="786a02f742015903c6c6fd852552d272912f4740e15847618a86e217f71f5419d25e1031afee585313896444934eb04b903a685b1448b755d56f701afe9be2ce"
    $a5="da77bd2a1d857d88b31de27536b81df7f005027d4f847667df13a0569b6048e0454ce9480827789547cc174060c4f388866ebb0209929b0de414cc9ac571c421"
    $a6="786a02f742015903c6c6fd852552d272912f4740e15847618a86e217f71f5419d25e1031afee585313896444934eb04b903a685b1448b755d56f701afe9be2ce"
    $a7="5fdc2960152a8769edc558706104dcecdd705f054ec9e16940a4aaa99dee74b70e9fe5651c2b949bbaeaee2fb3096f5ab76f250fda031b3f6de1c68fa5a626bb"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7)
}

rule blake2s_hashed_default_creds_zenitel
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for zenitel. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="327e7e3821f5f6d33c090137f979bf48ee62e9051c1610e1d6468ecb3c67a124"
    $a1="af7934ee4422362eb36803d0174c8e3806ed6509fd4511474a8c7949fdaf0d41"
    $a2="6204076fc988d9c8ba327799ea12528be066aad0192027adfcd3b505067edd3e"
    $a3="f54118fba98154d2bcd55b64e65b4d2faf19da54581939a8ecfb35797f3ce3e8"
    $a4="69217a3079908094e11121d042354a7c1f55b6482ca1a51e1b250dfd1ed0eef9"
    $a5="90931556d9513e8c26040a9ec2a2f1300bdc79a890907da9cc2b3a2c690574c1"
    $a6="69217a3079908094e11121d042354a7c1f55b6482ca1a51e1b250dfd1ed0eef9"
    $a7="09278df8d7fe3deaffa214c377d9069ae568e192da9b728b2c4fe6ab5e17f386"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7)
}

rule sha3_224_hashed_default_creds_zenitel
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for zenitel. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="a53fff8dd075bed169e164743231ff533d8b9260b0b8073f0a4c1d20"
    $a1="91c998d95dd632aff4f89ce2267bae3569aac0bc335cddd85442a337"
    $a2="cfbb56a314e406232e84144aa3b459691cc889b7b7d7406dcf2aeec1"
    $a3="df2099a205e965d2439f4d058e6d9ce0efab8761271f27cce682fd5f"
    $a4="6b4e03423667dbb73b6e15454f0eb1abd4597f9a1b078e3f5b5a6bc7"
    $a5="b0f3dc043a9c5c05f67651a8c9108b4c2b98e7246b2eea14cb204295"
    $a6="6b4e03423667dbb73b6e15454f0eb1abd4597f9a1b078e3f5b5a6bc7"
    $a7="4af931edf4e68f7856a6129f4e35f107beb7332a18248ce9c015388e"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7)
}

rule sha3_256_hashed_default_creds_zenitel
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for zenitel. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="fb001dfcffd1c899f3297871406242f097aecf1a5342ccf3ebcd116146188e4b"
    $a1="f338288eee1514243d931265ff46db5d4d75d769cf7eb80ff8bd84cc26f00d41"
    $a2="aeae63318b23cc3826a1b396f8ce6c5b83c89629acc8e5ed6ff944eb21d047ed"
    $a3="a107a3748c537701a39deb3e6130c0c5bed3badd11b49403ae644ac6347ebca2"
    $a4="a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a"
    $a5="1d6442ddcfd9db1ff81df77cbefcd5afcc8c7ca952ab3101ede17a84b866d3f3"
    $a6="a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a"
    $a7="aaaf4c262895753d6eb959a950c62f09063844fc80358dfed434aeb6b16c0af6"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7)
}

rule sha3_384_hashed_default_creds_zenitel
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for zenitel. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="9765a57f2010506383de91052915ce8bafbdb39f3e5a8c1a1693a0076365d37abbfd3305881ea3b5fa1426316afd7df3"
    $a1="963e2d7148bcc9a8e67571e4026fbf33b722a52aba9c13b61db7fd786c277b099cb48a8496db28df474f455391f9686f"
    $a2="0ca063dc16aa3e8234bbd5644bd93ceb65324c6cf85b00f711c63505ce5e05adc49c233115a1e153e8ad0947052037ca"
    $a3="3eb943fdf9f9aa06f7e7d812b8a099394e379b6d6dab9c5bb4e75993b764fce3543e138fa2f638431441cba86c3cf001"
    $a4="0c63a75b845e4f7d01107d852e4c2485c51a50aaaa94fc61995e71bbee983a2ac3713831264adb47fb6bd1e058d5f004"
    $a5="0bf2c5eed2dc859ca9707ae59a18b5097d580ce705808b80830c5cf5832405073e3fa3491ed7071a2362048edff48295"
    $a6="0c63a75b845e4f7d01107d852e4c2485c51a50aaaa94fc61995e71bbee983a2ac3713831264adb47fb6bd1e058d5f004"
    $a7="df7d85509fa17ee0c3ee8be041f0eed02d899f5a32b451f81838972c8c9afe7d0b44257e6c2d5ed67ba6b61c5d968007"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7)
}

rule sha3_512_hashed_default_creds_zenitel
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for zenitel. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="5a38afb1a18d408e6cd367f9db91e2ab9bce834cdad3da24183cc174956c20ce35dd39c2bd36aae907111ae3d6ada353f7697a5f1a8fc567aae9e4ca41a9d19d"
    $a1="0f499790d738f251e00b6d0070a6b80628f914b0982134117945472413ceebaa569b273bae2e483d623a977ae454503e537886853993d41b8b3eac11ca5bd59a"
    $a2="b12c327f742aac769cc3a8ebcb2dff2cb6bbf4ef7f8edd42ab65dbebb1cff8e72da7eef015355396474167708e54248fc8989a86b2da61c84f8fc5d500d2bd11"
    $a3="d88d5a0fe93ec16e99f580d2ecab5f0583535497ab7f6e8b5ae021bb06e29201ec666f80b3c7082868c1e1cf7e8d938cc65a0c1eb661355d93e59bf625cc3807"
    $a4="a69f73cca23a9ac5c8b567dc185a756e97c982164fe25859e0d1dcc1475c80a615b2123af1f5f94c11e3e9402c3ac558f500199d95b6d3e301758586281dcd26"
    $a5="d760688da522b4dc3350e6fb68961b0934f911c7d0ff337438cabf4608789ba94ce70b6601d7e08a279ef088716c4b1913b984513fea4c557d404d0598d4f2f1"
    $a6="a69f73cca23a9ac5c8b567dc185a756e97c982164fe25859e0d1dcc1475c80a615b2123af1f5f94c11e3e9402c3ac558f500199d95b6d3e301758586281dcd26"
    $a7="610945a8e6ca99983001a947fa52b4d9f5e95949490f78d7ee95f6cef9377da0f6ba5c77e6a1c8bc664493f3e419bff678da97ccaa520c810ec7eaf84a79e570"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7)
}

rule base64_hashed_default_creds_zenitel
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for zenitel. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="YWRtaW4="
    $a1="YWxwaGFhZG1pbg=="
    $a2="QURNSU4="
    $a3="YWxwaGFjb20="
    $a4="===="
    $a5="MTIzNA=="
    $a6="===="
    $a7="MTg1MQ=="
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7)
}

