/*This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as long as you use it under this license.*/

rule md5_hashed_default_creds_fortinet
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for fortinet. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="21232f297a57a5a743894a0e4a801fc3"
    $a1="d41d8cd98f00b204e9800998ecf8427e"
    $a2="d41d8cd98f00b204e9800998ecf8427e"
    $a3="2b5202e2ca770865479d47e91513ac08"
    $a4="9ae55575a3588889a4609a010ef6767e"
    $a5="21232f297a57a5a743894a0e4a801fc3"
    $a6="9ae55575a3588889a4609a010ef6767e"
    $a7="a89e1931f7b4c706e14b87c641e4fcfb"
    $a8="9ae55575a3588889a4609a010ef6767e"
    $a9="41f6707eeb565498bc83b833261bdbb6"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9)
}

rule sha1_hashed_default_creds_fortinet
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for fortinet. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="d033e22ae348aeb5660fc2140aec35850c4da997"
    $a1="da39a3ee5e6b4b0d3255bfef95601890afd80709"
    $a2="da39a3ee5e6b4b0d3255bfef95601890afd80709"
    $a3="66d9054684d7ec77c23e5c6045f6c840b2d0d837"
    $a4="86416ef3eeb4cc907ebcd12c0305511b4cfc5474"
    $a5="d033e22ae348aeb5660fc2140aec35850c4da997"
    $a6="86416ef3eeb4cc907ebcd12c0305511b4cfc5474"
    $a7="f81ec4fe7879c9a6d06b7204417f3097d727fd6d"
    $a8="86416ef3eeb4cc907ebcd12c0305511b4cfc5474"
    $a9="3f4c683ef920d351306096b266b38773fbc522c4"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9)
}

rule sha384_hashed_default_creds_fortinet
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for fortinet. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="9ca694a90285c034432c9550421b7b9dbd5c0f4b6673f05f6dbce58052ba20e4248041956ee8c9a2ec9f10290cdc0782"
    $a1="38b060a751ac96384cd9327eb1b1e36a21fdb71114be07434c0cc7bf63f6e1da274edebfe76f65fbd51ad2f14898b95b"
    $a2="38b060a751ac96384cd9327eb1b1e36a21fdb71114be07434c0cc7bf63f6e1da274edebfe76f65fbd51ad2f14898b95b"
    $a3="52870940601282a89425feefe2a9f2aaf76f0122b594e368397bd1ed99d6902c7e2983fa3014aa2041bf018116d20506"
    $a4="8d0bc3d36a50936cba4b2800da32086ae1389a30daf8332d11150bf5d390cbdb88cdfeae1691889b025270f10569762e"
    $a5="9ca694a90285c034432c9550421b7b9dbd5c0f4b6673f05f6dbce58052ba20e4248041956ee8c9a2ec9f10290cdc0782"
    $a6="8d0bc3d36a50936cba4b2800da32086ae1389a30daf8332d11150bf5d390cbdb88cdfeae1691889b025270f10569762e"
    $a7="7af516c02e2b5c52a3666c4ce57a3c13e932a4067b0b741fe2ae2f7b68eb46f308e761671755928fa8c5571a7f846c34"
    $a8="8d0bc3d36a50936cba4b2800da32086ae1389a30daf8332d11150bf5d390cbdb88cdfeae1691889b025270f10569762e"
    $a9="bce13b89af4d6d30bbc87322c89e90603a5dc660ddb487b4e7890f8ecc43f11ea393ab7f83aa3eed7a05b96959116423"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9)
}

rule sha224_hashed_default_creds_fortinet
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for fortinet. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="58acb7acccce58ffa8b953b12b5a7702bd42dae441c1ad85057fa70b"
    $a1="d14a028c2a3a2bc9476102bb288234c415a2b01f828ea62ac5b3e42f"
    $a2="d14a028c2a3a2bc9476102bb288234c415a2b01f828ea62ac5b3e42f"
    $a3="5fe261ef79367c96c7abe310f8ddc72cfc755e9e88f9922f668ad96e"
    $a4="eccdf0adddfa793166dba90f4ee2d7353a327b397686680fbb9bdb61"
    $a5="58acb7acccce58ffa8b953b12b5a7702bd42dae441c1ad85057fa70b"
    $a6="eccdf0adddfa793166dba90f4ee2d7353a327b397686680fbb9bdb61"
    $a7="1aeaaada4e12586aded001e2ab19b98df2df6931a21f5682b7bd288a"
    $a8="eccdf0adddfa793166dba90f4ee2d7353a327b397686680fbb9bdb61"
    $a9="4ca8a5406e7795ad5fd78f7e1d16251263745d2351a7897ce1f2a8bb"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9)
}

rule sha512_hashed_default_creds_fortinet
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for fortinet. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="c7ad44cbad762a5da0a452f9e854fdc1e0e7a52a38015f23f3eab1d80b931dd472634dfac71cd34ebc35d16ab7fb8a90c81f975113d6c7538dc69dd8de9077ec"
    $a1="cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e"
    $a2="cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e"
    $a3="b11e570d783ff08b6f920e55653a1833e366460039cf69df31e4b2e36cde6f1440b0f07c0545d937f5b097acb69c57e7c04731c608794f1aa66e8d1d75b99992"
    $a4="dbe2ac714cddf902f6094133afbc3976a3f79cb03b350f21559d81da04b086bb2b414bd7fcf48b751f6dd3b48b2abf0c7d42e59059b4db3432a8ca130323e8e8"
    $a5="c7ad44cbad762a5da0a452f9e854fdc1e0e7a52a38015f23f3eab1d80b931dd472634dfac71cd34ebc35d16ab7fb8a90c81f975113d6c7538dc69dd8de9077ec"
    $a6="dbe2ac714cddf902f6094133afbc3976a3f79cb03b350f21559d81da04b086bb2b414bd7fcf48b751f6dd3b48b2abf0c7d42e59059b4db3432a8ca130323e8e8"
    $a7="e31687dba46f908c72c0b572e7cd53b5f3de5cdc3e527dbae4cf59162c1b6bdd0d2268b2d09c906aa4ad65f048adc6261164353aa813a7085d0bc713a60e9c91"
    $a8="dbe2ac714cddf902f6094133afbc3976a3f79cb03b350f21559d81da04b086bb2b414bd7fcf48b751f6dd3b48b2abf0c7d42e59059b4db3432a8ca130323e8e8"
    $a9="0eb20e5b4c6a9994e4ba220182020c6bec0e8869c99c8d0313dd254fe59998b15a252fd695392f77a3ee39d3a9b29b4ddb7a1a6fdba9fe898b00e6b71de28641"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9)
}

rule sha256_hashed_default_creds_fortinet
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for fortinet. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="8c6976e5b5410415bde908bd4dee15dfb167a9c873fc4bb8a81f6f2ab448a918"
    $a1="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    $a2="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    $a3="622542d3c23f9ffbee472ac5c1926499ea08d84de9a57662af29e73e0dc8e379"
    $a4="9c5646b582f10531c791dd2372854409c96e8276f979c0aa4a505ec760e06100"
    $a5="8c6976e5b5410415bde908bd4dee15dfb167a9c873fc4bb8a81f6f2ab448a918"
    $a6="9c5646b582f10531c791dd2372854409c96e8276f979c0aa4a505ec760e06100"
    $a7="d11185e77abb337f29c36d038ebbe4d4cec984538283d4fb520ef7f3860c2541"
    $a8="9c5646b582f10531c791dd2372854409c96e8276f979c0aa4a505ec760e06100"
    $a9="d7bf8a87314f48ba8567998bf502a15d71dc882ec8de2f7ed58d003f46573217"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9)
}

rule blake2b_hashed_default_creds_fortinet
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for fortinet. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="bfcce2c19c8563fd4aa66f6ec607341ff25e5f6fe7fa520d7d1242d871385f23a3e8e80093120b4877d79535e10b182ae2ec8937d1f72f091e7178c9e4ff0f11"
    $a1="786a02f742015903c6c6fd852552d272912f4740e15847618a86e217f71f5419d25e1031afee585313896444934eb04b903a685b1448b755d56f701afe9be2ce"
    $a2="786a02f742015903c6c6fd852552d272912f4740e15847618a86e217f71f5419d25e1031afee585313896444934eb04b903a685b1448b755d56f701afe9be2ce"
    $a3="43a77afb14d597b136c20872f2fc28d538ae41401b0da99b8736b4d3816a2b98bb56a0263d6e5129125eff689004ee87d0fb0a9035cd3a98d047f028e40f9bcb"
    $a4="4cb279237ab023accfa7e593fa8bdf959ee5faa525dd346e24f88e7115e11fbb688bc98d52ae9beb8ac30c23af8ca04abc3c390271ab8f8fbe9f431fdaa7b483"
    $a5="bfcce2c19c8563fd4aa66f6ec607341ff25e5f6fe7fa520d7d1242d871385f23a3e8e80093120b4877d79535e10b182ae2ec8937d1f72f091e7178c9e4ff0f11"
    $a6="4cb279237ab023accfa7e593fa8bdf959ee5faa525dd346e24f88e7115e11fbb688bc98d52ae9beb8ac30c23af8ca04abc3c390271ab8f8fbe9f431fdaa7b483"
    $a7="3461b3ddae3e29468d925f1ec18d41671f1237914a0642ec559cec10fb42918b444d54ed9fcd97fe49b3652143349af8c00aeb6b5520163c83db949e9d2b47af"
    $a8="4cb279237ab023accfa7e593fa8bdf959ee5faa525dd346e24f88e7115e11fbb688bc98d52ae9beb8ac30c23af8ca04abc3c390271ab8f8fbe9f431fdaa7b483"
    $a9="2f6deb55f0aa2e248a133f2e022fda0fa8709a8ca1ab55ec002ed99c4777d089b70462f66593103ea1e42931cf4b6108945b71fdca8e78b8969e558829fa0513"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9)
}

rule blake2s_hashed_default_creds_fortinet
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for fortinet. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="327e7e3821f5f6d33c090137f979bf48ee62e9051c1610e1d6468ecb3c67a124"
    $a1="69217a3079908094e11121d042354a7c1f55b6482ca1a51e1b250dfd1ed0eef9"
    $a2="69217a3079908094e11121d042354a7c1f55b6482ca1a51e1b250dfd1ed0eef9"
    $a3="1f02ae88ea98666fb96ac488e33361f8ba6db22dab811652299961070a57b469"
    $a4="211cf96d140aeafb62ffc43abe3f75812fa2651cd37a15ec6d829a2b085f22cf"
    $a5="327e7e3821f5f6d33c090137f979bf48ee62e9051c1610e1d6468ecb3c67a124"
    $a6="211cf96d140aeafb62ffc43abe3f75812fa2651cd37a15ec6d829a2b085f22cf"
    $a7="ecc901026d4b7dd2f933a628c6c0dda3e5ff33ba69016cee9560ca34a29199e9"
    $a8="211cf96d140aeafb62ffc43abe3f75812fa2651cd37a15ec6d829a2b085f22cf"
    $a9="ae97ba78fcafc06d37efc1851fd111bffad73d57bd1c7d5ddb7e8df279250c78"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9)
}

rule sha3_224_hashed_default_creds_fortinet
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for fortinet. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="a53fff8dd075bed169e164743231ff533d8b9260b0b8073f0a4c1d20"
    $a1="6b4e03423667dbb73b6e15454f0eb1abd4597f9a1b078e3f5b5a6bc7"
    $a2="6b4e03423667dbb73b6e15454f0eb1abd4597f9a1b078e3f5b5a6bc7"
    $a3="b6c6919cdbb526b17a4772b55a5e6c1253f2ca6a3209f112e43894ab"
    $a4="8a6ee7a6e59c5ee453a7674f284daf3c259f929a6c8a9094e546d406"
    $a5="a53fff8dd075bed169e164743231ff533d8b9260b0b8073f0a4c1d20"
    $a6="8a6ee7a6e59c5ee453a7674f284daf3c259f929a6c8a9094e546d406"
    $a7="242f4b098f186780f9547da35187f4e2bea14cd108c8bc996a36814b"
    $a8="8a6ee7a6e59c5ee453a7674f284daf3c259f929a6c8a9094e546d406"
    $a9="6b0a1c22b7a9f336ca970307497f2bc9e0976b083f9e8ca9d6eab0b7"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9)
}

rule sha3_256_hashed_default_creds_fortinet
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for fortinet. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="fb001dfcffd1c899f3297871406242f097aecf1a5342ccf3ebcd116146188e4b"
    $a1="a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a"
    $a2="a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a"
    $a3="99b262df09c1e7b51be9f5220a5be5633c6b8d00c4e3048e89cc66d091f0a0d5"
    $a4="690e36fa8c6440b20da312da2f328bd061f155526fff967b1062f6e30c976ef2"
    $a5="fb001dfcffd1c899f3297871406242f097aecf1a5342ccf3ebcd116146188e4b"
    $a6="690e36fa8c6440b20da312da2f328bd061f155526fff967b1062f6e30c976ef2"
    $a7="b33c7c2c2d2680b89e6d1acf253abfe626a6853b1580ef638ef898ab86082d7d"
    $a8="690e36fa8c6440b20da312da2f328bd061f155526fff967b1062f6e30c976ef2"
    $a9="3cbfa61a98f38951ac8c580f79e9681200218a85111d136f582a1a84019e0a61"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9)
}

rule sha3_384_hashed_default_creds_fortinet
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for fortinet. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="9765a57f2010506383de91052915ce8bafbdb39f3e5a8c1a1693a0076365d37abbfd3305881ea3b5fa1426316afd7df3"
    $a1="0c63a75b845e4f7d01107d852e4c2485c51a50aaaa94fc61995e71bbee983a2ac3713831264adb47fb6bd1e058d5f004"
    $a2="0c63a75b845e4f7d01107d852e4c2485c51a50aaaa94fc61995e71bbee983a2ac3713831264adb47fb6bd1e058d5f004"
    $a3="fb8854478dea0977d8e325262fabe628d7bb5a15b2d7f3f8ed1a7d5ca3e093a5baf1511fd05c9bc55bdf3ab58d35f84a"
    $a4="2939d842fe82d218507180743a8a8cfc81077eeaed6c2fa16a1991a89aceaad75195d52ae952b05fbc746528336893ad"
    $a5="9765a57f2010506383de91052915ce8bafbdb39f3e5a8c1a1693a0076365d37abbfd3305881ea3b5fa1426316afd7df3"
    $a6="2939d842fe82d218507180743a8a8cfc81077eeaed6c2fa16a1991a89aceaad75195d52ae952b05fbc746528336893ad"
    $a7="b346e046c4193deca8b843990b75b1cbefc7e9ad998f36700d3259113df8745918d4868de69f3fe3a966f7552f69d820"
    $a8="2939d842fe82d218507180743a8a8cfc81077eeaed6c2fa16a1991a89aceaad75195d52ae952b05fbc746528336893ad"
    $a9="aed89cba56a6a539d4f1bd0ee475b2bca1495d83c18b0c314941803613662f631f45b13e73ab9039f8396c9515dcad9e"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9)
}

rule sha3_512_hashed_default_creds_fortinet
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for fortinet. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="5a38afb1a18d408e6cd367f9db91e2ab9bce834cdad3da24183cc174956c20ce35dd39c2bd36aae907111ae3d6ada353f7697a5f1a8fc567aae9e4ca41a9d19d"
    $a1="a69f73cca23a9ac5c8b567dc185a756e97c982164fe25859e0d1dcc1475c80a615b2123af1f5f94c11e3e9402c3ac558f500199d95b6d3e301758586281dcd26"
    $a2="a69f73cca23a9ac5c8b567dc185a756e97c982164fe25859e0d1dcc1475c80a615b2123af1f5f94c11e3e9402c3ac558f500199d95b6d3e301758586281dcd26"
    $a3="da5dad9f1b38ecd9f7edabb93f70a68ac27f7f1a9903fc01bc60aa587a8de877729ac3b0776a4aaf0008d26bbdfaefa7c730643dd217024cb2e7a1dbfc11dd5d"
    $a4="2f01dac6a2ff602460f44a8337a4910c6b39ec4aa315245029243c73a51544c0779c5e1b3e9239bdff4d8decf2747dc161e9f30edfaa1e0d9f4ef9d231d020a9"
    $a5="5a38afb1a18d408e6cd367f9db91e2ab9bce834cdad3da24183cc174956c20ce35dd39c2bd36aae907111ae3d6ada353f7697a5f1a8fc567aae9e4ca41a9d19d"
    $a6="2f01dac6a2ff602460f44a8337a4910c6b39ec4aa315245029243c73a51544c0779c5e1b3e9239bdff4d8decf2747dc161e9f30edfaa1e0d9f4ef9d231d020a9"
    $a7="a89a5c422f0abb27bddbd6c81c8723c8ec2c415f57dc249daf80e857d5ecd9191a9d744ee2300f0c3cbe8d9c05501540d7eba027722e9a6c9d25d6e79338dd8c"
    $a8="2f01dac6a2ff602460f44a8337a4910c6b39ec4aa315245029243c73a51544c0779c5e1b3e9239bdff4d8decf2747dc161e9f30edfaa1e0d9f4ef9d231d020a9"
    $a9="a280d5fcdc558049d04a666dfde3cd9d1630a913b5221ef58874ecfebe4a6589a6358573037616c9e7426f8bc538eff0e57431e54aa50d574716ae2928dc34af"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9)
}

rule base64_hashed_default_creds_fortinet
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for fortinet. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="YWRtaW4="
    $a1="===="
    $a2="===="
    $a3="YmNwYihzZXJpYWwgbnVtYmVyIG9mIHRoZSBmaXJld2FsbCk="
    $a4="bWFpbnRhaW5lcg=="
    $a5="YWRtaW4="
    $a6="bWFpbnRhaW5lcg=="
    $a7="YmNwYltTRVJJQUwgTk8uXQ=="
    $a8="bWFpbnRhaW5lcg=="
    $a9="cGJjcGJuKGFkZC1zZXJpYWwtbnVtYmVyKQ=="
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9)
}

