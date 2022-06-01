/*This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as long as you use it under this license.*/

rule md5_hashed_default_creds_symbol
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for symbol. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="21232f297a57a5a743894a0e4a801fc3"
    $a1="97bff26855a8bfa63e05d5477e794b24"
    $a2="d41d8cd98f00b204e9800998ecf8427e"
    $a3="02c86eb2792f3262c21d030a87e19793"
    $a4="02c86eb2792f3262c21d030a87e19793"
    $a5="02c86eb2792f3262c21d030a87e19793"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}

rule sha1_hashed_default_creds_symbol
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for symbol. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="d033e22ae348aeb5660fc2140aec35850c4da997"
    $a1="810a25d76c31e495cc070bdf42e076f7c9b0a1cd"
    $a2="da39a3ee5e6b4b0d3255bfef95601890afd80709"
    $a3="3f84ef531f9db996694ad09a8fdddbca1440577e"
    $a4="3f84ef531f9db996694ad09a8fdddbca1440577e"
    $a5="3f84ef531f9db996694ad09a8fdddbca1440577e"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}

rule sha384_hashed_default_creds_symbol
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for symbol. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="9ca694a90285c034432c9550421b7b9dbd5c0f4b6673f05f6dbce58052ba20e4248041956ee8c9a2ec9f10290cdc0782"
    $a1="8d25604a8bbfdef1024d3d8c2dbce0f611dc57ff2af88b8a79756eee3254aa3e6699023e69c66a0b3d552cf32bd550b5"
    $a2="38b060a751ac96384cd9327eb1b1e36a21fdb71114be07434c0cc7bf63f6e1da274edebfe76f65fbd51ad2f14898b95b"
    $a3="dacbe2de6441f1b603b49c4f35d998adc878f22108c46c868a49208acb3a22eed93ed8dc3fe5864fc60f232a98aa4472"
    $a4="dacbe2de6441f1b603b49c4f35d998adc878f22108c46c868a49208acb3a22eed93ed8dc3fe5864fc60f232a98aa4472"
    $a5="dacbe2de6441f1b603b49c4f35d998adc878f22108c46c868a49208acb3a22eed93ed8dc3fe5864fc60f232a98aa4472"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}

rule sha224_hashed_default_creds_symbol
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for symbol. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="58acb7acccce58ffa8b953b12b5a7702bd42dae441c1ad85057fa70b"
    $a1="b2ffac084974a94d2393c4f48a9e9e0c7b84ec4fc8857f9bcdff45e2"
    $a2="d14a028c2a3a2bc9476102bb288234c415a2b01f828ea62ac5b3e42f"
    $a3="9ac4c81d4f926ecc59f4f3eb3e9f4b590fc9828e74654d0e93b2295a"
    $a4="9ac4c81d4f926ecc59f4f3eb3e9f4b590fc9828e74654d0e93b2295a"
    $a5="9ac4c81d4f926ecc59f4f3eb3e9f4b590fc9828e74654d0e93b2295a"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}

rule sha512_hashed_default_creds_symbol
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for symbol. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="c7ad44cbad762a5da0a452f9e854fdc1e0e7a52a38015f23f3eab1d80b931dd472634dfac71cd34ebc35d16ab7fb8a90c81f975113d6c7538dc69dd8de9077ec"
    $a1="60a8c2b8151f19e9906f9792c36fa2ff659dca4189bc2e7c82e830524e3c70813a8beee3a14f37321bd67abea79e9e8b12c445078c89344531a0452b7b1f632a"
    $a2="cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e"
    $a3="dc77a9990a0467e22c42be36697552e3e6b0891e4c758a864af94e621d62a6becbe7d388b255c3634c36ef09661c69ec4c7ad8ee1493cd8d925b2a4d4f040260"
    $a4="dc77a9990a0467e22c42be36697552e3e6b0891e4c758a864af94e621d62a6becbe7d388b255c3634c36ef09661c69ec4c7ad8ee1493cd8d925b2a4d4f040260"
    $a5="dc77a9990a0467e22c42be36697552e3e6b0891e4c758a864af94e621d62a6becbe7d388b255c3634c36ef09661c69ec4c7ad8ee1493cd8d925b2a4d4f040260"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}

rule sha256_hashed_default_creds_symbol
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for symbol. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="8c6976e5b5410415bde908bd4dee15dfb167a9c873fc4bb8a81f6f2ab448a918"
    $a1="b76a7ca153c24671658335bbd08946350ffc621fa1c516e7123095d4ffd5c581"
    $a2="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    $a3="ba0e4afa93400b805dfcc4b9e6aef549269946e2d1af5ababfc3a73c67912d89"
    $a4="ba0e4afa93400b805dfcc4b9e6aef549269946e2d1af5ababfc3a73c67912d89"
    $a5="ba0e4afa93400b805dfcc4b9e6aef549269946e2d1af5ababfc3a73c67912d89"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}

rule blake2b_hashed_default_creds_symbol
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for symbol. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="bfcce2c19c8563fd4aa66f6ec607341ff25e5f6fe7fa520d7d1242d871385f23a3e8e80093120b4877d79535e10b182ae2ec8937d1f72f091e7178c9e4ff0f11"
    $a1="57178a4a67c7974d512a81ca798eb89e5a100edd27ab0422c690d527f15c31f6b0046a89173b65409ad3fb6fb62ede7c26deafa34895e889927fec29b46efbcd"
    $a2="786a02f742015903c6c6fd852552d272912f4740e15847618a86e217f71f5419d25e1031afee585313896444934eb04b903a685b1448b755d56f701afe9be2ce"
    $a3="d3a9a8c875ab459b9de48c34114330a6f228d525fca03b00eccd95f6ed9f9f18ee71b61bed14503ba8d0a8f52d8fda17cb3cf7a3da20589a2d7ce8d17a943da0"
    $a4="d3a9a8c875ab459b9de48c34114330a6f228d525fca03b00eccd95f6ed9f9f18ee71b61bed14503ba8d0a8f52d8fda17cb3cf7a3da20589a2d7ce8d17a943da0"
    $a5="d3a9a8c875ab459b9de48c34114330a6f228d525fca03b00eccd95f6ed9f9f18ee71b61bed14503ba8d0a8f52d8fda17cb3cf7a3da20589a2d7ce8d17a943da0"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}

rule blake2s_hashed_default_creds_symbol
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for symbol. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="327e7e3821f5f6d33c090137f979bf48ee62e9051c1610e1d6468ecb3c67a124"
    $a1="dcf5f7e8cacc71b4940afd674ddfbd5048727156bea54c6b53dcb5ecfe5d7077"
    $a2="69217a3079908094e11121d042354a7c1f55b6482ca1a51e1b250dfd1ed0eef9"
    $a3="ae41ad868e3152db8f44fbfee6b89a053ed9b892b1267deb46e585219dc664eb"
    $a4="ae41ad868e3152db8f44fbfee6b89a053ed9b892b1267deb46e585219dc664eb"
    $a5="ae41ad868e3152db8f44fbfee6b89a053ed9b892b1267deb46e585219dc664eb"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}

rule sha3_224_hashed_default_creds_symbol
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for symbol. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="a53fff8dd075bed169e164743231ff533d8b9260b0b8073f0a4c1d20"
    $a1="c47c3b65f4d1014d4a7012696551a53ff1c154fb3025c5b221c56ef0"
    $a2="6b4e03423667dbb73b6e15454f0eb1abd4597f9a1b078e3f5b5a6bc7"
    $a3="5fd8a9cdd1b01180a7f27844af85a615ed6f9287bd8754a9fabdc8a7"
    $a4="5fd8a9cdd1b01180a7f27844af85a615ed6f9287bd8754a9fabdc8a7"
    $a5="5fd8a9cdd1b01180a7f27844af85a615ed6f9287bd8754a9fabdc8a7"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}

rule sha3_256_hashed_default_creds_symbol
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for symbol. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="fb001dfcffd1c899f3297871406242f097aecf1a5342ccf3ebcd116146188e4b"
    $a1="afdd4a73b7219632c5e045c426ad106d1564c96ecfe9299cdcb9d5af0f7e1ed2"
    $a2="a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a"
    $a3="c7e54715454ed8169f67e800a58be511c2f8c0236e088e895d393c81c944e2d7"
    $a4="c7e54715454ed8169f67e800a58be511c2f8c0236e088e895d393c81c944e2d7"
    $a5="c7e54715454ed8169f67e800a58be511c2f8c0236e088e895d393c81c944e2d7"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}

rule sha3_384_hashed_default_creds_symbol
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for symbol. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="9765a57f2010506383de91052915ce8bafbdb39f3e5a8c1a1693a0076365d37abbfd3305881ea3b5fa1426316afd7df3"
    $a1="d931599da33a102b3c326872e9acd7608dc0251fea000f49bd2e3dcba99c441270cca1906a6df8900f1f8d291c26db06"
    $a2="0c63a75b845e4f7d01107d852e4c2485c51a50aaaa94fc61995e71bbee983a2ac3713831264adb47fb6bd1e058d5f004"
    $a3="511f3077273b59714ac47f5e96151acd6d9ecac08516ecee10676e8a383f736f4817f6287d37d08c055098beaeec0025"
    $a4="511f3077273b59714ac47f5e96151acd6d9ecac08516ecee10676e8a383f736f4817f6287d37d08c055098beaeec0025"
    $a5="511f3077273b59714ac47f5e96151acd6d9ecac08516ecee10676e8a383f736f4817f6287d37d08c055098beaeec0025"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}

rule sha3_512_hashed_default_creds_symbol
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for symbol. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="5a38afb1a18d408e6cd367f9db91e2ab9bce834cdad3da24183cc174956c20ce35dd39c2bd36aae907111ae3d6ada353f7697a5f1a8fc567aae9e4ca41a9d19d"
    $a1="74ae2367eb66737d132c500d96a18da3d06d2887db244161ca35c95fd3d4c8f22597c96dc97d7c9b5c0f52a5a8c920655ab4dd768b68c306207df02953165cb1"
    $a2="a69f73cca23a9ac5c8b567dc185a756e97c982164fe25859e0d1dcc1475c80a615b2123af1f5f94c11e3e9402c3ac558f500199d95b6d3e301758586281dcd26"
    $a3="5c518e23c25c76fd1fb1f36cf4cb56dd520db4cfb8e14216eba390c5b8ad727e3f580516610aa74ac67193b50a9349518f2fdf153dc0fafcc432960621fcf602"
    $a4="5c518e23c25c76fd1fb1f36cf4cb56dd520db4cfb8e14216eba390c5b8ad727e3f580516610aa74ac67193b50a9349518f2fdf153dc0fafcc432960621fcf602"
    $a5="5c518e23c25c76fd1fb1f36cf4cb56dd520db4cfb8e14216eba390c5b8ad727e3f580516610aa74ac67193b50a9349518f2fdf153dc0fafcc432960621fcf602"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}

rule base64_hashed_default_creds_symbol
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for symbol. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="YWRtaW4="
    $a1="c3ltYm9s"
    $a2="===="
    $a3="U3ltYm9s"
    $a4="U3ltYm9s"
    $a5="U3ltYm9s"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}

