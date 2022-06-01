/*This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as long as you use it under this license.*/

rule md5_hashed_default_creds_ericsson
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for ericsson. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="21232f297a57a5a743894a0e4a801fc3"
    $a1="c21f969b5f03d33d43e04f8f136e7682"
    $a2="d41d8cd98f00b204e9800998ecf8427e"
    $a3="d41d8cd98f00b204e9800998ecf8427e"
    $a4="d41d8cd98f00b204e9800998ecf8427e"
    $a5="657f8b8da628ef83cf69101b6817150a"
    $a6="b9b83bad6bd2b4f7c40109304cf580e1"
    $a7="b9b83bad6bd2b4f7c40109304cf580e1"
    $a8="69090e1aa8f5397ab41bef9074816cc8"
    $a9="657f8b8da628ef83cf69101b6817150a"
    $a10="0d851b18c1313c76b2731fb1bca53af8"
    $a11="0d851b18c1313c76b2731fb1bca53af8"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11)
}

rule sha1_hashed_default_creds_ericsson
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for ericsson. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="d033e22ae348aeb5660fc2140aec35850c4da997"
    $a1="7505d64a54e061b7acd54ccd58b49dc43500b635"
    $a2="da39a3ee5e6b4b0d3255bfef95601890afd80709"
    $a3="da39a3ee5e6b4b0d3255bfef95601890afd80709"
    $a4="da39a3ee5e6b4b0d3255bfef95601890afd80709"
    $a5="92005ecf3788faea8346a7919fba0232188561ab"
    $a6="b780d252a12c8c472099c589d729a6d60a27dc7b"
    $a7="b780d252a12c8c472099c589d729a6d60a27dc7b"
    $a8="1ad692285750b58b6d8e1b3acdfb649874b6ba50"
    $a9="92005ecf3788faea8346a7919fba0232188561ab"
    $a10="3aa24562e5ddbc02f7354d04ce68e0983ca1ef7b"
    $a11="3aa24562e5ddbc02f7354d04ce68e0983ca1ef7b"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11)
}

rule sha384_hashed_default_creds_ericsson
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for ericsson. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="9ca694a90285c034432c9550421b7b9dbd5c0f4b6673f05f6dbce58052ba20e4248041956ee8c9a2ec9f10290cdc0782"
    $a1="42f7113044c011e770740189f408d58fa50b795bd67a83a5dffe7b31a6463841de17df777ecbd9666ebb69e3a5be7d32"
    $a2="38b060a751ac96384cd9327eb1b1e36a21fdb71114be07434c0cc7bf63f6e1da274edebfe76f65fbd51ad2f14898b95b"
    $a3="38b060a751ac96384cd9327eb1b1e36a21fdb71114be07434c0cc7bf63f6e1da274edebfe76f65fbd51ad2f14898b95b"
    $a4="38b060a751ac96384cd9327eb1b1e36a21fdb71114be07434c0cc7bf63f6e1da274edebfe76f65fbd51ad2f14898b95b"
    $a5="1e363b70c602295e1f204dadd818dd5f0706b6a5e6a47372f255ed6369a94962396774c254e720b007df320049e1ba9e"
    $a6="e261dcccc9be0ef2af5803709466bd985ae371bc9b22fa5aad80f51a80bc627edc259ff738a025e9ac933681667a6529"
    $a7="e261dcccc9be0ef2af5803709466bd985ae371bc9b22fa5aad80f51a80bc627edc259ff738a025e9ac933681667a6529"
    $a8="a8b4ba4b574d2d02119efe4adecb700911fa1e7a3c9e24b38c5495635a54d7fc92a1391b25caf622e6feb22fd2c1b932"
    $a9="1e363b70c602295e1f204dadd818dd5f0706b6a5e6a47372f255ed6369a94962396774c254e720b007df320049e1ba9e"
    $a10="f89feea53b3d49c93be9bba04242fa183701f8dc45a96978254f1afead273efeb73c2acab0fdac339c281731894b2221"
    $a11="f89feea53b3d49c93be9bba04242fa183701f8dc45a96978254f1afead273efeb73c2acab0fdac339c281731894b2221"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11)
}

rule sha224_hashed_default_creds_ericsson
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for ericsson. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="58acb7acccce58ffa8b953b12b5a7702bd42dae441c1ad85057fa70b"
    $a1="f0e8b3c2dda2512b55e4dc5d4859b1877e98109c7c4e755ccd2a5763"
    $a2="d14a028c2a3a2bc9476102bb288234c415a2b01f828ea62ac5b3e42f"
    $a3="d14a028c2a3a2bc9476102bb288234c415a2b01f828ea62ac5b3e42f"
    $a4="d14a028c2a3a2bc9476102bb288234c415a2b01f828ea62ac5b3e42f"
    $a5="e9a17768d48637bcee3b5ce3ed21ccdb2c39c5d9b089444908208b2e"
    $a6="e9e648bddc054e8643beb7194d056d9ff74dfabc2ec32376b8ba615a"
    $a7="e9e648bddc054e8643beb7194d056d9ff74dfabc2ec32376b8ba615a"
    $a8="6cb0e3de5bf9bf402fd61c59da949ea0eb90e08c24c5da49878ffe43"
    $a9="e9a17768d48637bcee3b5ce3ed21ccdb2c39c5d9b089444908208b2e"
    $a10="ffa2a1b27f9a7b2bccec3d0efc2b0bf25c178be55fb8b3fd93c8d77c"
    $a11="ffa2a1b27f9a7b2bccec3d0efc2b0bf25c178be55fb8b3fd93c8d77c"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11)
}

rule sha512_hashed_default_creds_ericsson
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for ericsson. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="c7ad44cbad762a5da0a452f9e854fdc1e0e7a52a38015f23f3eab1d80b931dd472634dfac71cd34ebc35d16ab7fb8a90c81f975113d6c7538dc69dd8de9077ec"
    $a1="1625cdb75d25d9f699fd2779f44095b6e320767f606f095eb7edab5581e9e3441adbb0d628832f7dc4574a77a382973ce22911b7e4df2a9d2c693826bbd125bc"
    $a2="cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e"
    $a3="cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e"
    $a4="cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e"
    $a5="5766d45bdba1152105abfd9662e551401a9756f1a37b3a3669ac590390479e9220591027098d61eff70ed6d0314d2cac7128f488df052ed7318ead76ba5f2f7b"
    $a6="585d09bbd0230435c6600fbc2f9858c6878b183b024f459c5e11f389106e835528423846ee0cfeab5ee870288bae56f2ff052a7942ddcb2ebfcb91e6664ac2bf"
    $a7="585d09bbd0230435c6600fbc2f9858c6878b183b024f459c5e11f389106e835528423846ee0cfeab5ee870288bae56f2ff052a7942ddcb2ebfcb91e6664ac2bf"
    $a8="4fd54a51b6680ee7cf925e084aa10576a46213cda660c2367898b31f545b2fb24b69dc7c4c7fc252d75a333e57a1432878641ff6ea0b8b0547cae85779a34e0e"
    $a9="5766d45bdba1152105abfd9662e551401a9756f1a37b3a3669ac590390479e9220591027098d61eff70ed6d0314d2cac7128f488df052ed7318ead76ba5f2f7b"
    $a10="9776ff6e746cc815066e024ad18130c1b9acf5d45c9afedabd831c0656a7011a103e2d9d659747456e62b6098205eed4cee616cb57122cf8a9e5eeee07d63fe8"
    $a11="9776ff6e746cc815066e024ad18130c1b9acf5d45c9afedabd831c0656a7011a103e2d9d659747456e62b6098205eed4cee616cb57122cf8a9e5eeee07d63fe8"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11)
}

rule sha256_hashed_default_creds_ericsson
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for ericsson. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="8c6976e5b5410415bde908bd4dee15dfb167a9c873fc4bb8a81f6f2ab448a918"
    $a1="37a8eec1ce19687d132fe29051dca629d164e2c4958ba141d5f4133a33f0688f"
    $a2="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    $a3="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    $a4="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    $a5="106a5842fc5fce6f663176285ed1516dbb1e3d15c05abab12fdca46d60b539b7"
    $a6="c7d253870ab8de3825e3a9b5ee603e21abd0dfe62763e8e2fc1fc9f4684e8a19"
    $a7="c7d253870ab8de3825e3a9b5ee603e21abd0dfe62763e8e2fc1fc9f4684e8a19"
    $a8="2afbb1b55c6a2417ea3a1294bb7436009df69b1c112a6d06d381bda807ee05ff"
    $a9="106a5842fc5fce6f663176285ed1516dbb1e3d15c05abab12fdca46d60b539b7"
    $a10="7f56e488201f458dcf845761b65ab0109015b569b5a5ac7809d6a2a9a0b62626"
    $a11="7f56e488201f458dcf845761b65ab0109015b569b5a5ac7809d6a2a9a0b62626"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11)
}

rule blake2b_hashed_default_creds_ericsson
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for ericsson. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="bfcce2c19c8563fd4aa66f6ec607341ff25e5f6fe7fa520d7d1242d871385f23a3e8e80093120b4877d79535e10b182ae2ec8937d1f72f091e7178c9e4ff0f11"
    $a1="6a3712e2b92f69ead391b691710a587f21fae1e7b83b94b7835344eed1c463cfe03816e61922646f7aa0b581f3ba35842b12e556b2e4e0644c0f1d1d0549a79f"
    $a2="786a02f742015903c6c6fd852552d272912f4740e15847618a86e217f71f5419d25e1031afee585313896444934eb04b903a685b1448b755d56f701afe9be2ce"
    $a3="786a02f742015903c6c6fd852552d272912f4740e15847618a86e217f71f5419d25e1031afee585313896444934eb04b903a685b1448b755d56f701afe9be2ce"
    $a4="786a02f742015903c6c6fd852552d272912f4740e15847618a86e217f71f5419d25e1031afee585313896444934eb04b903a685b1448b755d56f701afe9be2ce"
    $a5="81f783b70f8bf5cb39bafba79d696a6dc531475f6ae1b8bb819f380c852b4a776db1cb84b217c41bfd844dce41cfb790e31a4b6e12a7c12b6efb5b29eddded62"
    $a6="e4fe8c2f97a24e355e600db1e13520c09c323ea214f544ff6f0f4023ebbcdd89c91740519f756c64ba094bb108b1d65183e34e24b585496c355f3aaa74574edc"
    $a7="e4fe8c2f97a24e355e600db1e13520c09c323ea214f544ff6f0f4023ebbcdd89c91740519f756c64ba094bb108b1d65183e34e24b585496c355f3aaa74574edc"
    $a8="87480ee4a7f233177b6100e39313a05bab24bb1f8e55dc238435f0552f8df680b2e1ddbc3c02c25666cb024e710effbabdd48497842e0cf8f43127484b88e1f8"
    $a9="81f783b70f8bf5cb39bafba79d696a6dc531475f6ae1b8bb819f380c852b4a776db1cb84b217c41bfd844dce41cfb790e31a4b6e12a7c12b6efb5b29eddded62"
    $a10="86dcb3b0f95abbda4b831c34271eee87f75b1ed628464796dfdca8c18edc44234119b734689182664206e4e34f1ed5483bb4a4c34cb3c7a8de709fef04cd26f0"
    $a11="86dcb3b0f95abbda4b831c34271eee87f75b1ed628464796dfdca8c18edc44234119b734689182664206e4e34f1ed5483bb4a4c34cb3c7a8de709fef04cd26f0"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11)
}

rule blake2s_hashed_default_creds_ericsson
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for ericsson. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="327e7e3821f5f6d33c090137f979bf48ee62e9051c1610e1d6468ecb3c67a124"
    $a1="4f38de7eea698e71df046d36abca9a5d7ce3f82f829f4b8c0f54a6334209985a"
    $a2="69217a3079908094e11121d042354a7c1f55b6482ca1a51e1b250dfd1ed0eef9"
    $a3="69217a3079908094e11121d042354a7c1f55b6482ca1a51e1b250dfd1ed0eef9"
    $a4="69217a3079908094e11121d042354a7c1f55b6482ca1a51e1b250dfd1ed0eef9"
    $a5="0b1eec1552ff1189863e2932eb76a3c3695836c36aaed8301037d8c79fdc8c03"
    $a6="143b7b8209303b61211c12812a171db7a9934b8a81066e3d8d6e3f7e50010ec0"
    $a7="143b7b8209303b61211c12812a171db7a9934b8a81066e3d8d6e3f7e50010ec0"
    $a8="8bd297185dc82427927739076bd1a19f6bc9d8a447f53813fb6e82bfaa53b65b"
    $a9="0b1eec1552ff1189863e2932eb76a3c3695836c36aaed8301037d8c79fdc8c03"
    $a10="c683866c00dc2ad95260337ef2b6c46b96f548fdbe2a59936535a7cb647ebd3e"
    $a11="c683866c00dc2ad95260337ef2b6c46b96f548fdbe2a59936535a7cb647ebd3e"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11)
}

rule sha3_224_hashed_default_creds_ericsson
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for ericsson. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="a53fff8dd075bed169e164743231ff533d8b9260b0b8073f0a4c1d20"
    $a1="56a9602a1d3111b4a5c6c78e6210e0d431718b1a99315e78e232c27c"
    $a2="6b4e03423667dbb73b6e15454f0eb1abd4597f9a1b078e3f5b5a6bc7"
    $a3="6b4e03423667dbb73b6e15454f0eb1abd4597f9a1b078e3f5b5a6bc7"
    $a4="6b4e03423667dbb73b6e15454f0eb1abd4597f9a1b078e3f5b5a6bc7"
    $a5="0b1efbd8a699a51ffe71726a2742d0b40d5c11855dbcaae37f5c104b"
    $a6="f31ce4fb1e19793e94550cf556862f9fa446dbfcc835db2b461f0026"
    $a7="f31ce4fb1e19793e94550cf556862f9fa446dbfcc835db2b461f0026"
    $a8="4de781bd81b0af5224b5f55613c4b309b479bbcd6318f6fdbbaa3457"
    $a9="0b1efbd8a699a51ffe71726a2742d0b40d5c11855dbcaae37f5c104b"
    $a10="43de4e176bbd06c3f84e8ffa24abc2b9ccf619eec3f278b3aa85be77"
    $a11="43de4e176bbd06c3f84e8ffa24abc2b9ccf619eec3f278b3aa85be77"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11)
}

rule sha3_256_hashed_default_creds_ericsson
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for ericsson. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="fb001dfcffd1c899f3297871406242f097aecf1a5342ccf3ebcd116146188e4b"
    $a1="2747cabbb481a433679f6dc8aae833dd1b64452778b97e2729bd3c54dede0886"
    $a2="a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a"
    $a3="a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a"
    $a4="a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a"
    $a5="1782ca260b116c2360821078875e766e03ba1cdb547381416e2fabe1c495804b"
    $a6="c09d48b3d5671f93f6bbe8bb21f15e52ab4e3cd035574200694c965b64f75998"
    $a7="c09d48b3d5671f93f6bbe8bb21f15e52ab4e3cd035574200694c965b64f75998"
    $a8="5e6196ecb5f28fa44aaf3d2fb0fbc1fdd0c6cd303603bdbb5abfa3e34a9755a5"
    $a9="1782ca260b116c2360821078875e766e03ba1cdb547381416e2fabe1c495804b"
    $a10="4d235e963851a33d292c78aeee20bb9c80f4be6ee31b2e38fd8f77297e30bf13"
    $a11="4d235e963851a33d292c78aeee20bb9c80f4be6ee31b2e38fd8f77297e30bf13"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11)
}

rule sha3_384_hashed_default_creds_ericsson
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for ericsson. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="9765a57f2010506383de91052915ce8bafbdb39f3e5a8c1a1693a0076365d37abbfd3305881ea3b5fa1426316afd7df3"
    $a1="f437f71603b12fec1a4c1cdf46af48d0274fc3da86d451c00285697137cd82fb803b543f025e4d4549eb5efb514643c8"
    $a2="0c63a75b845e4f7d01107d852e4c2485c51a50aaaa94fc61995e71bbee983a2ac3713831264adb47fb6bd1e058d5f004"
    $a3="0c63a75b845e4f7d01107d852e4c2485c51a50aaaa94fc61995e71bbee983a2ac3713831264adb47fb6bd1e058d5f004"
    $a4="0c63a75b845e4f7d01107d852e4c2485c51a50aaaa94fc61995e71bbee983a2ac3713831264adb47fb6bd1e058d5f004"
    $a5="fbee00eab192ea52017accdefa65aa541c49bf1e5133d8ddea9f185e14cb17fe3ce3f725360a6a24b69fc6242f5073bd"
    $a6="28066f4563d83e69c2809650f859ca2c6a97b97de635afda527e62ed8660201c6a3c3acd07505bf151da7402896ca1ff"
    $a7="28066f4563d83e69c2809650f859ca2c6a97b97de635afda527e62ed8660201c6a3c3acd07505bf151da7402896ca1ff"
    $a8="e758cd128de8a0266eb9460c1a91f2046c454c37e47153a5b4f2d8717d287cf907890d82983817b7166ae4cd14ea014e"
    $a9="fbee00eab192ea52017accdefa65aa541c49bf1e5133d8ddea9f185e14cb17fe3ce3f725360a6a24b69fc6242f5073bd"
    $a10="68c89b100df772d7806b9982b14678f8ca83f8ff0e17a6f95ab3bf3274564afad4fdb1378c80a48aeecb8131fbe89a24"
    $a11="68c89b100df772d7806b9982b14678f8ca83f8ff0e17a6f95ab3bf3274564afad4fdb1378c80a48aeecb8131fbe89a24"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11)
}

rule sha3_512_hashed_default_creds_ericsson
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for ericsson. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="5a38afb1a18d408e6cd367f9db91e2ab9bce834cdad3da24183cc174956c20ce35dd39c2bd36aae907111ae3d6ada353f7697a5f1a8fc567aae9e4ca41a9d19d"
    $a1="fbaf1d3516e4849991e8eaa16e401a9d0cebad944297cd80022f9424c8d9d172f7cc94844f529cca51005498f56ca90672ca918cbbfc06c0071b9c12b98f89b6"
    $a2="a69f73cca23a9ac5c8b567dc185a756e97c982164fe25859e0d1dcc1475c80a615b2123af1f5f94c11e3e9402c3ac558f500199d95b6d3e301758586281dcd26"
    $a3="a69f73cca23a9ac5c8b567dc185a756e97c982164fe25859e0d1dcc1475c80a615b2123af1f5f94c11e3e9402c3ac558f500199d95b6d3e301758586281dcd26"
    $a4="a69f73cca23a9ac5c8b567dc185a756e97c982164fe25859e0d1dcc1475c80a615b2123af1f5f94c11e3e9402c3ac558f500199d95b6d3e301758586281dcd26"
    $a5="dc2f4dabb854477fbedc841fa433e732db9309922075259d549ddcaa8df2c9421d55d154ebe9c3e65325a8524b7a823726da1d3020ae7477b30c787b707e8d31"
    $a6="5494b9ad0be108474a6dc8a92354ed94b0cf51c7092a28c7a201eaf94891d437a8638bba468c1b0ff625aa9b9e1415aed0943ce8c7be29a24511166b4a1dcec4"
    $a7="5494b9ad0be108474a6dc8a92354ed94b0cf51c7092a28c7a201eaf94891d437a8638bba468c1b0ff625aa9b9e1415aed0943ce8c7be29a24511166b4a1dcec4"
    $a8="65d69364a975c0a17dc28ac55ab29d2cc0b4cf0f013a993bcd9cfebffe3248077bc373763cf5de0a0467033f5a2e9da465e6792349abad8b20790708ef1298b9"
    $a9="dc2f4dabb854477fbedc841fa433e732db9309922075259d549ddcaa8df2c9421d55d154ebe9c3e65325a8524b7a823726da1d3020ae7477b30c787b707e8d31"
    $a10="f96b8c19c3e7f114833925bce79968bd9e75b8f15f3a6cd3858ceae6a97105fa0a22911ba45b9ab8cf840b447848e447a40c65a6b39457b979172633572b1ea0"
    $a11="f96b8c19c3e7f114833925bce79968bd9e75b8f15f3a6cd3858ceae6a97105fa0a22911ba45b9ab8cf840b447848e447a40c65a6b39457b979172633572b1ea0"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11)
}

rule base64_hashed_default_creds_ericsson
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for ericsson. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="YWRtaW4="
    $a1="ZGVmYXVsdA=="
    $a2="===="
    $a3="===="
    $a4="===="
    $a5="aGVscA=="
    $a6="ZXhwZXJ0"
    $a7="ZXhwZXJ0"
    $a8="TUQxMTA="
    $a9="aGVscA=="
    $a10="bmV0bWFu"
    $a11="bmV0bWFu"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11)
}

