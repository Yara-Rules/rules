/*This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as long as you use it under this license.*/

rule md5_hashed_default_creds_xylan
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for xylan. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="21232f297a57a5a743894a0e4a801fc3"
    $a1="b36eb6a54154f7301f004e1e61c87ce8"
    $a2="776e6c3d14fd9df9fc13e130d598c448"
    $a3="b36eb6a54154f7301f004e1e61c87ce8"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule sha1_hashed_default_creds_xylan
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for xylan. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="d033e22ae348aeb5660fc2140aec35850c4da997"
    $a1="01ba7992f85de477e8e630428eb5ed14769f9155"
    $a2="529a2169843d649acaf9b41df60db6d69af1e991"
    $a3="01ba7992f85de477e8e630428eb5ed14769f9155"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule sha384_hashed_default_creds_xylan
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for xylan. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="9ca694a90285c034432c9550421b7b9dbd5c0f4b6673f05f6dbce58052ba20e4248041956ee8c9a2ec9f10290cdc0782"
    $a1="d1e417c541712287a7ab93ec354f0146d8312ee6378b38f92147cca61c2ed0bab1ce98541c1fa52fd9f2e25bdf89a1c8"
    $a2="5493a250d3ff9a2a54132a51ec6ab26d32b8b08da3763a1c94045602e2c2acbb14a8d0a4de99ca04645fc5f2a4ff56dd"
    $a3="d1e417c541712287a7ab93ec354f0146d8312ee6378b38f92147cca61c2ed0bab1ce98541c1fa52fd9f2e25bdf89a1c8"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule sha224_hashed_default_creds_xylan
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for xylan. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="58acb7acccce58ffa8b953b12b5a7702bd42dae441c1ad85057fa70b"
    $a1="e22118ed1e9982ac90b2939302bd3c29cef5c5ff5dd462a8405f6e8c"
    $a2="a8746091df3beae80988240b06d21e69466041008e55fd2acf77b770"
    $a3="e22118ed1e9982ac90b2939302bd3c29cef5c5ff5dd462a8405f6e8c"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule sha512_hashed_default_creds_xylan
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for xylan. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="c7ad44cbad762a5da0a452f9e854fdc1e0e7a52a38015f23f3eab1d80b931dd472634dfac71cd34ebc35d16ab7fb8a90c81f975113d6c7538dc69dd8de9077ec"
    $a1="c884a2849503efabb12c984ba4ffaed6a99ba3b24cfc647b63d4f4194a20373f10aa31d9571df9fe56a40fc49548a5033471ad5123b68bf6b2aaf53c125af4a9"
    $a2="ef05b6eae39eb51b5b8ca1c3ccc85ec4975fffe99ae816d1f8f78eb25bbc3eafc0de8fb8589a9f92cea310d5703df0e4ce5cb20ee51df40c1a1f5caadac1ffb3"
    $a3="c884a2849503efabb12c984ba4ffaed6a99ba3b24cfc647b63d4f4194a20373f10aa31d9571df9fe56a40fc49548a5033471ad5123b68bf6b2aaf53c125af4a9"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule sha256_hashed_default_creds_xylan
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for xylan. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="8c6976e5b5410415bde908bd4dee15dfb167a9c873fc4bb8a81f6f2ab448a918"
    $a1="78b49fb2cc2d2ed6c1bb8383b3d267b3bc623a8a0fb4aff4aa5d3db74c3b4967"
    $a2="be3f1b44776624b9c37b661e9711ac1d8f51628b80c33e3b60b6a56fea088c9b"
    $a3="78b49fb2cc2d2ed6c1bb8383b3d267b3bc623a8a0fb4aff4aa5d3db74c3b4967"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule blake2b_hashed_default_creds_xylan
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for xylan. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="bfcce2c19c8563fd4aa66f6ec607341ff25e5f6fe7fa520d7d1242d871385f23a3e8e80093120b4877d79535e10b182ae2ec8937d1f72f091e7178c9e4ff0f11"
    $a1="5d37c38d3a94242aa79b946556981480323fd757dbb086703d845e60e10078ba1ae3fc43bda86fa90c25aa416c9fb61eb1c5e01581a6fd7fcdbd02d8abfe9aa5"
    $a2="71746a5fb22fd342acf186d243652375a1d127d637e54150a6ca5798a2d5c6b1abd24f21e7e261e4e97b999fc52e72c8fd23e5afc95fc74121bc48d2742145ba"
    $a3="5d37c38d3a94242aa79b946556981480323fd757dbb086703d845e60e10078ba1ae3fc43bda86fa90c25aa416c9fb61eb1c5e01581a6fd7fcdbd02d8abfe9aa5"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule blake2s_hashed_default_creds_xylan
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for xylan. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="327e7e3821f5f6d33c090137f979bf48ee62e9051c1610e1d6468ecb3c67a124"
    $a1="2c96f501eb50f9bd0a37146a68964daf02a4daa903fa7e390cfe84c07446dc80"
    $a2="3ce461e8f901e67371da46cfaee864e3f56e47ff4ae205cc502ce19a8b8ff9c1"
    $a3="2c96f501eb50f9bd0a37146a68964daf02a4daa903fa7e390cfe84c07446dc80"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule sha3_224_hashed_default_creds_xylan
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for xylan. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="a53fff8dd075bed169e164743231ff533d8b9260b0b8073f0a4c1d20"
    $a1="370e8b1251bb73d7e8f596230443929972694327707344245ce287f1"
    $a2="ce979e97df0c952848e02a59d8f6b16850a3ce1320071d9458ea8ed0"
    $a3="370e8b1251bb73d7e8f596230443929972694327707344245ce287f1"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule sha3_256_hashed_default_creds_xylan
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for xylan. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="fb001dfcffd1c899f3297871406242f097aecf1a5342ccf3ebcd116146188e4b"
    $a1="20fa9c8dcc6b58031532bc56585ffdc3718ff844722bdfa37bc6ad76957aaafd"
    $a2="add19367953daf9688b7ac2d1fb3cf80e8f158fafa8e7f11f512dd5845578078"
    $a3="20fa9c8dcc6b58031532bc56585ffdc3718ff844722bdfa37bc6ad76957aaafd"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule sha3_384_hashed_default_creds_xylan
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for xylan. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="9765a57f2010506383de91052915ce8bafbdb39f3e5a8c1a1693a0076365d37abbfd3305881ea3b5fa1426316afd7df3"
    $a1="d245abad420995115064295eb5e440e3eae238d75065c3c1efed264118e66c4c4bcd15e3e8f37fe14ac99709e7d6938f"
    $a2="7810f88c4a73bafa6d9bd91bc670d086413e8c3a4c225c314d81d2059a5c56debe060b612a733b99eda38ed75c73716b"
    $a3="d245abad420995115064295eb5e440e3eae238d75065c3c1efed264118e66c4c4bcd15e3e8f37fe14ac99709e7d6938f"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule sha3_512_hashed_default_creds_xylan
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for xylan. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="5a38afb1a18d408e6cd367f9db91e2ab9bce834cdad3da24183cc174956c20ce35dd39c2bd36aae907111ae3d6ada353f7697a5f1a8fc567aae9e4ca41a9d19d"
    $a1="82d6d00febc1e0af849cc06ff5919fd9c980b94fc352d37741c348621be1331c716f6a4dd26b471b7497e67d5888544146cf31cd23b8305f55ecbc4b14540f43"
    $a2="68d744c2fe5664432c594b937d4d920cf215cb39477be66c67a15b8720af33cec3d2ccc321230896a2655d8131f5dcafbf0afbc0e59edfb56a6adf174c4e3c80"
    $a3="82d6d00febc1e0af849cc06ff5919fd9c980b94fc352d37741c348621be1331c716f6a4dd26b471b7497e67d5888544146cf31cd23b8305f55ecbc4b14540f43"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule base64_hashed_default_creds_xylan
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for xylan. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="YWRtaW4="
    $a1="c3dpdGNo"
    $a2="ZGlhZw=="
    $a3="c3dpdGNo"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

