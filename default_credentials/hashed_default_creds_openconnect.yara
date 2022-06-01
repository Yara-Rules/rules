/*This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as long as you use it under this license.*/

rule md5_hashed_default_creds_openconnect
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for openconnect. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="21232f297a57a5a743894a0e4a801fc3"
    $a1="48d18c2f9253969469c99afae38b7b9c"
    $a2="18de90c6da59e445d71eef6ab461cab2"
    $a3="48d18c2f9253969469c99afae38b7b9c"
    $a4="4f5cec75c744bd39b5126debbb7cffb8"
    $a5="48d18c2f9253969469c99afae38b7b9c"
    $a6="a18b52134bf979a780f84eac70578f9e"
    $a7="48d18c2f9253969469c99afae38b7b9c"
    $a8="288682ec5f2450588bb37a4523d11616"
    $a9="48d18c2f9253969469c99afae38b7b9c"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9)
}

rule sha1_hashed_default_creds_openconnect
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for openconnect. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="d033e22ae348aeb5660fc2140aec35850c4da997"
    $a1="9c7c944ba8e134bc69a910180d62952c99050f8f"
    $a2="01c8267a0c30f7796fc2ee0a35aec585ace242e8"
    $a3="9c7c944ba8e134bc69a910180d62952c99050f8f"
    $a4="6f372c90822f7de721f3e6edc42653a746e81d90"
    $a5="9c7c944ba8e134bc69a910180d62952c99050f8f"
    $a6="0e0a61c867616eef145bca3653bbd02406032dc1"
    $a7="9c7c944ba8e134bc69a910180d62952c99050f8f"
    $a8="875a8f2f42c570f5f4ea7bfd154f582bcf95673a"
    $a9="9c7c944ba8e134bc69a910180d62952c99050f8f"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9)
}

rule sha384_hashed_default_creds_openconnect
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for openconnect. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="9ca694a90285c034432c9550421b7b9dbd5c0f4b6673f05f6dbce58052ba20e4248041956ee8c9a2ec9f10290cdc0782"
    $a1="007ac647d19f81bbd8b82e851a6e888587598792256c2e011f5b4a498d6bd3d60164aaa31d4462dab6c38fb9f8f424a7"
    $a2="0ff64f996d8a96a38eb1b6517c1b589c5828de0aedee8c3a5f88be0be123f2444decd406693afefc6f004212be4c5013"
    $a3="007ac647d19f81bbd8b82e851a6e888587598792256c2e011f5b4a498d6bd3d60164aaa31d4462dab6c38fb9f8f424a7"
    $a4="431b73020c73a6b38313f9f5624cf71fa4ee55f20773c892ffcc3655a952fcaed2a17b07098af4d13b64b1f88e7005f1"
    $a5="007ac647d19f81bbd8b82e851a6e888587598792256c2e011f5b4a498d6bd3d60164aaa31d4462dab6c38fb9f8f424a7"
    $a6="62c2678811252ad18f03bf17e8da50d004cb340700bf2bd04ee81629a0ce31f8542a0287f8dcef19f782d7106872d7c3"
    $a7="007ac647d19f81bbd8b82e851a6e888587598792256c2e011f5b4a498d6bd3d60164aaa31d4462dab6c38fb9f8f424a7"
    $a8="4e807e812394357ed9e0aeb1ea7094f09d1acb0fc095294ebeadceb294c2a2952b802521c935e70fbd32d52818c6d452"
    $a9="007ac647d19f81bbd8b82e851a6e888587598792256c2e011f5b4a498d6bd3d60164aaa31d4462dab6c38fb9f8f424a7"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9)
}

rule sha224_hashed_default_creds_openconnect
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for openconnect. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="58acb7acccce58ffa8b953b12b5a7702bd42dae441c1ad85057fa70b"
    $a1="894f442e8ec6ce833d956b04e4ab3ffd521cf15356077e7fdf7ee8b9"
    $a2="6fbb735206b638f03a9f5c1a5b4c9ff9afdf4e76450b024b316290e2"
    $a3="894f442e8ec6ce833d956b04e4ab3ffd521cf15356077e7fdf7ee8b9"
    $a4="ef5210eca043e9e7e9c9c739d467f87351b7c62a502d8fe97f8d9f41"
    $a5="894f442e8ec6ce833d956b04e4ab3ffd521cf15356077e7fdf7ee8b9"
    $a6="e377f76fc20600fdc9bf2f5b5d0a93b35ad292462a043f4b4ec691b6"
    $a7="894f442e8ec6ce833d956b04e4ab3ffd521cf15356077e7fdf7ee8b9"
    $a8="49d4e84d5e9b335410f4510afd91b8f9e824ed4d6bd9de1f0887fc07"
    $a9="894f442e8ec6ce833d956b04e4ab3ffd521cf15356077e7fdf7ee8b9"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9)
}

rule sha512_hashed_default_creds_openconnect
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for openconnect. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="c7ad44cbad762a5da0a452f9e854fdc1e0e7a52a38015f23f3eab1d80b931dd472634dfac71cd34ebc35d16ab7fb8a90c81f975113d6c7538dc69dd8de9077ec"
    $a1="84c0a44a2699e851517bcfd6dbe85eaf1fffaae8554a2ba6c18e64713e7ea22899fe1f9ed4c163569b9ed7942af1bf94d225b2048dfc0c84d1eb6261268979ec"
    $a2="9229ac15237b0bc3bef9683db7096555c455cf50fc76671a057aedb4518f5ff9c5c831e43cda54a17b68bddb15b39006f91ee1ff8e2593eb2904c11401e0af51"
    $a3="84c0a44a2699e851517bcfd6dbe85eaf1fffaae8554a2ba6c18e64713e7ea22899fe1f9ed4c163569b9ed7942af1bf94d225b2048dfc0c84d1eb6261268979ec"
    $a4="8eb3aef537d38daf8714dc53a3fedaa3bc5263303f8f4841d4b0308d38939ce3b4169c1a26fbb686e5734cbf6681ccc73829ebafc603cd9083bb1513409ba9fd"
    $a5="84c0a44a2699e851517bcfd6dbe85eaf1fffaae8554a2ba6c18e64713e7ea22899fe1f9ed4c163569b9ed7942af1bf94d225b2048dfc0c84d1eb6261268979ec"
    $a6="49385d39f875d7b24b2e0fbb8ada43c9213afa476b4307a18b734d97656168b0a6a85c9ba48ab825ac90405f60cd5fd67cb91625c8c3efbe1d2ab70deacf0823"
    $a7="84c0a44a2699e851517bcfd6dbe85eaf1fffaae8554a2ba6c18e64713e7ea22899fe1f9ed4c163569b9ed7942af1bf94d225b2048dfc0c84d1eb6261268979ec"
    $a8="c429443a06764c82d4f2aabe79af3ce68b909a636e2065de0b337b4ea558350e96dd0b9a60322004ee86ccd691aad7f6467cd71e0f9044e71ca684e797d5a788"
    $a9="84c0a44a2699e851517bcfd6dbe85eaf1fffaae8554a2ba6c18e64713e7ea22899fe1f9ed4c163569b9ed7942af1bf94d225b2048dfc0c84d1eb6261268979ec"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9)
}

rule sha256_hashed_default_creds_openconnect
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for openconnect. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="8c6976e5b5410415bde908bd4dee15dfb167a9c873fc4bb8a81f6f2ab448a918"
    $a1="9fa444ae546c12aa74b68494378a1e4d08e1674afe0b549cce538f8af36a3e0d"
    $a2="378aa3b3beecc8cd5718f7cec8c60b9bb3042165199648b94e4378c32aa60c89"
    $a3="9fa444ae546c12aa74b68494378a1e4d08e1674afe0b549cce538f8af36a3e0d"
    $a4="061a1c0ea20e6b5d90ace3c0d879304b52c751ef53e62ccf159e1fb21d954c2f"
    $a5="9fa444ae546c12aa74b68494378a1e4d08e1674afe0b549cce538f8af36a3e0d"
    $a6="8bd82fac9d64437eef946dbcec0c0dce185aca62f0f239b5f9a81eb7f53f3eab"
    $a7="9fa444ae546c12aa74b68494378a1e4d08e1674afe0b549cce538f8af36a3e0d"
    $a8="9f4d10730006eef4bf802559e1f26a254ad4eb11b8d0eff66ace8ffb4d1c12bb"
    $a9="9fa444ae546c12aa74b68494378a1e4d08e1674afe0b549cce538f8af36a3e0d"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9)
}

rule blake2b_hashed_default_creds_openconnect
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for openconnect. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="bfcce2c19c8563fd4aa66f6ec607341ff25e5f6fe7fa520d7d1242d871385f23a3e8e80093120b4877d79535e10b182ae2ec8937d1f72f091e7178c9e4ff0f11"
    $a1="46c1415ed84d84d02c5a07dd8c674a5ddbf258c3aa8705101f8225e74c605713cbe732c6614188b7e9eb581e740ed76cb47566a1c3628c1276b1e908f393268b"
    $a2="4c91adb357eb774fb98827c5194cfdc456fc42c7616e0a08c5b4e31d801dd3ca641db4165460fcac54c32831112a0fe601691bbc12212df90cde2be954c9c707"
    $a3="46c1415ed84d84d02c5a07dd8c674a5ddbf258c3aa8705101f8225e74c605713cbe732c6614188b7e9eb581e740ed76cb47566a1c3628c1276b1e908f393268b"
    $a4="4b4efdf6002f8cf809bbc9452d8f0790262866164350ff0bf7bb57786c5378172fdf7d740554abc678998a82f45033c76d9eba7253106f9f527670854e6670ab"
    $a5="46c1415ed84d84d02c5a07dd8c674a5ddbf258c3aa8705101f8225e74c605713cbe732c6614188b7e9eb581e740ed76cb47566a1c3628c1276b1e908f393268b"
    $a6="4a30f07d4ff6efdb38e93ae369bafd005d1dc745c72ca901d58bd6aba1487bba4264126cd52ddc50537403e562f5b82cc20d8793a93c0ef0976c2b7da07e3a12"
    $a7="46c1415ed84d84d02c5a07dd8c674a5ddbf258c3aa8705101f8225e74c605713cbe732c6614188b7e9eb581e740ed76cb47566a1c3628c1276b1e908f393268b"
    $a8="6f6426bae1da8bd45b1bca5a1feb777caa3fcbd1939774739a639b28f6a56dd649a908da4e60145cb00516c320448a9314f8b617cebc4cff1a4620751021edd5"
    $a9="46c1415ed84d84d02c5a07dd8c674a5ddbf258c3aa8705101f8225e74c605713cbe732c6614188b7e9eb581e740ed76cb47566a1c3628c1276b1e908f393268b"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9)
}

rule blake2s_hashed_default_creds_openconnect
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for openconnect. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="327e7e3821f5f6d33c090137f979bf48ee62e9051c1610e1d6468ecb3c67a124"
    $a1="8f0c8099d665b831109e78fc4a0364e34d2fe634eaa1e832b29c8af7c24af73a"
    $a2="79e288aabff890a4eed9e879e9ceeca4dc704506bf7c17318defd9eaf98203bd"
    $a3="8f0c8099d665b831109e78fc4a0364e34d2fe634eaa1e832b29c8af7c24af73a"
    $a4="5b05808a9f43dc381814a59e5f9fe7d1ea654f0dd6ae73cebeb1bfab23b3fbaa"
    $a5="8f0c8099d665b831109e78fc4a0364e34d2fe634eaa1e832b29c8af7c24af73a"
    $a6="01aa412fae479c699ebd7dd2f4e9544dd444a089e053a54edbd21752b41762e3"
    $a7="8f0c8099d665b831109e78fc4a0364e34d2fe634eaa1e832b29c8af7c24af73a"
    $a8="8c0d7ae26386f2ac954ba3d826f9fbe7cba826c139c7cbb80f46be7fa694a03a"
    $a9="8f0c8099d665b831109e78fc4a0364e34d2fe634eaa1e832b29c8af7c24af73a"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9)
}

rule sha3_224_hashed_default_creds_openconnect
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for openconnect. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="a53fff8dd075bed169e164743231ff533d8b9260b0b8073f0a4c1d20"
    $a1="cafc7b1bce7fad90c07fb9e2fc3d44a4dc479b7d9177be07988ed776"
    $a2="5413432a9c301397e5b5ddb212b7b413a4c97f48c0dafb32a0e8e166"
    $a3="cafc7b1bce7fad90c07fb9e2fc3d44a4dc479b7d9177be07988ed776"
    $a4="9f4cd298b8d6a29d017fd5990c22c328c5470eaa887fc1d8bbb65d1d"
    $a5="cafc7b1bce7fad90c07fb9e2fc3d44a4dc479b7d9177be07988ed776"
    $a6="f6686c0af609bade2b79d70747f7ffb4aadc77c08d48fe292c28585f"
    $a7="cafc7b1bce7fad90c07fb9e2fc3d44a4dc479b7d9177be07988ed776"
    $a8="9df3cc4f1160675adba0ba283c103037e3b3210c7cfd697bc27f8821"
    $a9="cafc7b1bce7fad90c07fb9e2fc3d44a4dc479b7d9177be07988ed776"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9)
}

rule sha3_256_hashed_default_creds_openconnect
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for openconnect. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="fb001dfcffd1c899f3297871406242f097aecf1a5342ccf3ebcd116146188e4b"
    $a1="0ba89b0f374bc15fbc2f39882ba5c4d1db59517683acfc7785022de3d19fd4fe"
    $a2="19d7cd70d22058fd1b9f31b78d1a1ad90cdf9541a1b17ac7b2cd9a62e8ac2bb5"
    $a3="0ba89b0f374bc15fbc2f39882ba5c4d1db59517683acfc7785022de3d19fd4fe"
    $a4="031e7b87a990d87f7ede6d67a6d166366a2c222428de5825ddff1b42f77a684b"
    $a5="0ba89b0f374bc15fbc2f39882ba5c4d1db59517683acfc7785022de3d19fd4fe"
    $a6="90837cedf4bd5ac7a1a4a0d95ca81a172a7ff25a1630f158abead0653101079d"
    $a7="0ba89b0f374bc15fbc2f39882ba5c4d1db59517683acfc7785022de3d19fd4fe"
    $a8="db83f91b7812a78fae5624a47d23297827bc5c1a34cb240c12aeb01278e55fa4"
    $a9="0ba89b0f374bc15fbc2f39882ba5c4d1db59517683acfc7785022de3d19fd4fe"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9)
}

rule sha3_384_hashed_default_creds_openconnect
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for openconnect. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="9765a57f2010506383de91052915ce8bafbdb39f3e5a8c1a1693a0076365d37abbfd3305881ea3b5fa1426316afd7df3"
    $a1="2d39c734a534bc6bcc705c5b3779fbb96fbb9d6bc872afd394753945fa39e72251d41a333be6cba95ed2d4e15409a3c9"
    $a2="ef5543deb4b3d69d67ee03d2bc196338f13e5f8fdee290ff03f8a239ffd92f1fcc73b944e5eb9a8fc2f86efa536e8c57"
    $a3="2d39c734a534bc6bcc705c5b3779fbb96fbb9d6bc872afd394753945fa39e72251d41a333be6cba95ed2d4e15409a3c9"
    $a4="0ffb48c488a6cac65e53daf1b23c252dbc5c9d8b9db45090c24cb8e97cbabf903939a8b624ca342a67632b2e94d51f55"
    $a5="2d39c734a534bc6bcc705c5b3779fbb96fbb9d6bc872afd394753945fa39e72251d41a333be6cba95ed2d4e15409a3c9"
    $a6="236a146b382d610556b4f079e9c57e216cf5fbe207fc431d0e437a76268c6d10e77f7095ffb46d31b3657f66d34c217e"
    $a7="2d39c734a534bc6bcc705c5b3779fbb96fbb9d6bc872afd394753945fa39e72251d41a333be6cba95ed2d4e15409a3c9"
    $a8="c0f39e696d6fe9654df897fac572d7aaf295705661716b59615d2b0746941a9ccd2226adb99f94690b35b950a23a0c9d"
    $a9="2d39c734a534bc6bcc705c5b3779fbb96fbb9d6bc872afd394753945fa39e72251d41a333be6cba95ed2d4e15409a3c9"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9)
}

rule sha3_512_hashed_default_creds_openconnect
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for openconnect. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="5a38afb1a18d408e6cd367f9db91e2ab9bce834cdad3da24183cc174956c20ce35dd39c2bd36aae907111ae3d6ada353f7697a5f1a8fc567aae9e4ca41a9d19d"
    $a1="0370a17f310db92409df517c78f93f3033dc09b066c7e62b3e8ddafeb6b85d5860ff9b036e986a43a2fc8109923bd1cdab08f60a8770369f85e9d350b1819883"
    $a2="92a04f9414a125c33f46245693b43ed71341ef8186d7182f2d6599a769bd70a231c739ce3b5461145f3aaf4ca48ed298086e3ea30e0c4347cd27dc4560cbf02c"
    $a3="0370a17f310db92409df517c78f93f3033dc09b066c7e62b3e8ddafeb6b85d5860ff9b036e986a43a2fc8109923bd1cdab08f60a8770369f85e9d350b1819883"
    $a4="0a58894a41dd11073057b983dee7d5ca7699afbed2ef4703c6704bfb934f8a81bcb588e64d2cf7dca3a69b7ead0cdbb657b8e9c66c2eb3a0ed021f5695c69cf8"
    $a5="0370a17f310db92409df517c78f93f3033dc09b066c7e62b3e8ddafeb6b85d5860ff9b036e986a43a2fc8109923bd1cdab08f60a8770369f85e9d350b1819883"
    $a6="df93662f33e0d941e8722f19e52cab59aa5618f2a44fa1fc1076b8cd8deac32290cda053e99eb7ad2083960c115a9f0dfe2377b2beaa23a16fac7c42c9cba63a"
    $a7="0370a17f310db92409df517c78f93f3033dc09b066c7e62b3e8ddafeb6b85d5860ff9b036e986a43a2fc8109923bd1cdab08f60a8770369f85e9d350b1819883"
    $a8="7fde68d4de587aa17c5259103cfeb4720c4c2324e8c75df0f87a9c34a2ed5199b2b403f20be568e70d9a2ff54c42a24efc6c3abdf023b8fa44369bcb3b22f2ff"
    $a9="0370a17f310db92409df517c78f93f3033dc09b066c7e62b3e8ddafeb6b85d5860ff9b036e986a43a2fc8109923bd1cdab08f60a8770369f85e9d350b1819883"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9)
}

rule base64_hashed_default_creds_openconnect
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for openconnect. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="YWRtaW4="
    $a1="T0NT"
    $a2="YWRtaW5zdGF0"
    $a3="T0NT"
    $a4="YWRtaW51c2Vy"
    $a5="T0NT"
    $a6="YWRtaW52aWV3"
    $a7="T0NT"
    $a8="aGVscGRlc2s="
    $a9="T0NT"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9)
}

