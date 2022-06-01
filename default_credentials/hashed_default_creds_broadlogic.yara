/*This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as long as you use it under this license.*/

rule md5_hashed_default_creds_broadlogic
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for broadlogic. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="21232f297a57a5a743894a0e4a801fc3"
    $a1="21232f297a57a5a743894a0e4a801fc3"
    $a2="97384261b8bbf966df16e5ad509922db"
    $a3="97384261b8bbf966df16e5ad509922db"
    $a4="add6bb58e139be103324d04d82d8f545"
    $a5="add6bb58e139be103324d04d82d8f545"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}

rule sha1_hashed_default_creds_broadlogic
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for broadlogic. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="d033e22ae348aeb5660fc2140aec35850c4da997"
    $a1="d033e22ae348aeb5660fc2140aec35850c4da997"
    $a2="2fc42d37fee2c81d767e09fb298b70c748940f86"
    $a3="2fc42d37fee2c81d767e09fb298b70c748940f86"
    $a4="30e0c5f0ec5359f21e34af3691470c1b91865295"
    $a5="30e0c5f0ec5359f21e34af3691470c1b91865295"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}

rule sha384_hashed_default_creds_broadlogic
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for broadlogic. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="9ca694a90285c034432c9550421b7b9dbd5c0f4b6673f05f6dbce58052ba20e4248041956ee8c9a2ec9f10290cdc0782"
    $a1="9ca694a90285c034432c9550421b7b9dbd5c0f4b6673f05f6dbce58052ba20e4248041956ee8c9a2ec9f10290cdc0782"
    $a2="e8d3610af1f69386211907c916abaa27f50ddadbf94af845750fbc230a2d023a89db2fea55fc2115e0e05c60f03f2774"
    $a3="e8d3610af1f69386211907c916abaa27f50ddadbf94af845750fbc230a2d023a89db2fea55fc2115e0e05c60f03f2774"
    $a4="cc741da44e4d00e88805b9b575c675e88d69a66380985fdb4421d0382a31ff08c6ba9433d04f7707f029200bbb3096c6"
    $a5="cc741da44e4d00e88805b9b575c675e88d69a66380985fdb4421d0382a31ff08c6ba9433d04f7707f029200bbb3096c6"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}

rule sha224_hashed_default_creds_broadlogic
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for broadlogic. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="58acb7acccce58ffa8b953b12b5a7702bd42dae441c1ad85057fa70b"
    $a1="58acb7acccce58ffa8b953b12b5a7702bd42dae441c1ad85057fa70b"
    $a2="c23b4b05a88545c92b14e2f27cd39aeb442dc816eac8c96db34c6076"
    $a3="c23b4b05a88545c92b14e2f27cd39aeb442dc816eac8c96db34c6076"
    $a4="22d417dcf61fea58e9cdc85ce70382c7bf7d5553bc9f0774a3287b7b"
    $a5="22d417dcf61fea58e9cdc85ce70382c7bf7d5553bc9f0774a3287b7b"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}

rule sha512_hashed_default_creds_broadlogic
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for broadlogic. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="c7ad44cbad762a5da0a452f9e854fdc1e0e7a52a38015f23f3eab1d80b931dd472634dfac71cd34ebc35d16ab7fb8a90c81f975113d6c7538dc69dd8de9077ec"
    $a1="c7ad44cbad762a5da0a452f9e854fdc1e0e7a52a38015f23f3eab1d80b931dd472634dfac71cd34ebc35d16ab7fb8a90c81f975113d6c7538dc69dd8de9077ec"
    $a2="b77fe2d86fbc5bd116d6a073eb447e76a74add3fa0d0b801f97535963241be3cdce1dbcaed603b78f020d0845b2d4bfc892ceb2a7d1c8f1d98abc4812ef5af21"
    $a3="b77fe2d86fbc5bd116d6a073eb447e76a74add3fa0d0b801f97535963241be3cdce1dbcaed603b78f020d0845b2d4bfc892ceb2a7d1c8f1d98abc4812ef5af21"
    $a4="0d57be97f9d5abb348c1e3c76c75734979412498e2a2e7482e909a44ce4ae2b19187749c4bd17f4fa33c6eadc5a0535112eb6ea03e01a0987af3003c6c45dde6"
    $a5="0d57be97f9d5abb348c1e3c76c75734979412498e2a2e7482e909a44ce4ae2b19187749c4bd17f4fa33c6eadc5a0535112eb6ea03e01a0987af3003c6c45dde6"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}

rule sha256_hashed_default_creds_broadlogic
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for broadlogic. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="8c6976e5b5410415bde908bd4dee15dfb167a9c873fc4bb8a81f6f2ab448a918"
    $a1="8c6976e5b5410415bde908bd4dee15dfb167a9c873fc4bb8a81f6f2ab448a918"
    $a2="9c0d294c05fc1d88d698034609bb81c0c69196327594e4c69d2915c80fd9850c"
    $a3="9c0d294c05fc1d88d698034609bb81c0c69196327594e4c69d2915c80fd9850c"
    $a4="c6c6dc4efdd314700252330e1e36db2ef1b1cc2d703b884168c541963336a0c8"
    $a5="c6c6dc4efdd314700252330e1e36db2ef1b1cc2d703b884168c541963336a0c8"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}

rule blake2b_hashed_default_creds_broadlogic
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for broadlogic. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="bfcce2c19c8563fd4aa66f6ec607341ff25e5f6fe7fa520d7d1242d871385f23a3e8e80093120b4877d79535e10b182ae2ec8937d1f72f091e7178c9e4ff0f11"
    $a1="bfcce2c19c8563fd4aa66f6ec607341ff25e5f6fe7fa520d7d1242d871385f23a3e8e80093120b4877d79535e10b182ae2ec8937d1f72f091e7178c9e4ff0f11"
    $a2="78029416f2a036f9bbee2b4519a452479916558edd66a43816bcce88d4b0269a8bb63062747ee448b35fdd05b00abeaf5003014087011ff134b7a00487caaccd"
    $a3="78029416f2a036f9bbee2b4519a452479916558edd66a43816bcce88d4b0269a8bb63062747ee448b35fdd05b00abeaf5003014087011ff134b7a00487caaccd"
    $a4="df007f36db7de946707d84d81e720969f1354d129b3f561c38db414d329eb88abdcdad0c8b0b2db547c4c03543afa42dbfe6c53cc3a0af2a315ce5be87850cea"
    $a5="df007f36db7de946707d84d81e720969f1354d129b3f561c38db414d329eb88abdcdad0c8b0b2db547c4c03543afa42dbfe6c53cc3a0af2a315ce5be87850cea"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}

rule blake2s_hashed_default_creds_broadlogic
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for broadlogic. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="327e7e3821f5f6d33c090137f979bf48ee62e9051c1610e1d6468ecb3c67a124"
    $a1="327e7e3821f5f6d33c090137f979bf48ee62e9051c1610e1d6468ecb3c67a124"
    $a2="293eea3b1d83925a4c5794c9d2a7a049b796ba4831e66bbfff5ea318a264cb3f"
    $a3="293eea3b1d83925a4c5794c9d2a7a049b796ba4831e66bbfff5ea318a264cb3f"
    $a4="6b98c00ae312dcb59af4d7769487889c3ab1a7366bdbf9dec1a1ed98d4ff8f1e"
    $a5="6b98c00ae312dcb59af4d7769487889c3ab1a7366bdbf9dec1a1ed98d4ff8f1e"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}

rule sha3_224_hashed_default_creds_broadlogic
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for broadlogic. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="a53fff8dd075bed169e164743231ff533d8b9260b0b8073f0a4c1d20"
    $a1="a53fff8dd075bed169e164743231ff533d8b9260b0b8073f0a4c1d20"
    $a2="6c997153b9824fae73b4f417bb5ee86113c6ac5c8208ad2fe2a11d71"
    $a3="6c997153b9824fae73b4f417bb5ee86113c6ac5c8208ad2fe2a11d71"
    $a4="5cd9d36bfd71ccc6cd7ac8d50cc18d3f8f5bdb1a710189d238e1ff09"
    $a5="5cd9d36bfd71ccc6cd7ac8d50cc18d3f8f5bdb1a710189d238e1ff09"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}

rule sha3_256_hashed_default_creds_broadlogic
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for broadlogic. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="fb001dfcffd1c899f3297871406242f097aecf1a5342ccf3ebcd116146188e4b"
    $a1="fb001dfcffd1c899f3297871406242f097aecf1a5342ccf3ebcd116146188e4b"
    $a2="f6238a3654d68b8148200a053d013ec6c1caf6e12b24679c88d645f80c686bbe"
    $a3="f6238a3654d68b8148200a053d013ec6c1caf6e12b24679c88d645f80c686bbe"
    $a4="cae76c66f907f3a9ad797c25588a373441deb380830161fadc4b1635eb9ce438"
    $a5="cae76c66f907f3a9ad797c25588a373441deb380830161fadc4b1635eb9ce438"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}

rule sha3_384_hashed_default_creds_broadlogic
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for broadlogic. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="9765a57f2010506383de91052915ce8bafbdb39f3e5a8c1a1693a0076365d37abbfd3305881ea3b5fa1426316afd7df3"
    $a1="9765a57f2010506383de91052915ce8bafbdb39f3e5a8c1a1693a0076365d37abbfd3305881ea3b5fa1426316afd7df3"
    $a2="18b54a8de3ef7af582050541d99e85e583708db04970f30d1fbbbe5bd22a3926c2147939e2be80a83b4f325ad72cd7fe"
    $a3="18b54a8de3ef7af582050541d99e85e583708db04970f30d1fbbbe5bd22a3926c2147939e2be80a83b4f325ad72cd7fe"
    $a4="53845c65e33295c909d20b77f04bd899442215563889fa207617ff39fa4319b5cc6dc1f4739bc4cea6ab4f73254ee71f"
    $a5="53845c65e33295c909d20b77f04bd899442215563889fa207617ff39fa4319b5cc6dc1f4739bc4cea6ab4f73254ee71f"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}

rule sha3_512_hashed_default_creds_broadlogic
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for broadlogic. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="5a38afb1a18d408e6cd367f9db91e2ab9bce834cdad3da24183cc174956c20ce35dd39c2bd36aae907111ae3d6ada353f7697a5f1a8fc567aae9e4ca41a9d19d"
    $a1="5a38afb1a18d408e6cd367f9db91e2ab9bce834cdad3da24183cc174956c20ce35dd39c2bd36aae907111ae3d6ada353f7697a5f1a8fc567aae9e4ca41a9d19d"
    $a2="1e60cc099bc0ab00cbffb311120b7ca623df6058beb22ac37f5101883128bd5777e26c52c0efd7e2c2319aeefac74440c653b0af588cc5002850a6d75ad277d7"
    $a3="1e60cc099bc0ab00cbffb311120b7ca623df6058beb22ac37f5101883128bd5777e26c52c0efd7e2c2319aeefac74440c653b0af588cc5002850a6d75ad277d7"
    $a4="468975f36294ef9d7d1d7b6e988c8e9f1e2a791728bfcbc7b0c505028fc7b5610c68042df6b7b53517d10390cdaedff7bcd8654edd432e73e47c4f66939c0a26"
    $a5="468975f36294ef9d7d1d7b6e988c8e9f1e2a791728bfcbc7b0c505028fc7b5610c68042df6b7b53517d10390cdaedff7bcd8654edd432e73e47c4f66939c0a26"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}

rule base64_hashed_default_creds_broadlogic
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for broadlogic. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="YWRtaW4="
    $a1="YWRtaW4="
    $a2="aW5zdGFsbGVy"
    $a3="aW5zdGFsbGVy"
    $a4="d2ViYWRtaW4="
    $a5="d2ViYWRtaW4="
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}

