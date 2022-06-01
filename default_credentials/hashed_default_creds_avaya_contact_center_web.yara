/*This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as long as you use it under this license.*/

rule md5_hashed_default_creds_avaya_contact_center_web
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for avaya_contact_center_web. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="add6bb58e139be103324d04d82d8f545"
    $a1="add6bb58e139be103324d04d82d8f545"
condition:
    ($a0 and $a1)
}

rule sha1_hashed_default_creds_avaya_contact_center_web
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for avaya_contact_center_web. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="30e0c5f0ec5359f21e34af3691470c1b91865295"
    $a1="30e0c5f0ec5359f21e34af3691470c1b91865295"
condition:
    ($a0 and $a1)
}

rule sha384_hashed_default_creds_avaya_contact_center_web
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for avaya_contact_center_web. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="cc741da44e4d00e88805b9b575c675e88d69a66380985fdb4421d0382a31ff08c6ba9433d04f7707f029200bbb3096c6"
    $a1="cc741da44e4d00e88805b9b575c675e88d69a66380985fdb4421d0382a31ff08c6ba9433d04f7707f029200bbb3096c6"
condition:
    ($a0 and $a1)
}

rule sha224_hashed_default_creds_avaya_contact_center_web
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for avaya_contact_center_web. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="22d417dcf61fea58e9cdc85ce70382c7bf7d5553bc9f0774a3287b7b"
    $a1="22d417dcf61fea58e9cdc85ce70382c7bf7d5553bc9f0774a3287b7b"
condition:
    ($a0 and $a1)
}

rule sha512_hashed_default_creds_avaya_contact_center_web
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for avaya_contact_center_web. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="0d57be97f9d5abb348c1e3c76c75734979412498e2a2e7482e909a44ce4ae2b19187749c4bd17f4fa33c6eadc5a0535112eb6ea03e01a0987af3003c6c45dde6"
    $a1="0d57be97f9d5abb348c1e3c76c75734979412498e2a2e7482e909a44ce4ae2b19187749c4bd17f4fa33c6eadc5a0535112eb6ea03e01a0987af3003c6c45dde6"
condition:
    ($a0 and $a1)
}

rule sha256_hashed_default_creds_avaya_contact_center_web
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for avaya_contact_center_web. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="c6c6dc4efdd314700252330e1e36db2ef1b1cc2d703b884168c541963336a0c8"
    $a1="c6c6dc4efdd314700252330e1e36db2ef1b1cc2d703b884168c541963336a0c8"
condition:
    ($a0 and $a1)
}

rule blake2b_hashed_default_creds_avaya_contact_center_web
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for avaya_contact_center_web. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="df007f36db7de946707d84d81e720969f1354d129b3f561c38db414d329eb88abdcdad0c8b0b2db547c4c03543afa42dbfe6c53cc3a0af2a315ce5be87850cea"
    $a1="df007f36db7de946707d84d81e720969f1354d129b3f561c38db414d329eb88abdcdad0c8b0b2db547c4c03543afa42dbfe6c53cc3a0af2a315ce5be87850cea"
condition:
    ($a0 and $a1)
}

rule blake2s_hashed_default_creds_avaya_contact_center_web
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for avaya_contact_center_web. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="6b98c00ae312dcb59af4d7769487889c3ab1a7366bdbf9dec1a1ed98d4ff8f1e"
    $a1="6b98c00ae312dcb59af4d7769487889c3ab1a7366bdbf9dec1a1ed98d4ff8f1e"
condition:
    ($a0 and $a1)
}

rule sha3_224_hashed_default_creds_avaya_contact_center_web
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for avaya_contact_center_web. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="5cd9d36bfd71ccc6cd7ac8d50cc18d3f8f5bdb1a710189d238e1ff09"
    $a1="5cd9d36bfd71ccc6cd7ac8d50cc18d3f8f5bdb1a710189d238e1ff09"
condition:
    ($a0 and $a1)
}

rule sha3_256_hashed_default_creds_avaya_contact_center_web
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for avaya_contact_center_web. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="cae76c66f907f3a9ad797c25588a373441deb380830161fadc4b1635eb9ce438"
    $a1="cae76c66f907f3a9ad797c25588a373441deb380830161fadc4b1635eb9ce438"
condition:
    ($a0 and $a1)
}

rule sha3_384_hashed_default_creds_avaya_contact_center_web
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for avaya_contact_center_web. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="53845c65e33295c909d20b77f04bd899442215563889fa207617ff39fa4319b5cc6dc1f4739bc4cea6ab4f73254ee71f"
    $a1="53845c65e33295c909d20b77f04bd899442215563889fa207617ff39fa4319b5cc6dc1f4739bc4cea6ab4f73254ee71f"
condition:
    ($a0 and $a1)
}

rule sha3_512_hashed_default_creds_avaya_contact_center_web
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for avaya_contact_center_web. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="468975f36294ef9d7d1d7b6e988c8e9f1e2a791728bfcbc7b0c505028fc7b5610c68042df6b7b53517d10390cdaedff7bcd8654edd432e73e47c4f66939c0a26"
    $a1="468975f36294ef9d7d1d7b6e988c8e9f1e2a791728bfcbc7b0c505028fc7b5610c68042df6b7b53517d10390cdaedff7bcd8654edd432e73e47c4f66939c0a26"
condition:
    ($a0 and $a1)
}

rule base64_hashed_default_creds_avaya_contact_center_web
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for avaya_contact_center_web. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="d2ViYWRtaW4="
    $a1="d2ViYWRtaW4="
condition:
    ($a0 and $a1)
}

