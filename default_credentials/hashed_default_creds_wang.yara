/*This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as long as you use it under this license.*/

rule md5_hashed_default_creds_wang
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for wang. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="ddf86b0b94e34566c486fd076b9686a6"
    $a1="20b7ebcdca2cd3ef18d66fe5bf026075"
condition:
    ($a0 and $a1)
}

rule sha1_hashed_default_creds_wang
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for wang. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="4aad0471e6ce1a8b8c30b3b77fa8370ea12552eb"
    $a1="2bfb09e2c7a43adde0c3f986fb5d0563d8dfd5f5"
condition:
    ($a0 and $a1)
}

rule sha384_hashed_default_creds_wang
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for wang. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="2af0bc8e3f178c8345eb7252abf64cb4e919149716a42bd9de58af74d8b50cff141891c00813ad10e7d55955af7c25d5"
    $a1="dc06211d2a1e2e97063104b44f9364f4840a8b8b5a772c1daa813d5d30da77b073abed0088af0cea1391b323021e0665"
condition:
    ($a0 and $a1)
}

rule sha224_hashed_default_creds_wang
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for wang. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="db3ffee338aef33c3ed7d2dd1585c067c05003890a702e2794e27afd"
    $a1="945e396af7a6b4fa1940488100acb768c3b8ee8ba600a7f7309e8598"
condition:
    ($a0 and $a1)
}

rule sha512_hashed_default_creds_wang
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for wang. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="1063fd487f06043509190d038c46221f35fd05f779e7fabced8caf65c1295642190d63652024a37a3cc9e0f0884f276c0b7c91629eb17de07df1d3dbcfeba846"
    $a1="7a79d85a7b0a5be354d18a860d1b9cd29608cb113e99943fca9590cce3b73e7e03029b9fee54830706380673be75ec143f72b19987cbd5fe0910998bbd440078"
condition:
    ($a0 and $a1)
}

rule sha256_hashed_default_creds_wang
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for wang. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="8e72403a856ec94da616beba1e30064176ede451e7cfab83ade501aa86e2f77f"
    $a1="bd9f74ae3252da8e4fef58e0c00af921907f7079765fe4954c3d43b194d6efbe"
condition:
    ($a0 and $a1)
}

rule blake2b_hashed_default_creds_wang
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for wang. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="b3c24ab1f361b33822386a881fe2fd1b3e4a829b75e646174365bc2639168cdd2ed5f6ce721613d78e9b8fbdeea6ef592afb3972de5efde61d61dd447727799d"
    $a1="52f7e8a8453ffdc90c4c1de4933b9163aabd2781d7fe323c2c97ea37092862505f016634dcb6004c8d76c88023dc772826d7b03733cb92c12a9e70b557d7f63b"
condition:
    ($a0 and $a1)
}

rule blake2s_hashed_default_creds_wang
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for wang. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="96817c0b4b4fd3e1ef42dfd82426f21299ce3e10a4c2c5c55df3e2401b134bcd"
    $a1="ba65cc15cdeee558c99d048df19db19d1eaf48fc46743f294fb784a348a78622"
condition:
    ($a0 and $a1)
}

rule sha3_224_hashed_default_creds_wang
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for wang. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="deb029013853b98280132561f380182410ec2e006c96e6f78fc99780"
    $a1="a1db138acad008b8dddfa85f97e01642baa9b6b8fc0fbd9490da5802"
condition:
    ($a0 and $a1)
}

rule sha3_256_hashed_default_creds_wang
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for wang. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="9361e667282efe20304db27b6f4008226dc548073663a94c317c1cde7d89a102"
    $a1="08ee5ef22b5b1f6c39637bd0dd817ad86a1d978a056942ac073067a483f3e02b"
condition:
    ($a0 and $a1)
}

rule sha3_384_hashed_default_creds_wang
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for wang. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="e5440a265cc83cbf9a98af9aac98d6a4610086c6110348886160aab958c1409265eb48fb93ac9ef2bf42d6d57e58b8cf"
    $a1="9263a17a02ff0c9f7554450e0e76eba297c2505e6000b4f0ad6bd3e0529b6b6d2e26abe582850dda273e7daa0f75a0ab"
condition:
    ($a0 and $a1)
}

rule sha3_512_hashed_default_creds_wang
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for wang. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="e17a38b395d339ea705790f3a7275543de32c457376819484dffd4d131b4f76f4075e152ed758f2c4cfa899ada895864fc810257035000a66809b69698204d41"
    $a1="e8621ad8ebf19aa89cb80fae06ad25f9b65dd048dbd8d4ff715ce95a443e87431c790b7fe8c3ecc0dd83f0f8bd1a413fa38324d68b281e0f904c44e3e68386c6"
condition:
    ($a0 and $a1)
}

rule base64_hashed_default_creds_wang
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for wang. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="Q1NH"
    $a1="U0VTQU1F"
condition:
    ($a0 and $a1)
}

