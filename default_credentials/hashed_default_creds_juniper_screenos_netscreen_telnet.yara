/*This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as long as you use it under this license.*/

rule md5_hashed_default_creds_juniper_screenos_netscreen_telnet
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for juniper_screenos_netscreen_telnet. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="f222b9ec8469d27230ef4201f95e3d46"
    $a1="077404fea9a815f4e82effc52d43ae9b"
condition:
    ($a0 and $a1)
}

rule sha1_hashed_default_creds_juniper_screenos_netscreen_telnet
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for juniper_screenos_netscreen_telnet. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="82579efda5bd6ce6047b0903ffa462f2c1e1da65"
    $a1="4743f889d1c1983e9060ac1d233e54b3c93ebbef"
condition:
    ($a0 and $a1)
}

rule sha384_hashed_default_creds_juniper_screenos_netscreen_telnet
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for juniper_screenos_netscreen_telnet. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="f78bd52b7538fb7ee4c57c995a1bbf476fca33e2adce23d5b114ac159d2616187ac1f2f292e7062d163cdefe5434835f"
    $a1="446c46f01a41309caf5d3b1522adedadc9371c583c80a79b8ad6d86e735968641dc69327c2f2c73a21c9018abe109ef9"
condition:
    ($a0 and $a1)
}

rule sha224_hashed_default_creds_juniper_screenos_netscreen_telnet
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for juniper_screenos_netscreen_telnet. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="dd7ed3ca1388703a69f0932c659b7ef08dd1e48ba64cd93a5949e6f0"
    $a1="8e0581efe1906cdc1a60d915ea8df75cfb5420efaeb9cd4a9ce21b4c"
condition:
    ($a0 and $a1)
}

rule sha512_hashed_default_creds_juniper_screenos_netscreen_telnet
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for juniper_screenos_netscreen_telnet. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="a057d693d382ea522c9614ead06120a4a8ad74c23f9785af2ee64935b9f95848ad8d0eaf1088d14183cb71a0e1d51aceeccd218d3d270741ab9aa1fa3c0d79d6"
    $a1="67afbe21286c95e82ef7d29cff51d9c269667fd0bd60b0aa91fe0a78d1f07639bc6f318d59d55a55a1d54d1e5718fb422eb7d5c6af7ec61025ba7e25027a9493"
condition:
    ($a0 and $a1)
}

rule sha256_hashed_default_creds_juniper_screenos_netscreen_telnet
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for juniper_screenos_netscreen_telnet. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="23bb8b463e0de9b386c62fd5916c01d811a110be4cd2f882c2ab0a920fad19c7"
    $a1="b8632cbb31afe9a202de1957f8b45dce9f7fefe5745a8ff5a9cd8774f60232a0"
condition:
    ($a0 and $a1)
}

rule blake2b_hashed_default_creds_juniper_screenos_netscreen_telnet
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for juniper_screenos_netscreen_telnet. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="b63fd22eb6fa67b5764bd701c2bca5ecf545e600402cdbcf319859767693d8077bf8513ead89cb0e62dbcb0fe57650cfa948126aef5f039e36863882a4348e6a"
    $a1="ca89db4214705c22f6039d0805fe6f9c787f3d081cba1dd063c788d82bec297a252e2c70644351741a86a9821d0cc8f974e018ec864512cf86423d26a199f7d1"
condition:
    ($a0 and $a1)
}

rule blake2s_hashed_default_creds_juniper_screenos_netscreen_telnet
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for juniper_screenos_netscreen_telnet. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="9ca80bd0953938baf509f7bd03fb009d336cbef99edb07037ffde53afef33d26"
    $a1="552f2751877bbe6ccfdd3a92d54af32a8f7fec9c81c3914a0e22936ec87f1440"
condition:
    ($a0 and $a1)
}

rule sha3_224_hashed_default_creds_juniper_screenos_netscreen_telnet
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for juniper_screenos_netscreen_telnet. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="b158b1d74cf4c3c13d914034055183bad8697f81868ba01cf9c656ab"
    $a1="6b63ef251b653a65040549282394da439d26bf42cc0123f044fd3c34"
condition:
    ($a0 and $a1)
}

rule sha3_256_hashed_default_creds_juniper_screenos_netscreen_telnet
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for juniper_screenos_netscreen_telnet. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="9f2dc58fe82d1f53a48ef3c0d8b0237125012949b7c159e4d0a78e741840b410"
    $a1="1bed6a75e9d04844820c5ceac58447fe2fdc97b852caeb64c8338e8803e29b26"
condition:
    ($a0 and $a1)
}

rule sha3_384_hashed_default_creds_juniper_screenos_netscreen_telnet
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for juniper_screenos_netscreen_telnet. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="c5953e0f9d2f428cc2e39d004c4e3fce7383c4a94b08fb5d2847ec5e60073b669c9b9ea515ec173bb23bf366b5f56f29"
    $a1="f7522e21a7a76232d20a3e48ee0806335df13f5a1060c4b00b61e994a4cb506515a38c48506257479d79b32ade400d6e"
condition:
    ($a0 and $a1)
}

rule sha3_512_hashed_default_creds_juniper_screenos_netscreen_telnet
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for juniper_screenos_netscreen_telnet. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="66aefb7dde2dac856807d63d2bda9d71568b7e6ad28c698bcbf0d725e61c72bc790064532977c1f714c9f1be28fa45253b8d91646d9160dc5f9aacd7a2d5ff29"
    $a1="de8a3ce932c663d19f5c23fe39772ba5ccec98db0afb220e0b8293ba37c5687b33502b46c80909137b20370bb61b1de72704ba228ca090b577dfb9f1e71ed053"
condition:
    ($a0 and $a1)
}

rule base64_hashed_default_creds_juniper_screenos_netscreen_telnet
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for juniper_screenos_netscreen_telnet. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="bmV0c2NyZWVu"
    $a1="PDw8ICVzKHVuPSclcycpID0gJXU="
condition:
    ($a0 and $a1)
}

