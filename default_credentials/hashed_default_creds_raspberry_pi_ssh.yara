/*This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as long as you use it under this license.*/

rule md5_hashed_default_creds_raspberry_pi_ssh
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for raspberry_pi_ssh. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="72ab8af56bddab33b269c5964b26620a"
    $a1="b89749505e144b564adfe3ea8fc394aa"
condition:
    ($a0 and $a1)
}

rule sha1_hashed_default_creds_raspberry_pi_ssh
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for raspberry_pi_ssh. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="b02e5b66ace6dc3b459be661062c452b50ea1c13"
    $a1="eaca980117c022577f5b2fdce33242bd13148447"
condition:
    ($a0 and $a1)
}

rule sha384_hashed_default_creds_raspberry_pi_ssh
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for raspberry_pi_ssh. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="520dc475f13a853cf460b09609ac16cabf78cad4ded3a44e258bbb099669e79a6fde03cc13ca1b845829dde32e6320f7"
    $a1="22462d58277a3c531c3370898fef482bd6d681db1eec407d05f05bc65df30fdd32b5155e966f83537f0cb97436fdc328"
condition:
    ($a0 and $a1)
}

rule sha224_hashed_default_creds_raspberry_pi_ssh
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for raspberry_pi_ssh. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="30522bf0e6e99b1ce86aea503f63f3063cfea91c820ec6b7c7d84dd2"
    $a1="209e26396027dc41b8032c4af1011c9de13150dfde2ee785f86d5118"
condition:
    ($a0 and $a1)
}

rule sha512_hashed_default_creds_raspberry_pi_ssh
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for raspberry_pi_ssh. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="88138504e31a2ba7bd240aed179e436a668ae3e8b4b2b59bcea41f5e012a4528f902fea3bb6bd62a31621497a6efa531241d18da27e07e3fd21ee1e64c2516ce"
    $a1="5895bb1bccf1da795c83734405a7a0193fbb56473842118dd1b66b2186a290e00fa048bc2a302d763c381ea3ac3f2bc2f30aaa005fb2c836bbf641d395c4eb5e"
condition:
    ($a0 and $a1)
}

rule sha256_hashed_default_creds_raspberry_pi_ssh
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for raspberry_pi_ssh. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="85b42e1702877c851eb7412fe958c8fb447c3207b4798fadab42ea8539046ce1"
    $a1="e97407735e49029c96e5708c724fc9ce57b6335dba804a893320fcb7c0a07953"
condition:
    ($a0 and $a1)
}

rule blake2b_hashed_default_creds_raspberry_pi_ssh
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for raspberry_pi_ssh. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="d6e1f63f0278cad56cc49fd8bf2ee999351369561a78c6c617ce11ca97a367c2ac8e2ac1ed2fdac6517980ee2b5a975fd5f484d301b7681618321e4d9d47e2e8"
    $a1="6cc17a49898d6d401b4f63b96ea62e24ca798f59c3aa54b57f92d2f5df455ec17166423287d368980f102d3144f2f38f0b570bc0c13c835de32c00bcb72728f8"
condition:
    ($a0 and $a1)
}

rule blake2s_hashed_default_creds_raspberry_pi_ssh
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for raspberry_pi_ssh. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="df7237b77fd25a16b214d44d11c5a7c72b17987c1521e33d355ababb23755e10"
    $a1="3384299169959fc6bd5bd77fea881c34b65fe2cb6a1cb6598dd19d9aed142e24"
condition:
    ($a0 and $a1)
}

rule sha3_224_hashed_default_creds_raspberry_pi_ssh
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for raspberry_pi_ssh. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="a481172d9b06124e8ae43cee7d7adbb406cad55a7501f4de91c20327"
    $a1="dc95a37066e9fff8910dc7f143bca7d4841f68f2c0d82199faddf329"
condition:
    ($a0 and $a1)
}

rule sha3_256_hashed_default_creds_raspberry_pi_ssh
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for raspberry_pi_ssh. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="7d9605848f19017dc0bc40e0d0c32c4b2238e31713945f8b797347ae29039ec3"
    $a1="cbe01278f00e2de65533a93974896715ca37b4b2a915db69d9f234555e7342b9"
condition:
    ($a0 and $a1)
}

rule sha3_384_hashed_default_creds_raspberry_pi_ssh
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for raspberry_pi_ssh. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="65ddd20a75473b10f2f7d285b625a6beeb0064eb07c915e6548468c5d4b5a320a7ec34a1be509b63236eca3ecd635301"
    $a1="38bd5c110d1b0c706ee925264a49639dd650e185292e02fa3820a98d50e14c81359ab7d9084cd041bb82a341694bea71"
condition:
    ($a0 and $a1)
}

rule sha3_512_hashed_default_creds_raspberry_pi_ssh
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for raspberry_pi_ssh. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="695457a7c7d5d016e0145db5dfabb3b2790aca7acc016bb9aa4e1a392ba09b43b715010134ec05b3d09ed2849e6e1509c8aa307726b7d9058316c7584d7cd285"
    $a1="9ca136c8b28613d271becc9635f4f507c91756d5f76e4b31717ebd8bf0a32ad87813d3b665b77c189ad6bf06d1795b978f37f46b512f39e232acbfe8c5175dfb"
condition:
    ($a0 and $a1)
}

rule base64_hashed_default_creds_raspberry_pi_ssh
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for raspberry_pi_ssh. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="cGk="
    $a1="cmFzcGJlcnJ5"
condition:
    ($a0 and $a1)
}

