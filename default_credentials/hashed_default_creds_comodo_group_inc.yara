/*This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as long as you use it under this license.*/

rule md5_hashed_default_creds_comodo_group_inc
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for comodo_group_inc. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="0926095fd78b40feb9cc9c075f385dd6"
    $a1="0926095fd78b40feb9cc9c075f385dd6"
condition:
    ($a0 and $a1)
}

rule sha1_hashed_default_creds_comodo_group_inc
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for comodo_group_inc. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="8947320cee61087e89fa734c2a3baf64cf46083d"
    $a1="8947320cee61087e89fa734c2a3baf64cf46083d"
condition:
    ($a0 and $a1)
}

rule sha384_hashed_default_creds_comodo_group_inc
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for comodo_group_inc. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="4984cec212baf75d96ebe1fe0716b3dfb41d21dc47be7bbbe47028db323192b03561b7e213da066603996f6ed0f11a28"
    $a1="4984cec212baf75d96ebe1fe0716b3dfb41d21dc47be7bbbe47028db323192b03561b7e213da066603996f6ed0f11a28"
condition:
    ($a0 and $a1)
}

rule sha224_hashed_default_creds_comodo_group_inc
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for comodo_group_inc. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="2da0a433943dbe79eca6489b23172882b1bb4f1ed7cc2d6c080b9ea9"
    $a1="2da0a433943dbe79eca6489b23172882b1bb4f1ed7cc2d6c080b9ea9"
condition:
    ($a0 and $a1)
}

rule sha512_hashed_default_creds_comodo_group_inc
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for comodo_group_inc. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="61f2c2a4060df5548f43459575894a351035a87b3be2193ec4dc0e22669812d1d173907f7660142be4ba30ae9b5ee8dc99387ddec0dc329cdee196e16cd360f5"
    $a1="61f2c2a4060df5548f43459575894a351035a87b3be2193ec4dc0e22669812d1d173907f7660142be4ba30ae9b5ee8dc99387ddec0dc329cdee196e16cd360f5"
condition:
    ($a0 and $a1)
}

rule sha256_hashed_default_creds_comodo_group_inc
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for comodo_group_inc. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="d588d209baf20e2ff03e4e5c060bab98077b791596f0d1a4640e8dadefd5953f"
    $a1="d588d209baf20e2ff03e4e5c060bab98077b791596f0d1a4640e8dadefd5953f"
condition:
    ($a0 and $a1)
}

rule blake2b_hashed_default_creds_comodo_group_inc
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for comodo_group_inc. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="1a9d933c41a6f459836041cea4dd353e2688f7dda5b16484ede305ee7dd49ae2d6db9ca413710c78d60d12d3184768e510b2dee87e242661fecccaff8883c75a"
    $a1="1a9d933c41a6f459836041cea4dd353e2688f7dda5b16484ede305ee7dd49ae2d6db9ca413710c78d60d12d3184768e510b2dee87e242661fecccaff8883c75a"
condition:
    ($a0 and $a1)
}

rule blake2s_hashed_default_creds_comodo_group_inc
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for comodo_group_inc. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="832fa1c2c0abfd5539261cb7d3c0c4f0ecd1703a293f360e8d4be65b980f667c"
    $a1="832fa1c2c0abfd5539261cb7d3c0c4f0ecd1703a293f360e8d4be65b980f667c"
condition:
    ($a0 and $a1)
}

rule sha3_224_hashed_default_creds_comodo_group_inc
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for comodo_group_inc. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="d6e162b4a854f3130f9112a7a5623922caaa44c0f147b742fb0cee94"
    $a1="d6e162b4a854f3130f9112a7a5623922caaa44c0f147b742fb0cee94"
condition:
    ($a0 and $a1)
}

rule sha3_256_hashed_default_creds_comodo_group_inc
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for comodo_group_inc. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="cc84f389af1aba71162a91d93db7651413d64a00b024e5e407719e25b0247f9b"
    $a1="cc84f389af1aba71162a91d93db7651413d64a00b024e5e407719e25b0247f9b"
condition:
    ($a0 and $a1)
}

rule sha3_384_hashed_default_creds_comodo_group_inc
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for comodo_group_inc. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="f10aba19d403b82c2f488bd2b96843e500cfbb92440076c9f3b8ba1a233100fb0c208661a9af98fb705a71cae056e862"
    $a1="f10aba19d403b82c2f488bd2b96843e500cfbb92440076c9f3b8ba1a233100fb0c208661a9af98fb705a71cae056e862"
condition:
    ($a0 and $a1)
}

rule sha3_512_hashed_default_creds_comodo_group_inc
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for comodo_group_inc. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="6f3cf829ccef7aa9f146af6a3ef2dd69422c2b012164bed60fb6dbd3b543ca758894d35b086a764fd5bff4d27fb7dc8626805dc033b681a1546acc1669b9be2f"
    $a1="6f3cf829ccef7aa9f146af6a3ef2dd69422c2b012164bed60fb6dbd3b543ca758894d35b086a764fd5bff4d27fb7dc8626805dc033b681a1546acc1669b9be2f"
condition:
    ($a0 and $a1)
}

rule base64_hashed_default_creds_comodo_group_inc
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for comodo_group_inc. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="bXlkbHA="
    $a1="bXlkbHA="
condition:
    ($a0 and $a1)
}

