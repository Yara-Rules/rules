/*This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as long as you use it under this license.*/

rule md5_hashed_default_creds_zyxel_nwa_nap_wac_wireless_access_point_series_ftp
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for zyxel_nwa_nap_wac_wireless_access_point_series_ftp. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="f1b463eeaba608a486e73220fcabf42a"
    $a1="81dc9bdb52d04dc20036dbd8313ed055"
condition:
    ($a0 and $a1)
}

rule sha1_hashed_default_creds_zyxel_nwa_nap_wac_wireless_access_point_series_ftp
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for zyxel_nwa_nap_wac_wireless_access_point_series_ftp. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="ff021c97bffd085faf80a84345a5750162b994f2"
    $a1="7110eda4d09e062aa5e4a390b0a572ac0d2c0220"
condition:
    ($a0 and $a1)
}

rule sha384_hashed_default_creds_zyxel_nwa_nap_wac_wireless_access_point_series_ftp
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for zyxel_nwa_nap_wac_wireless_access_point_series_ftp. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="2134b1073ddea12e2bb0e1fdeff6c76ca239646cc9083ec483eb958043b4e1bedfbb715c613ca9edcdf197652357364e"
    $a1="504f008c8fcf8b2ed5dfcde752fc5464ab8ba064215d9c5b5fc486af3d9ab8c81b14785180d2ad7cee1ab792ad44798c"
condition:
    ($a0 and $a1)
}

rule sha224_hashed_default_creds_zyxel_nwa_nap_wac_wireless_access_point_series_ftp
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for zyxel_nwa_nap_wac_wireless_access_point_series_ftp. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="cb41345488844ddfbe4a2a53497507337a4fffad8739cc8fbc15efe6"
    $a1="99fb2f48c6af4761f904fc85f95eb56190e5d40b1f44ec3a9c1fa319"
condition:
    ($a0 and $a1)
}

rule sha512_hashed_default_creds_zyxel_nwa_nap_wac_wireless_access_point_series_ftp
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for zyxel_nwa_nap_wac_wireless_access_point_series_ftp. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="73b04152d94849894efef49087251f49de7063146153d23dd46522d8b455d2fabe2194e315caf60e60dd10dd10c00130f452fef2ea713e338b58f4997ad80a75"
    $a1="d404559f602eab6fd602ac7680dacbfaadd13630335e951f097af3900e9de176b6db28512f2e000b9d04fba5133e8b1c6e8df59db3a8ab9d60be4b97cc9e81db"
condition:
    ($a0 and $a1)
}

rule sha256_hashed_default_creds_zyxel_nwa_nap_wac_wireless_access_point_series_ftp
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for zyxel_nwa_nap_wac_wireless_access_point_series_ftp. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="d947fef893df172d76288f02ee4325ce091dfcb78faa5f7516f558e5e32b73bc"
    $a1="03ac674216f3e15c761ee1a5e255f067953623c8b388b4459e13f978d7c846f4"
condition:
    ($a0 and $a1)
}

rule blake2b_hashed_default_creds_zyxel_nwa_nap_wac_wireless_access_point_series_ftp
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for zyxel_nwa_nap_wac_wireless_access_point_series_ftp. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="45817fa4dacf4e18290b58789369bc64756270058b4426c3b34db0ede8c6a7fb900ca0a580cc5a8f8d81e77669bfa8803d289fe046bfdac0e8bb89074d9d0f4f"
    $a1="da77bd2a1d857d88b31de27536b81df7f005027d4f847667df13a0569b6048e0454ce9480827789547cc174060c4f388866ebb0209929b0de414cc9ac571c421"
condition:
    ($a0 and $a1)
}

rule blake2s_hashed_default_creds_zyxel_nwa_nap_wac_wireless_access_point_series_ftp
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for zyxel_nwa_nap_wac_wireless_access_point_series_ftp. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="8ce02a5fdabb36d20cc49852d31f103f0a24973f2c192e23ae6a030944b9bd63"
    $a1="90931556d9513e8c26040a9ec2a2f1300bdc79a890907da9cc2b3a2c690574c1"
condition:
    ($a0 and $a1)
}

rule sha3_224_hashed_default_creds_zyxel_nwa_nap_wac_wireless_access_point_series_ftp
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for zyxel_nwa_nap_wac_wireless_access_point_series_ftp. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="35973e50cddcd11527bbe2e0530ccd8e66bc2b7c8ff75200fb300655"
    $a1="b0f3dc043a9c5c05f67651a8c9108b4c2b98e7246b2eea14cb204295"
condition:
    ($a0 and $a1)
}

rule sha3_256_hashed_default_creds_zyxel_nwa_nap_wac_wireless_access_point_series_ftp
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for zyxel_nwa_nap_wac_wireless_access_point_series_ftp. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="fe7b562b962cf56d69d30f52fb326fe8e42f9799082d6ab1e504b404bfd32080"
    $a1="1d6442ddcfd9db1ff81df77cbefcd5afcc8c7ca952ab3101ede17a84b866d3f3"
condition:
    ($a0 and $a1)
}

rule sha3_384_hashed_default_creds_zyxel_nwa_nap_wac_wireless_access_point_series_ftp
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for zyxel_nwa_nap_wac_wireless_access_point_series_ftp. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="a262127457671dc660c32089b0785017ef6ff8d6f5b2efd7607bd01e724e31d8d2e20bf9fc993b9b3da51089fade29ad"
    $a1="0bf2c5eed2dc859ca9707ae59a18b5097d580ce705808b80830c5cf5832405073e3fa3491ed7071a2362048edff48295"
condition:
    ($a0 and $a1)
}

rule sha3_512_hashed_default_creds_zyxel_nwa_nap_wac_wireless_access_point_series_ftp
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for zyxel_nwa_nap_wac_wireless_access_point_series_ftp. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="3202ce529b0577e0603cf888d68dc6fabea5afd9552a16d25fa6dea9c3ede492758d2b795e4c9b20b5b72e891e47fa378e1c516e5b26cfdd13fb109fbc1d44a7"
    $a1="d760688da522b4dc3350e6fb68961b0934f911c7d0ff337438cabf4608789ba94ce70b6601d7e08a279ef088716c4b1913b984513fea4c557d404d0598d4f2f1"
condition:
    ($a0 and $a1)
}

rule base64_hashed_default_creds_zyxel_nwa_nap_wac_wireless_access_point_series_ftp
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for zyxel_nwa_nap_wac_wireless_access_point_series_ftp. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="ZGV2aWNlaGFlY2l2ZWQ="
    $a1="MTIzNA=="
condition:
    ($a0 and $a1)
}

