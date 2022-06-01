/*This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as long as you use it under this license.*/

rule md5_hashed_default_creds_memotec
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for memotec. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="d5055515aa324fbf6497d8ade35de679"
    $a1="09348c20a019be0318387c08df7a783d"
condition:
    ($a0 and $a1)
}

rule sha1_hashed_default_creds_memotec
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for memotec. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="6a96650a61f5f64649b20202239702079d1cc9b7"
    $a1="0f4d09e43d208d5e9222322fbc7091ceea1a78c3"
condition:
    ($a0 and $a1)
}

rule sha384_hashed_default_creds_memotec
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for memotec. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="e4f142111a4f88b6b4645cd82e3438fc501b1e8337093914024aacffeb7dd6324b38784398a830b7663bdd82ba124ba9"
    $a1="6cbe8fc7bd50b262e822d039459015cb5f4fc3255a86d3fd14c81140153dc714b24bb7a2e2159842415aba43e63b3189"
condition:
    ($a0 and $a1)
}

rule sha224_hashed_default_creds_memotec
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for memotec. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="6a0385d88ec7667fb93f71241f2448ad2470bf5716fa6d4848e68611"
    $a1="64cd35385184bab91d1f394b3f64e935fd4bc939333c486a70d9a946"
condition:
    ($a0 and $a1)
}

rule sha512_hashed_default_creds_memotec
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for memotec. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="2f59d72adf16294638014c138e6a478ce303370ddea1c1e85eed05e9c93dd0b9ed07e7af8dfcf72fcae423406bf1f1ef207ed3173312ad8f631878232da02533"
    $a1="abe6267e41571ad4632231ccab1936e34c91ee389b02bcafe90a6391012bba585138edf92ccf349a451722d8236937fc26fa22c1edf0f9de6851bc96a9a13b82"
condition:
    ($a0 and $a1)
}

rule sha256_hashed_default_creds_memotec
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for memotec. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="c2dd62dc3c825209b1a778fcbc258109a5c21d87d4dcf43955bb6839cc82be1b"
    $a1="0834c2d60725ac5902257b3b78dd161ad26d1c0290dbf1e47cc14add5b8c8142"
condition:
    ($a0 and $a1)
}

rule blake2b_hashed_default_creds_memotec
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for memotec. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="b22293d80dff73f0aa7602df414813f4469a2640b32392a7d71e58505050cd0d730c2e2d31ab37450ab2b1f0f5bfe15f0e5b9d708bc3835187740b189b602848"
    $a1="4cb52c5f42cfbe6a67675d1aba438a50b6f411071de6380d17e89856d99f476c560b3ba2da418eb3dc274a6241fc53b1a0307d7146964b73e953bbd4b58d8837"
condition:
    ($a0 and $a1)
}

rule blake2s_hashed_default_creds_memotec
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for memotec. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="350ad36ebc32b36e6c25b9177eb3992c76d3d9e9c14b8c859e4a87c69f6873ed"
    $a1="c417c6a97cf0da54c21c5214ff25871cd5298dc953f5e8c8c517659eadbf44a4"
condition:
    ($a0 and $a1)
}

rule sha3_224_hashed_default_creds_memotec
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for memotec. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="dded9a065206aec7902554721b4ca626f34d559116dfdb032d92bcb9"
    $a1="d263b1a42751fec04f7d158f17d618e58e278ecf7ada3dc66c3e097c"
condition:
    ($a0 and $a1)
}

rule sha3_256_hashed_default_creds_memotec
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for memotec. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="9fac138b2a4571e1571fed9f2f6177c455208b06e44fa7a42c34bbca13aaa399"
    $a1="90e6263244bbac7413c1947f2306e13af65ee6507c6d46e3493b276ecc098871"
condition:
    ($a0 and $a1)
}

rule sha3_384_hashed_default_creds_memotec
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for memotec. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="26e75f9a61ee723256f9282bc6379729b59ab1c7184b09cfa0cb4ec6067dd0e1f787cbd3614e5757600aaf065b4ecceb"
    $a1="ca7f171379319d935814bfed6f0a11570dfd7c07821d890236d052e4e77c588f521c851ee9020113bd58bfceae0bd338"
condition:
    ($a0 and $a1)
}

rule sha3_512_hashed_default_creds_memotec
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for memotec. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="2d72065ad97118d01a63a450cf087dd4b997ccd34fda25758197d1b27c724b78a7ce2f8f360bd6e5ee96383e624ca8d8fc056a966e96bbddfce211e7d6e893f3"
    $a1="d7fe5e2e1ab20da6becbbbd478b7ef4d3d28fbda00f8f66a7881e2794d413b5e5bea54ee5667f7136554eb35115d91d7a8c830b9895a383a13ea4874d8dad25f"
condition:
    ($a0 and $a1)
}

rule base64_hashed_default_creds_memotec
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for memotec. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="bWVtb3RlYw=="
    $a1="c3VwZXJ2aXNvcg=="
condition:
    ($a0 and $a1)
}

