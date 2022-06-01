/*This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as long as you use it under this license.*/

rule md5_hashed_default_creds_ibm_imm_web
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for ibm_imm_web. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="7541ef28f697b02fb3a3643b686655a9"
    $a1="5732fec825535eeafb8fac50fee3a8aa"
condition:
    ($a0 and $a1)
}

rule sha1_hashed_default_creds_ibm_imm_web
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for ibm_imm_web. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="ef223734af130519fb71edc32fd5d810c72afbb7"
    $a1="6f64cf089e9ab22113e0dd69b7f5eb45637b0d48"
condition:
    ($a0 and $a1)
}

rule sha384_hashed_default_creds_ibm_imm_web
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for ibm_imm_web. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="efe32638d64bd159be83959149ee6c0ef02b4d84d6568e1131a285770d49e46d062748dae2790509abfd834722040f8b"
    $a1="95bb8661afd7e9483a41818e8e87b82952bae3dc0fae7f05a65418a902579907623d806bcf2a99ae4260fe5c5566d015"
condition:
    ($a0 and $a1)
}

rule sha224_hashed_default_creds_ibm_imm_web
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for ibm_imm_web. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="9c2a01fb33a8c19c12922465913c0a3144481cdac1d8c4847d474ee2"
    $a1="c717ab75684b694907f0031473bc4a5820a0a9d3e27105b34c4ef9c7"
condition:
    ($a0 and $a1)
}

rule sha512_hashed_default_creds_ibm_imm_web
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for ibm_imm_web. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="0907d458d75760dc66e4add0227e76af23b8234fc35ac908673f847e13fe51192a8673b9a818af4c12d53904ca1e707c69fdd856a1f716e864f18ad32ed64978"
    $a1="6e1c00887d820074eb1ff6971ef581715e3c18c75f1b43f5786b6d6c45798286d39176d2d75ec392d65ecb1b059c385a1c73719cbe634f352098c3a9b94cb2b1"
condition:
    ($a0 and $a1)
}

rule sha256_hashed_default_creds_ibm_imm_web
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for ibm_imm_web. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="0d9fed9bd1ee63b55cfb1a695f80a3d11caba9477f3d7ac39d18ec3f11dc696d"
    $a1="edd878f94bafc7a4e96cf4fafbc9e9cf7bf9b846382127a001a3149f654c4d65"
condition:
    ($a0 and $a1)
}

rule blake2b_hashed_default_creds_ibm_imm_web
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for ibm_imm_web. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="af3e42e32f9fce311a555271da2b8ddd790a0b996eed9fa7dede54b488e001f05d54fc43175dbd6b0208c786c317dcb187542ec01aeef8aef5072dd43a11b3d8"
    $a1="17f2a5ce43340ecd940b40392b47e8c42978735c5d4db42aca7012b1997c3f82eb6b77582be3545b1cb292af4446be8d6bcae893da0f87a2f33423a217eb23ee"
condition:
    ($a0 and $a1)
}

rule blake2s_hashed_default_creds_ibm_imm_web
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for ibm_imm_web. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="d58ed7560e7a0cb80b317d66c3104fe78481ffdb3fe6a49bc8156e2176f79a1a"
    $a1="57dc47a9eb9becb8d558024404ab271631aec582eebb5b6076b0ada9ef2de835"
condition:
    ($a0 and $a1)
}

rule sha3_224_hashed_default_creds_ibm_imm_web
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for ibm_imm_web. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="9af5b794e95ee053339664b53d6d6a3edb218f68db58905bb8eb300d"
    $a1="6b13988ba352729f77059ba0757ef9c4820c529ac180dd4a53453dcd"
condition:
    ($a0 and $a1)
}

rule sha3_256_hashed_default_creds_ibm_imm_web
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for ibm_imm_web. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="845750e3bb2cfc044e696f341bb0da69acda35a455684b1263ca42283de3c1eb"
    $a1="60f349f5bad61d210f325ed6daf7675c951f02eed941597e493b20c318a470c3"
condition:
    ($a0 and $a1)
}

rule sha3_384_hashed_default_creds_ibm_imm_web
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for ibm_imm_web. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="60ed6bc722a6111382af19977117beb97c865bfccc87cdd9824c86a9d369d14127441c45a064e402166f9341af68276a"
    $a1="c5fe84ed23b8e644aa5982e5b53dff806f3bf2a2c227717e36e3587565b1620593a9717b934d842607df82fb8ece06a3"
condition:
    ($a0 and $a1)
}

rule sha3_512_hashed_default_creds_ibm_imm_web
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for ibm_imm_web. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="3e73b2c6a80a10e2c19d5d5333bd5ad2e26df2ad9ab4047595dd3922d8bb26ae6d41fd7e648e7a28ac3b0ccc643b034a911608da2a362385a8608240601abd52"
    $a1="efc03c23d9d9169696dd61e13190c9afa71026fdfa0b2dad03db08caad052e38212baec007daa497aec6f35b0834fcb7cf856524743a1ca35ac59fa8787ab464"
condition:
    ($a0 and $a1)
}

rule base64_hashed_default_creds_ibm_imm_web
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for ibm_imm_web. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="VVNFUklE"
    $a1="UEFTU1cwUkQ="
condition:
    ($a0 and $a1)
}

