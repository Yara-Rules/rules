/*This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as long as you use it under this license.*/

rule md5_hashed_default_creds_crt
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for crt. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="caf8b369a673f825333ccf59ecd7bf5a"
    $a1="962ef1c7550b790dbe222a01fd187111"
condition:
    ($a0 and $a1)
}

rule sha1_hashed_default_creds_crt
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for crt. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="dd1c8dc0f179aa574e5c58735adff62420d26c79"
    $a1="3c5a3775de70777b13e690e4ae3a2cacddfffa20"
condition:
    ($a0 and $a1)
}

rule sha384_hashed_default_creds_crt
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for crt. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="bb4fa1e408c1d9a1b46af7126729b13cbd8a01e705bc6e26fc59b2a7de2e90b43991c792c4089438a4473bd5f6fa76cc"
    $a1="b6292b11d918f502260601e43758bee89204d42c3fdfdb63a4e05aab43447031cca7d8a40b117ba6d71a9d2cb07b19dd"
condition:
    ($a0 and $a1)
}

rule sha224_hashed_default_creds_crt
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for crt. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="74cf1b20bb5eb3edd11ea546fb7877010f06424fac89d6d7a18f7337"
    $a1="2a6a900c5d7d1e2af4bca459a8cb64fc291ab877662ce19321f5cb67"
condition:
    ($a0 and $a1)
}

rule sha512_hashed_default_creds_crt
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for crt. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="831baff160a608ef921ade3231a30d1f3d7a87f0919e20d84800be442f72e8b850e8d9af9b18e4f98f63f7d8594ebc04311d158159d6ea661f49c2a950504368"
    $a1="b515a451324ff35cd55224f390cad6f1d9606c3678e164eeae19875b5444f9c3feefc792b02edb1b8c9b73e90964b484febc51650b2513aa4d99a48b5f0616a6"
condition:
    ($a0 and $a1)
}

rule sha256_hashed_default_creds_crt
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for crt. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="fd4d53fe3f8b48ad75c7284e049507af5ef766bbe95c63b027b639639b09ec06"
    $a1="282a07ca6622ee1a0905ece84b4fd7208efdb66576669ac05425462b446bee05"
condition:
    ($a0 and $a1)
}

rule blake2b_hashed_default_creds_crt
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for crt. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="09aa5f344a91d156cdeab4c5705a35bb5cec4eba1120b1e3d6041090c4703be0a7de8276e496824d0001b627732edd236a50023c658731bc0a201e792b15f16e"
    $a1="089ad4a1f4542a5c787202aca7d2c866d642fea04b2095079516e854b279cc873c8954526ed54491e4af8ce4f9b9169b41128bb49969797c77fbeb99782b94de"
condition:
    ($a0 and $a1)
}

rule blake2s_hashed_default_creds_crt
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for crt. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="d2f099740be00c8dd0971a63f041892d448cd7d1e396b37ddaaa938278b530fc"
    $a1="c87f12938122af1870b0ebda9f9064d6d882e1a43fbfb90819ea4e287d9b8ebb"
condition:
    ($a0 and $a1)
}

rule sha3_224_hashed_default_creds_crt
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for crt. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="8ba39e850472e658663e9d702df887c9184787ee97dba5530e79c4fc"
    $a1="0aa5e0e76168c09026162393243476ff90e02d498e8450d337dfa817"
condition:
    ($a0 and $a1)
}

rule sha3_256_hashed_default_creds_crt
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for crt. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="7f73672fbffe44a89b1c6ab318ccadd20db8333e1ddc63d6fea69346b68ac6a7"
    $a1="680130426ecff5860a526f7ec156cb4f6fc41ddd0a3b271010753a0900610dff"
condition:
    ($a0 and $a1)
}

rule sha3_384_hashed_default_creds_crt
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for crt. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="b7b9ed8b52ae23af2a8623b24d27356b7056c9be59fd5ed63910b2c59149528462f6869bca3606cdb566b64984eea323"
    $a1="4989b42988dfd06632c28aa8737106a17f7103a60a6ea68c6ce9719e33ca6f9dcd72eae891bbf2b6386e3681942e3bfc"
condition:
    ($a0 and $a1)
}

rule sha3_512_hashed_default_creds_crt
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for crt. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="c9fbb6fa8c4f01007aff7d72821cc14c4e4ee104f4d45ce27775279bdbb39e6bb1bd5b9e2984c08674541271398f1087e749138f3a9d47a20ffa480996d0e2cc"
    $a1="58857c71301907ac4669cf8f78d4c07e570e2e8257740d08ad7f5426a999546d54a1696ad6d70988982d840b4c78dd750f212c4dfd495e0a2ea2234359d3720a"
condition:
    ($a0 and $a1)
}

rule base64_hashed_default_creds_crt
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for crt. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="ZWdjcg=="
    $a1="ZXJnYw=="
condition:
    ($a0 and $a1)
}

