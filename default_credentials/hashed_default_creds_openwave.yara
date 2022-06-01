/*This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as long as you use it under this license.*/

rule md5_hashed_default_creds_openwave
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for openwave. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="cfe5d2ebf969d01706383177e6c1e8cb"
    $a1="6c9726ad3881a0d88125e1d0ee15dd76"
    $a2="36bcbb801f5052739af8220c6ea51434"
    $a3="fa09be8aa44a4075cbf13a8a2319afc9"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule sha1_hashed_default_creds_openwave
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for openwave. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="8bcd0d793e5c24d3fbe6f2cd73f3dc8962696db9"
    $a1="3c89849a005943e2be242cc820cdc3f87a7ad47c"
    $a2="b4c56ee8d2854166dec66644f541b85247105b2c"
    $a3="81c64e156f5dd267d0df3d0934099771a1171b81"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule sha384_hashed_default_creds_openwave
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for openwave. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="249585b6e8a1b8a22548a6c73507b3310fbe648e8dc92c8e725d7fdcec4ccee930f2df5c5569fec07a06dd8943b4b779"
    $a1="4002f99dfcc7297be64076e6a204c24c45e26ff29df305ced73e66730c297bbd503c417e1022f914f36a7c761d885799"
    $a2="8a7c455d373266f5528ca765beadf67b8cd9df1f8c3fcfb5fdbd7541d0a4a389eb39360fb6439f474cf0e538101df97b"
    $a3="ff428ec7d2ee6edea31648f7ab027313a465dc192539909745999815b94fdcbf246a5be48a0a661cd235a1fe01ea2ecf"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule sha224_hashed_default_creds_openwave
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for openwave. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="3a418de52c68aba860a624226c0d7688c0065cce087b26a9a2620ce7"
    $a1="d21a5001b684045b598c50be9122da36b93c99c0998d8b54c81738ec"
    $a2="31a97dd618f14542b2694706a865537fc1303f3072c8cfd61369cc9f"
    $a3="3bd4ec8f039e6eb9a1a288e594c8a3c22b66ce51f8d5a919f2e90c73"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule sha512_hashed_default_creds_openwave
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for openwave. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="91a55e21d14029542872b51658931194ca4b0fa4e33518ae38b16ce4ea5eadde6a7c5f6c7587f7449d861c15bc92c70ac9b1c82d60f91753a03f6ea52982084c"
    $a1="3721e62bad7215d7a3bd33a0c4fda8a2523d026cf320656c5820ee8ea89447a3e01f05ca430c1a9abf721d4b3f4574dd02cbecaa32deafac2ef59ab73fe41d4b"
    $a2="0a67db7f97aeccbbad8cede443d8cba9cd66d3935d47be40b48a93cbb5a1afc61bbf0bae8a8c9654c0789284151da1ccdce97e30034a8e0414db08f512a8366e"
    $a3="e932a76e25d20898510036173c54b53c2d99aef0a50cf8effe45285d25faa5325ee4118e5311cc7a08d26bb0fff26198da62695363250b1f5cd56d7559dcafca"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule sha256_hashed_default_creds_openwave
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for openwave. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="aa79f11221e25ddb870233c5ecb79eb1c341d1b67db1ba5273f68076982efee4"
    $a1="d7df0cbb692fc1fd64f987a0548664a6a5e6ff09f7c55510aff3311b4ac034da"
    $a2="518b67e652531c5fe7e25d6b2c3b4ef6224e7d90da2091967dd47eb082b26a19"
    $a3="c2fa26d57cd69ed4cf86f1a9cf8f0232cc20b24387e3299aa267224722bd31ef"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule blake2b_hashed_default_creds_openwave
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for openwave. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="b94e69a3e35abd67287cfe7ce14365a291a60ba853349a36c06fdcae2acb5381fde7464165620ed5deb1ee51d5d04111ef5f417764a44204953ba02bbdd4675c"
    $a1="6bdfea23f165ff59b09e6fb66b3dffeb00191604c2b4dc66d4c19ad2cf95a22fd09de06c5824360bcdd3546f1480b6815a83cc325225ce16277108adefe96a99"
    $a2="f100c65b0d6bcfedac6fba6625e7705217433b4759a70287da5a5153bbeb5c23df492b60360d6d5b3efb5faeda2f626836b6c76d89d7dc7ca902aad40ae3abeb"
    $a3="c975a3db7aee7e1177ce9a4889821ac43b33eff458b0bbb1a6986bff776d286f9934f9d23eadbbec4991d05a131142c2586e9051a4b200ddfd0bf028d1571507"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule blake2s_hashed_default_creds_openwave
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for openwave. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="ee017dfd76a6969bcfb09b3d8ae9a383c70db976d24e997c23cd771e978dadce"
    $a1="c9fc23fe383d94a682ce7a660ded8f49bcadd21f0afdbd2ee45bece27b06bf62"
    $a2="b7a48923c6d9fedb521d303597779f531e1c2b667b5f128bb9a61d840292111b"
    $a3="7fa8279adfcadd4bdc7502a0393e8f27bee43445b268bec343c81d14a943110c"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule sha3_224_hashed_default_creds_openwave
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for openwave. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="0a2c4b97e0dd6cee80df33d66d07f4146cb1a37e8c5c5ef25daf17cd"
    $a1="f7e2c9df64e128b71efa615cfc7e79cfc66bd5ca6fae0414ce862de7"
    $a2="b31e6c41b571759de5fb9d4b5a59653bbdcb345000ccf982be94ece5"
    $a3="358e3c6529cda6548d2e592ad4716d219df5f6b712cb249ebf37e82b"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule sha3_256_hashed_default_creds_openwave
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for openwave. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="7d2f5fc2f92429cdb7f9e504896b6e776567cd5bc8906460b724562219b93713"
    $a1="e8d5a6d907c60a4b195d31867ac037819446197d7e3d8a0ea5f9f8cb14d66f8c"
    $a2="2440602c0d1c3adbb2ee9485506eed4b1ec0f20bcca3ea2ddbb10a351fe85911"
    $a3="a2e706707e353d09147b7de375589d26f2153ee706b38a48433e7e90f0b44a4c"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule sha3_384_hashed_default_creds_openwave
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for openwave. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="6e13691fbf307e304df38ed5642ccedd28d9bc7fcc0e199845e2aead16380ded2e7061a6c2e684411b6d307d6ba06c78"
    $a1="5c81e5a16deda72d7a26d62812b8de9ee35ef007af59616c1a0de71bb325f44f958a4825e294f0a10e7ffbd45de06326"
    $a2="f518f8c6ec3a806a5ad3cec99463383f94edf16486960bd62882c11ab7b75cac1f512ec2f5b8dbef497db829643c4418"
    $a3="857530910f65a899885215258b9b560c2f98fc3dcee68bf3aaf710827d4835b5b4f48ba03dbbe618360deca6bebd7236"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule sha3_512_hashed_default_creds_openwave
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for openwave. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="bb203b3b09c81104473b47f394ebf05282d7249507c1ca3d296f6474ffc303d8f2e6d5c780fcce55262fc25e83c248441940966f523f13416f9aa658ce01d1e9"
    $a1="0de24605e83f581c178b5a46f0ee6e503fd58524825aa2f1ba85016044e6e28d59bf9634af903072defd03ebeb0d6e52275c7f363422f34237051a43e36542c8"
    $a2="ff21aa55877cf49c500a8b286a5e430cd92140fc466facbf1797cf9674c38a6a2d7d7d45b69d87f76710e16f33c3b37858aa9d802d22a824578fb56c61e6ace6"
    $a3="a9c97c57ba97619b12af9c65080abe9aefb0f42166fc7f7dcdc4161c1e6cc20fcc81428d0f222ef7e2c5e8b4349978055440d4e3442d3e77a052ade2e4530988"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule base64_hashed_default_creds_openwave
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for openwave. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="Y2FjX2FkbWlu"
    $a1="Y2FjYWRtaW4="
    $a2="c3lz"
    $a3="dXBsaW5r"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

