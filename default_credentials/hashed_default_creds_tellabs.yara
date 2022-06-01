/*This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as long as you use it under this license.*/

rule md5_hashed_default_creds_tellabs
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for tellabs. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="63a9f0ea7bb98050796b649e85481845"
    $a1="a7d0e7a977456f60aa36706acc7f5fb5"
    $a2="2f1e9ae7e6a2f97a21c19fe4c3007a54"
    $a3="8954462dc06d12348e2ad32f4ea8d25f"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule sha1_hashed_default_creds_tellabs
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for tellabs. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="dc76e9f0c0006e8f919e0c515c66dbba3982f785"
    $a1="318998ce9cf1a7a05865b60d7a44438ce70bafed"
    $a2="4bf4982f17517951a1c63a646784fd323cba242c"
    $a3="5fb413a404020014a4077b14f950a635f08129d3"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule sha384_hashed_default_creds_tellabs
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for tellabs. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="7ed8c2c790aa83d6c3e404b5368f6832c18d46a0e98b9c7a7a5e3ef823e2c9f0e310abbf6f7ea9d9d883ccb64ec2736a"
    $a1="629d925ca42d071cac10e75427bcbd031d4f4f0d83ca3639400a335990ec7a1707ccd5671050fd4ba2f9bf88cd08689c"
    $a2="f24c2cef56c88200fd45a92ef453979e510e6979aa37a2a16eafe3d27a2c8fbc8d82b4ad8102e590c645b806ca8b1f02"
    $a3="0e754d5204dbebc67da1d279fbf89a6ae7000c0d2c12c802a42a99cc94c80a16ab49b346c7a118b5dacbe4fd88cf3f70"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule sha224_hashed_default_creds_tellabs
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for tellabs. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="871ce144069ea0816545f52f09cd135d1182262c3b235808fa5a3281"
    $a1="596787a6e6f508a97179985eb9083ca2eb2e2c517cbbf02ac1b356aa"
    $a2="e4f5be939b82f85e3389ab75249d927663839b0b9b918621d0e4e353"
    $a3="ad6dad1e4ed2144e4f47689e3e8e24b6b3c8daabf7fbded0aad67da2"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule sha512_hashed_default_creds_tellabs
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for tellabs. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="99adc231b045331e514a516b4b7680f588e3823213abe901738bc3ad67b2f6fcb3c64efb93d18002588d3ccc1a49efbae1ce20cb43df36b38651f11fa75678e8"
    $a1="a6093490b11cbba15ec004d1c7da133c8c38c0a0c8ab34c3bc9d786bedabc3b24578393717f4edce5a84688192a283fb7950c0f00bd56964d1b0be5bd7c7cdd1"
    $a2="166475b7cac12238c4cbb69f4c91d93b0fd2bf7ea3f09bc2002fadc74254a338880011630a3b6f714bb5116bab775c381bd457256c5d992f7526deb9d13ff60e"
    $a3="af2db999fc4948fdc482d48032d00a445911e2a26eb865291f424dffe3d563630913fab7b558cd83e38ce19f7e8676dbb9f4f3889b7299480920656912ccb3c1"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule sha256_hashed_default_creds_tellabs
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for tellabs. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="4813494d137e1631bba301d5acab6e7bb7aa74ce1185d456565ef51d737677b2"
    $a1="fa0fdd6f1c979d680cd19cd9a6c7b78cd1422ff0864f2de7e33d2798676723db"
    $a2="dc4921803d0d37b86b27dd795b0bf3a7c9ac718d64a1ff002780c9963fb32c3a"
    $a3="f0d9e2e1e43a963b440989efa139e558d12600d61a12de05ffc6d24ad04f5024"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule blake2b_hashed_default_creds_tellabs
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for tellabs. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="da23f3a4e096b0816ec2070050eac6cd9243240dad0b5cde6573e41d6852939ac5468aa9d81b5fbe156feb231a069f5afe8a5146630abc7807b1e0dcdaeb049a"
    $a1="84a754518520b30aa5bc6d084dc27ed6f9ab11ae414cae081d88bf0bbe5e60f8e5f2ee9b56f9b99cc52ff2d62533001d74f101dc3bb3b64973bf36701be1e952"
    $a2="8cc5ef0e16c1d5a69f0f7d7a54234e59b465c589a57e98ae993f305934f550eec092ab6023e7e162040ed7342ce054f9d1f8a93f174b1d3153adda60fe8ae819"
    $a3="642e7c08a1ad6fdbfb1ef8fdadec06861eff496ce58bf46b0fd486451e8bf1452834c3e2514a0c033426ebffe426d5076a9663cde30892ad6e2f70620ecd93a1"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule blake2s_hashed_default_creds_tellabs
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for tellabs. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="0cb8a879dc5d94ed67eb49cc7a4d3052d6a346f2e28fcd9e10e5822aba92eb39"
    $a1="677c0e1c8b881a4688b8c5408d7ca3761b0645652e9a7b40b855b80c5e6b501c"
    $a2="7ff965229dd79bf1fe3f663af4ffe50b247b0df3014b13f179ecdf8d2e675510"
    $a3="e20bdfecc0ab442df3491a771ededf5b8ec5c04e012019ab92b1aa1e12ed3d62"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule sha3_224_hashed_default_creds_tellabs
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for tellabs. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="3e42295e89a3a84ce7ee38e2ba317aeb57ca3164459bdf48f4da0e92"
    $a1="11699ce18203656dff6ccebf5d653b40442d5c5b8e2275e7177558e4"
    $a2="a7c1230f0e830d904dde62c173a576987afa7ee61d2789945c691b29"
    $a3="32d9800b7c38b56625cd7939e35f030933685cc89b856898bd81760a"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule sha3_256_hashed_default_creds_tellabs
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for tellabs. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="a00e4d3b352e9d11979549b9eef5dc951592f594488451e6cd86fdc4bce76a53"
    $a1="0616fc6541f2b8164099fb077d17ef9eeb5cd92872898298942db8acbcee0600"
    $a2="531c19f116fd82c8d06fe23171e1db63a0a252224337ec26b3fcdd39394783c6"
    $a3="61fc5eb531971522373c05fbb7d50ef2fd5eed08b841135e78fbdc2cd19a5927"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule sha3_384_hashed_default_creds_tellabs
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for tellabs. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="aac595410801e93eadb099ac575ccc12e43be2c15e31e7991e908329e5beb0729881b3be9ccdb0eeb6eb79335ea38b6d"
    $a1="63a2a65b7d53ece73c12a70ff421f6fab0649409b38a637347fcc9748f9258815270bf1f9be9747f26be4f476352602a"
    $a2="0226f5cdea11c457a06b5cf875ebba4ef9a51758d7dd8b78295924b26b686328fb10a15e41526e7edfae7c5aceb2638b"
    $a3="49f9bc7942e610c6029edb4e99577d184cdefd67be95a5c3f0513e6b2057ce79f0d9b91d1bfd0f9c03f1bb9f39cea00c"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule sha3_512_hashed_default_creds_tellabs
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for tellabs. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="8cd824c700eb0c125fff40c8c185d14c5dfe7f32814afac079ba7c20d93bc3c082193243c420fed22ef2474fbb85880e7bc1ca772150a1f759f8ddebca77711f"
    $a1="f73bc61e5e901a9bc89e72d464e4fe18eeb41c4e25c00cd2f0e5e7a450b237632648e2ccce32b26e615236622c8f611a470a9d48df757b6636ef504974f20039"
    $a2="e2699b363ba2601552e587119d477f359e5d14a9cbe62fb0d1d7c74b1b084cf84cf1ce556e0d1fe9d280aa207f40e7e7575cd689cc70c4362c3552c256f26061"
    $a3="dc04911c76e674867cd3f71778b8dbeea1ceda90d6cfd0054db2ac81a399238820c9aafcbf92d3e4cfb8551c1d1ccd7bea1b9eb0d7914a019ac3b01d6e7c2cd4"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule base64_hashed_default_creds_tellabs
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for tellabs. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="cm9vdA=="
    $a1="YWRtaW5fMQ=="
    $a2="dGVsbGFicw=="
    $a3="dGVsbGFicyMx"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

