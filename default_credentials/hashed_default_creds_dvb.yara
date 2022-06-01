/*This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as long as you use it under this license.*/

rule md5_hashed_default_creds_dvb
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for dvb. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="931a97d4e0b7a6cad7b026b636fc1756"
    $a1="afb26dc2cc5ad2a31242644d389f6e98"
    $a2="63a9f0ea7bb98050796b649e85481845"
    $a3="e86174b39b51f892689018eed6b68b78"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule sha1_hashed_default_creds_dvb
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for dvb. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="c4a8e0289e730aa527cfe96ae1a7c8870933787b"
    $a1="0812cca9a4c6729136886fcbbe915198f1a8c331"
    $a2="dc76e9f0c0006e8f919e0c515c66dbba3982f785"
    $a3="c932d13a633e1e4f277b52a30f8d3fca065d78f3"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule sha384_hashed_default_creds_dvb
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for dvb. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="619e017f112d67ebdf4d67dd061742453011e99b6ae5e9095d29aa070988600f20a6fda395a9dfae8b23e3577de98377"
    $a1="2db08bbcfa55242de63ce96e05cc22110bff4e2c2ecc6898171a37051b15da0d56aee41080a38149863df759666f7598"
    $a2="7ed8c2c790aa83d6c3e404b5368f6832c18d46a0e98b9c7a7a5e3ef823e2c9f0e310abbf6f7ea9d9d883ccb64ec2736a"
    $a3="200f488374f9e029da0598f3957eddc99e1abb891a079f8aac2ef73362c15bfec6fb1be4ec864e10a8c86fd46fba8dd2"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule sha224_hashed_default_creds_dvb
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for dvb. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="797a05f0affc5c3b906ace2c488039efc648e68c3475172523d1dff0"
    $a1="09b9b4cd7f36d29f1e1de01d0cef5a09f067430bbd7740a1da835a97"
    $a2="871ce144069ea0816545f52f09cd135d1182262c3b235808fa5a3281"
    $a3="98b7ed893a97240bd709bf5701a9d4fdca5033ffb5b3d0a01b7cc318"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule sha512_hashed_default_creds_dvb
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for dvb. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="86c8974bdfd288fe33c01169ad58565ef0fd1b7df38afa96ac26c28647e7d78acfb69edc13b18cd35b5b4763f9aab91cb70c427fa5a621f82e9f6207c3ae7d4e"
    $a1="57965510cedf7d994e59554539cc43a423edc10a04bbd1d0deab5873d9e155eb9f5722559c40ea27a4c6ed012585832dd40a10a2b8f1faec35230066554a0f94"
    $a2="99adc231b045331e514a516b4b7680f588e3823213abe901738bc3ad67b2f6fcb3c64efb93d18002588d3ccc1a49efbae1ce20cb43df36b38651f11fa75678e8"
    $a3="7312a19110e6bcbf4a19c7b284019d058f9c9e9ed891b9138c17818ecfe47c671bba4aa70720f5a58442c60f921a9a925f5273d8a16c66ce6ecd635ec22637ee"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule sha256_hashed_default_creds_dvb
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for dvb. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="d07822d74132acf5f284e2c39f9c549ac635c78fb77b1153c40f82436a9ed237"
    $a1="660c37442e010d523dd3e5f063881cb9d105eb7947ea391a7a539e4c6eaf92b4"
    $a2="4813494d137e1631bba301d5acab6e7bb7aa74ce1185d456565ef51d737677b2"
    $a3="c8a88e9f8851c5aea1cc0e3dbc6d7b91ed905cb6f22b1e8ced66ecf6b2f53f30"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule blake2b_hashed_default_creds_dvb
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for dvb. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="c62fceedf1529641035ec9127a692b908068a07184728ffb9252fa7707edda55a5b3ca48aa52943d4016abbd9709664a399c63c401d2e128d9b77876bbcbf0c4"
    $a1="62f543dcb309f5179725b992c941d218e7d7e41985870407f1a8e898c213e72bd43dd09dfeb403938e5210fc7aa191e30537a57c37232487e1f5ead2dcb23de5"
    $a2="da23f3a4e096b0816ec2070050eac6cd9243240dad0b5cde6573e41d6852939ac5468aa9d81b5fbe156feb231a069f5afe8a5146630abc7807b1e0dcdaeb049a"
    $a3="fce873e6840870a9efde5f6161622900f0e3959f96d920c83266ea4efc269858524fcfdfa74253360c207d4856b1b0f3484cd3773f74fc1326b488d2fd1dc6f9"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule blake2s_hashed_default_creds_dvb
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for dvb. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="945a907fe020fc5f04e699ffadae997dd665d3df6a7a4f3826e29b2b3a11543b"
    $a1="802776b78ceec967d1d731ca9a6048ae12cb9e0a20b5cd38c12ea6bfb1445e64"
    $a2="0cb8a879dc5d94ed67eb49cc7a4d3052d6a346f2e28fcd9e10e5822aba92eb39"
    $a3="8f48be8be75f2f3ca91a7d0f0bd7c742cde781351fb1ee893f72142c88a09c55"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule sha3_224_hashed_default_creds_dvb
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for dvb. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="20e689030580f76c7550158f9a7b5ca9b7aabbdaf68f7cd6c7062062"
    $a1="6eabb31bd4a6a964a540a152c118494e1e3ee55f829783d70c803da7"
    $a2="3e42295e89a3a84ce7ee38e2ba317aeb57ca3164459bdf48f4da0e92"
    $a3="15c8cef27a85855671e82683ddde3439258434200557130c519a2487"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule sha3_256_hashed_default_creds_dvb
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for dvb. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="b7e452aed4a65816040674e4e2578638a62d5b5e8a78784d0907f18cc9ac6c2e"
    $a1="1579f6aa3abf1fa981db85b6ca6617c750d895c5f81bc90b50f51e8c1a1b92e0"
    $a2="a00e4d3b352e9d11979549b9eef5dc951592f594488451e6cd86fdc4bce76a53"
    $a3="329010af6f34016057f927ca0321de7fa1ab8cbccf745f09918fbe018d024821"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule sha3_384_hashed_default_creds_dvb
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for dvb. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="3a33307afd768c1c5a32081b38e6ac2b2f10453c27f60802cd9088374eec4bff7abc227e9418242653f4a6e8d632b8c0"
    $a1="cb706c3e31df148cc49564c39065f6f88d1414a31ba9e682fd7cb36509d06dccd3c7b6036d08ad4c23ac59ca13b05c40"
    $a2="aac595410801e93eadb099ac575ccc12e43be2c15e31e7991e908329e5beb0729881b3be9ccdb0eeb6eb79335ea38b6d"
    $a3="88c3f3ba017c5ed9cfac15e6ac246719d23396bb7b0e7cb1ea8b8412acaa4e37b5e034eff76755231de977c153f8d052"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule sha3_512_hashed_default_creds_dvb
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for dvb. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="456152b8228074e349bf22781a0a8d924a1e69ae310e858069ae3bb1ca6def46dcb4df26878f786bd38da6fba4bef465e0496bf9471e6932ce13378d793174c2"
    $a1="9e30751de33626e6341e086cfa027a5347b36677acaa2325ff8d8b879f681bf41ce5c12b8564d4bd1478239ed5633ebffc7ebbcb1cd407ec585ff46c90788572"
    $a2="8cd824c700eb0c125fff40c8c185d14c5dfe7f32814afac079ba7c20d93bc3c082193243c420fed22ef2474fbb85880e7bc1ca772150a1f759f8ddebca77711f"
    $a3="0388d2b0d6427d3c7ba6a5c5f31b293ac90603bf73590971047f56733c52dcc7b1dc7b0bda35458ef6281a13b809223892fb1c94a70c657d09628514efb1d69c"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule base64_hashed_default_creds_dvb
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for dvb. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="ZHZzdGF0aW9u"
    $a1="ZHZzdDEwbg=="
    $a2="cm9vdA=="
    $a3="cGl4bWV0MjAwMw=="
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

