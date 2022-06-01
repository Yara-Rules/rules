/*This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as long as you use it under this license.*/

rule md5_hashed_default_creds_ssh_ssh
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for ssh_ssh. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="7d11dab2055563d3747f24cb36b2994c"
    $a1="7d11dab2055563d3747f24cb36b2994c"
    $a2="63a9f0ea7bb98050796b649e85481845"
    $a3="4203e8e192124c82386c9542da4b8b4d"
    $a4="63a9f0ea7bb98050796b649e85481845"
    $a5="ed45840f6a6415ca5eb50ae607e9449f"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}

rule sha1_hashed_default_creds_ssh_ssh
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for ssh_ssh. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="e09771b3cf9fdfceeed0f06bb188e7a2d434e134"
    $a1="e09771b3cf9fdfceeed0f06bb188e7a2d434e134"
    $a2="dc76e9f0c0006e8f919e0c515c66dbba3982f785"
    $a3="6401561d8326540f8d1be2112081432d8ddf62da"
    $a4="dc76e9f0c0006e8f919e0c515c66dbba3982f785"
    $a5="b8fad891d4314ddc31d382ce6a48bd3e3ff135b7"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}

rule sha384_hashed_default_creds_ssh_ssh
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for ssh_ssh. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="0390eaa4c16ec73e0cb8f759a497d30ad449b6f11637c85457a6de0b63e456c863bc991b9cf0f83c373453c7e058cc76"
    $a1="0390eaa4c16ec73e0cb8f759a497d30ad449b6f11637c85457a6de0b63e456c863bc991b9cf0f83c373453c7e058cc76"
    $a2="7ed8c2c790aa83d6c3e404b5368f6832c18d46a0e98b9c7a7a5e3ef823e2c9f0e310abbf6f7ea9d9d883ccb64ec2736a"
    $a3="5e5b054a1371434a3150ff26014bab146b50c563d6ea364b82d72d796197a475c3728cee12a5360def4a10766241f37b"
    $a4="7ed8c2c790aa83d6c3e404b5368f6832c18d46a0e98b9c7a7a5e3ef823e2c9f0e310abbf6f7ea9d9d883ccb64ec2736a"
    $a5="3fe35e481a78c49434a85ead9d705ed62919749d5e766cd2d6ef060127181ca83cd4087b6e11644b2f09a3957fb78c7c"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}

rule sha224_hashed_default_creds_ssh_ssh
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for ssh_ssh. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="37bf6de17154b357dae71719d78e28694183c26fd0999d8cdd23e8c4"
    $a1="37bf6de17154b357dae71719d78e28694183c26fd0999d8cdd23e8c4"
    $a2="871ce144069ea0816545f52f09cd135d1182262c3b235808fa5a3281"
    $a3="9fab6d8895b0e510404321f0a49de91b57954e9eff4fa6a657b4ce39"
    $a4="871ce144069ea0816545f52f09cd135d1182262c3b235808fa5a3281"
    $a5="9ccb03ee072bc1417365a249f925ddff6bf050841749e0ed0e141fe4"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}

rule sha512_hashed_default_creds_ssh_ssh
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for ssh_ssh. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="c27cdede5067848ace0a2fe458aecab174f2d2966fe26f4cb5d5072e3270f2e22bb3f677fb2c16d0bbcaff2f2be76619f91672a4acddf84f8a5fc53af519529f"
    $a1="c27cdede5067848ace0a2fe458aecab174f2d2966fe26f4cb5d5072e3270f2e22bb3f677fb2c16d0bbcaff2f2be76619f91672a4acddf84f8a5fc53af519529f"
    $a2="99adc231b045331e514a516b4b7680f588e3823213abe901738bc3ad67b2f6fcb3c64efb93d18002588d3ccc1a49efbae1ce20cb43df36b38651f11fa75678e8"
    $a3="1d8ae800c77cc8dfbc496582223362557b3215f7e18a22b3b8fb7787b2c02407055d21f6e897d263aa05608259646e064f92606973bce4968e93efb43397c64b"
    $a4="99adc231b045331e514a516b4b7680f588e3823213abe901738bc3ad67b2f6fcb3c64efb93d18002588d3ccc1a49efbae1ce20cb43df36b38651f11fa75678e8"
    $a5="90009d12415ac46a2c7e4492c12bbbb22d7888011ca9aca98ac14837f210e110fc63b991f24f0d51dc4c18245e08cfd2d93380569ca3a00701dda743e9a08a69"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}

rule sha256_hashed_default_creds_ssh_ssh
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for ssh_ssh. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="c802e7c149d5f84c96f2a63f357762db6f170a7c049c9ba6b2f740a6780a971e"
    $a1="c802e7c149d5f84c96f2a63f357762db6f170a7c049c9ba6b2f740a6780a971e"
    $a2="4813494d137e1631bba301d5acab6e7bb7aa74ce1185d456565ef51d737677b2"
    $a3="8f4ecd2e6bbc91770c629b6ad9b5769b744f140b3519b0d37039c369b23eeb9b"
    $a4="4813494d137e1631bba301d5acab6e7bb7aa74ce1185d456565ef51d737677b2"
    $a5="2ea802eeb4485cf32398e8fa1c85d0be431cfa53e21c8cae1e413c628eef2c0c"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}

rule blake2b_hashed_default_creds_ssh_ssh
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for ssh_ssh. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="89c39ca284190a1351ee8acf1166c7afd3cfd9461235cd8f2a9bcf0916f7d58ed61b373b384f5fe6ecd600b214010689c56be2ab4c91dc5ce5a11b87a1bc52b6"
    $a1="89c39ca284190a1351ee8acf1166c7afd3cfd9461235cd8f2a9bcf0916f7d58ed61b373b384f5fe6ecd600b214010689c56be2ab4c91dc5ce5a11b87a1bc52b6"
    $a2="da23f3a4e096b0816ec2070050eac6cd9243240dad0b5cde6573e41d6852939ac5468aa9d81b5fbe156feb231a069f5afe8a5146630abc7807b1e0dcdaeb049a"
    $a3="c8eb5292fab086aa38702ea82a65e78d4ef68b8a5208f053ed64a84c188fec1d3aa9ca3638d83a8a3cd504a39db80691a44741c70ff72a8ae3ebdddff3f7c93b"
    $a4="da23f3a4e096b0816ec2070050eac6cd9243240dad0b5cde6573e41d6852939ac5468aa9d81b5fbe156feb231a069f5afe8a5146630abc7807b1e0dcdaeb049a"
    $a5="31a330e8c8e72bbafd399ac5f50823c0682a5d830acbbe8df65bda0e7a93178e71604d50a9698af12175a35ba66e74dc5749d7991bdbaa638fc9518d3f3f4b12"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}

rule blake2s_hashed_default_creds_ssh_ssh
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for ssh_ssh. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="78c4a646a1e4ceaebf203b20b97935e177253fa7eee54f6b597277570fa5e492"
    $a1="78c4a646a1e4ceaebf203b20b97935e177253fa7eee54f6b597277570fa5e492"
    $a2="0cb8a879dc5d94ed67eb49cc7a4d3052d6a346f2e28fcd9e10e5822aba92eb39"
    $a3="e92ff577401fc80870583c9f437c1b6c3c5ecbb35388f3324469171c4549aeb1"
    $a4="0cb8a879dc5d94ed67eb49cc7a4d3052d6a346f2e28fcd9e10e5822aba92eb39"
    $a5="d65713daf4bfd4cec7b745476c42fcdb7f34045f314f4842f6e47dcc25d27ab9"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}

rule sha3_224_hashed_default_creds_ssh_ssh
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for ssh_ssh. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="b3a9254e676983a7369255af75cfe433b491d4b804d246ebe5819cf6"
    $a1="b3a9254e676983a7369255af75cfe433b491d4b804d246ebe5819cf6"
    $a2="3e42295e89a3a84ce7ee38e2ba317aeb57ca3164459bdf48f4da0e92"
    $a3="74cdde8b29020988c7bb0a05d8ff09c8e35f0e4264b526708800ca07"
    $a4="3e42295e89a3a84ce7ee38e2ba317aeb57ca3164459bdf48f4da0e92"
    $a5="def073a2b31ce23ee32457ab705a51f1abbce8e25c327dfb36c98873"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}

rule sha3_256_hashed_default_creds_ssh_ssh
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for ssh_ssh. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="797275582132afc384a99b71ab73b4490f7c96a838c8ad9db9521d1cdca8d537"
    $a1="797275582132afc384a99b71ab73b4490f7c96a838c8ad9db9521d1cdca8d537"
    $a2="a00e4d3b352e9d11979549b9eef5dc951592f594488451e6cd86fdc4bce76a53"
    $a3="68d1618215a76880a25b217f7d2db83f1af5f57aef6ae5ffe004d25f36d7828f"
    $a4="a00e4d3b352e9d11979549b9eef5dc951592f594488451e6cd86fdc4bce76a53"
    $a5="a214f7312073b63bf1c183534e979b18533771ab290e105043b898942702a995"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}

rule sha3_384_hashed_default_creds_ssh_ssh
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for ssh_ssh. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="049de04e34b19f24d355804c041ffdd7dbb0aafdc60641569ff4837a0d61bd761bfced258bd6fe2e89fcaa6533ba5449"
    $a1="049de04e34b19f24d355804c041ffdd7dbb0aafdc60641569ff4837a0d61bd761bfced258bd6fe2e89fcaa6533ba5449"
    $a2="aac595410801e93eadb099ac575ccc12e43be2c15e31e7991e908329e5beb0729881b3be9ccdb0eeb6eb79335ea38b6d"
    $a3="4ae6f91928b2a42add6d7628ef395d1b9d66900e8379aca8d778048462cde81cbe53ef595ae7ec64d49b2f0adea1a1fa"
    $a4="aac595410801e93eadb099ac575ccc12e43be2c15e31e7991e908329e5beb0729881b3be9ccdb0eeb6eb79335ea38b6d"
    $a5="a741e81d56af5d8d8989246b020b6511ca94eab702c084079afd8a0493d6231f66c3a7ea7a86c37bb61597d4956bb8aa"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}

rule sha3_512_hashed_default_creds_ssh_ssh
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for ssh_ssh. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="c7df725d7cdedc20832ba15a82a093cf057fb949f4ffd411ebaf0eb5433e2b076a62598b45f5fd356d5877ef736d7dca187278b3b419179d4a42257ef600109c"
    $a1="c7df725d7cdedc20832ba15a82a093cf057fb949f4ffd411ebaf0eb5433e2b076a62598b45f5fd356d5877ef736d7dca187278b3b419179d4a42257ef600109c"
    $a2="8cd824c700eb0c125fff40c8c185d14c5dfe7f32814afac079ba7c20d93bc3c082193243c420fed22ef2474fbb85880e7bc1ca772150a1f759f8ddebca77711f"
    $a3="d8cb68884b73300f1d449f3a207d9bcb734683bceca68e22897a1fe793344162fbb0359d89da2b12ece7664715f092e7c24274c8a69ce9cb5ff0b865aa425338"
    $a4="8cd824c700eb0c125fff40c8c185d14c5dfe7f32814afac079ba7c20d93bc3c082193243c420fed22ef2474fbb85880e7bc1ca772150a1f759f8ddebca77711f"
    $a5="830da7fdae27f65e0604953d955bdc20f007c6cbbb2a807cae31d88cef2403516d6c5f7a656f47eafc376cf37127fa824e115f7b34db333904354490edea6292"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}

rule base64_hashed_default_creds_ssh_ssh
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for ssh_ssh. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="bmFzYWRtaW4="
    $a1="bmFzYWRtaW4="
    $a2="cm9vdA=="
    $a3="N3VqTWtvMGFkbWlu"
    $a4="cm9vdA=="
    $a5="YXNjZW5k"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}

