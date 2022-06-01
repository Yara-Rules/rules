/*This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as long as you use it under this license.*/

rule md5_hashed_default_creds_wonderware_historian_mssql
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for wonderware_historian_mssql. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="9cf2903aac6bf5fa28745eb7ece79c0f"
    $a1="47efa148b3f2428ae072e2a66c779e53"
    $a2="038315ff8406b92d4ac9af43f1cc3fec"
    $a3="b105e7225fca404e542be5811a128e55"
    $a4="4606b4ad44b3a29a938ca4bae57abe08"
    $a5="a1fc0b4dc4eb11d1b8fffeb489b6157c"
    $a6="18fb3358c071e8cafc01472c04f9460e"
    $a7="e86f1924366d5e2d9bede7e97584760b"
    $a8="59a8add95efb4a6974aad6f7580a13f9"
    $a9="59a8add95efb4a6974aad6f7580a13f9"
    $a10="e0d3878bf82d4523590533b4f3973f39"
    $a11="e0d3878bf82d4523590533b4f3973f39"
    $a12="f0fc6dc45ccea5e53fe9e0d96cf565af"
    $a13="f0fc6dc45ccea5e53fe9e0d96cf565af"
    $a14="a99accb226354ab7230fa3258b03c4f5"
    $a15="a99accb226354ab7230fa3258b03c4f5"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13) or ($a14 and $a15)
}

rule sha1_hashed_default_creds_wonderware_historian_mssql
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for wonderware_historian_mssql. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="d9e8b295d2eb1aa8badfc258482dd064ebf92ff6"
    $a1="a32e0a88c1f082a3ab01b7ae773837f140083ba9"
    $a2="3f8d5bfb7fa75368b10d133fd615c91934b92d73"
    $a3="ce5831dfec31a90fe7a84444759c4c9c499f1d65"
    $a4="961398f8244c637b356df3ee9f968d348647f998"
    $a5="af04c88eef7d55a2ab7ca2555a1a4e31e25e0224"
    $a6="d636c59b5c3d7b509bd6c34a0b8d0c3607e9da45"
    $a7="350488fdbc51b2886cad9ac8ccb3cb8645f2ed15"
    $a8="cd95b28596f76196eda1286610d56439f70dd211"
    $a9="cd95b28596f76196eda1286610d56439f70dd211"
    $a10="23e01ff4f8c6bb030580163e6cfa9eeea63a8ad3"
    $a11="23e01ff4f8c6bb030580163e6cfa9eeea63a8ad3"
    $a12="7e0bb7f3ac2d6be75e678cce8288ffeada8194f8"
    $a13="7e0bb7f3ac2d6be75e678cce8288ffeada8194f8"
    $a14="b23abdbfc08e798d808012c78489422516d351ea"
    $a15="b23abdbfc08e798d808012c78489422516d351ea"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13) or ($a14 and $a15)
}

rule sha384_hashed_default_creds_wonderware_historian_mssql
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for wonderware_historian_mssql. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="2fb69b2d385e7196ba91de9a3e7e742ba3bbc8f6222ffbb82d1fb8fadcc958fb407e502e7f854274e0d5acbac94c5db5"
    $a1="c9106418b7268ae6d2b144fa2c9717db01f0ee711f2cf9ce5ebad193a0db994e58e0c3a03c5863db47c332eb8523c4bc"
    $a2="3b06a18d2b9855194737b9ffb04c212580745a4b7083d2d568ee053ac95bcce28b3e06a555dc5774f6e0cc3e34c3d37a"
    $a3="745c22ae2124abbb3f9c5728f558a6459d9d44e9f0323f0afa476ce00550ee8de2d4da7d7e696ed91f1e426e113f21bc"
    $a4="60ce97a2c551bdee852a1c59d57c53cad060444d02a9381e78cd51a7647c0aa9927b6dd92a821af9ec50305453dacaad"
    $a5="2d44c39e6f6d3c8d4ff8e12ac88553ac84d6297ce2d8fc58d4f0dd5ab71926bf3d77c31648ab1c1e452558dfe2198658"
    $a6="1625953ac77768ab52e08c1a0b33a7c43c072c83f0fa2fd2902a7f4cb01790a31f08ced9e603d389fccf61404b50c21d"
    $a7="6de70fa1acb5959f6a02c6c8585f296f69e13acd4f377a8494e87b3c6fa3bf9878cd4469793160ae605c3c1ef7c4ae3e"
    $a8="bf6cb307ac8955eea5459612ff2a17e7808fff58482791402d7a98fac06b77916dab480bc313ac00e6f941db8c589f8c"
    $a9="bf6cb307ac8955eea5459612ff2a17e7808fff58482791402d7a98fac06b77916dab480bc313ac00e6f941db8c589f8c"
    $a10="b631fb6c0c99a65c097c71a142923677fc223777c71a2d078a12dc302b90503b43ad560198317e740ab63062c1c3bdb5"
    $a11="b631fb6c0c99a65c097c71a142923677fc223777c71a2d078a12dc302b90503b43ad560198317e740ab63062c1c3bdb5"
    $a12="a14f03985a6982cd8befc3f6036d49dbcd0c594914d7c9b07b1f477f44228ab921a9367b3375a99050582aa3100fbe2d"
    $a13="a14f03985a6982cd8befc3f6036d49dbcd0c594914d7c9b07b1f477f44228ab921a9367b3375a99050582aa3100fbe2d"
    $a14="7fb6fe26b59f3602d48700381502f16e11a967d2ef4f09f3fe034a3e5438973f503915987918115e4975bffd6a5201f5"
    $a15="7fb6fe26b59f3602d48700381502f16e11a967d2ef4f09f3fe034a3e5438973f503915987918115e4975bffd6a5201f5"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13) or ($a14 and $a15)
}

rule sha224_hashed_default_creds_wonderware_historian_mssql
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for wonderware_historian_mssql. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="e0fba95c78422a27da775fac5ffa7b12595706af743a972287525dff"
    $a1="e7722bf002f04a50aa431e9d2509be7a28079ed8aee30961cc51c16c"
    $a2="5dd84d598e1fbf855a6de10d3223bc5e6bd714b99581aa026573c85e"
    $a3="63f04a68a327b6932ed60c43110bd8ed0e39c14b1bd12916a466dd43"
    $a4="a71654a85e969f14c3b640d5ffb80839798f781da5cc48b56e6b4069"
    $a5="fc8d606085bed264d006738011b0e22fb4ea894d04b0fcba0d006b1b"
    $a6="81e3cc97d51e5a49aaefea6ad781b08e4d073e3ce710d7da8a240d65"
    $a7="56290555e3f7818843439ad1388d385bb6330a856d2e9885933b1b6b"
    $a8="130fdb05e9a014dc6377a02f571d914636b011dcc3faa5aacdd49acc"
    $a9="130fdb05e9a014dc6377a02f571d914636b011dcc3faa5aacdd49acc"
    $a10="a9dfe45f992cbd82199e9e2db80f1590a1ca2a156e39a072870ce3cf"
    $a11="a9dfe45f992cbd82199e9e2db80f1590a1ca2a156e39a072870ce3cf"
    $a12="6f44726875df2af55ec5aaf012405225fc0f800c2ed5f389cb0a2d98"
    $a13="6f44726875df2af55ec5aaf012405225fc0f800c2ed5f389cb0a2d98"
    $a14="459bb46d2724b116ccc41f91d996f4e45309852a7b0468f79e03924a"
    $a15="459bb46d2724b116ccc41f91d996f4e45309852a7b0468f79e03924a"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13) or ($a14 and $a15)
}

rule sha512_hashed_default_creds_wonderware_historian_mssql
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for wonderware_historian_mssql. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="a27b82d438c06c590c354c65d77b953c0e6354374e8329939799fb5171b2e98594e8a9d0d7431e58bb97bca73f4802708203ed2ce87ed30ac8e0e12e6c8062b8"
    $a1="b771c14f6bf62ec126dc1f60738dda85e27aabe3015b4020bae2339f7513c1242ba9d997d0156453ab8249ce2f83ad4a467060c0ef4058011135d3b3788bdf4d"
    $a2="6ad7ca6a4d658f1037328fa49f621177c93479365615d319ab066a0280d8ff99b1aeac20460fb42c83ff35d16dccb7bf403875744991f01147efb6b11c50ae2f"
    $a3="9ba58388a06a998218a59a7cd4139cb7764c18e7319584bced2f69b40e8c97e17d6668e24f8e0ddc03db69429121c509aefb2dc40beb271df1c340f7bc858060"
    $a4="40c23c700019a1a6055008987cae4a89388f9dda17feb6566e655f92330e771bff0dd42c618b9c32793943a7cf501af7420c0ba4cdf58794f28d353720fb260c"
    $a5="f358f9b4dde032dff082adffba125b6cd6273abacf49ab376f83090e29896b3dc3270a09b6d051702affe9b20b3c45baa94358210945e0c58ed8ed3c5074910c"
    $a6="cbcc6f76b85e7f7f1e6876e45f8c5988fd60bf4adf33219744db428b58ccc932ca473aa16c0c84e077c84f4458d1ea3c07ecd9b7c9b0b38e2d40473a8ea588ad"
    $a7="6107bc7dae0430be5f8994259f65c2535fc110102b0fc6426b49c8b84b22c49c62733504096dd79b9e1e315af945872428613a6e6a1b44a0474fdfaded96de5a"
    $a8="0ccd8a5e286c335e66ca1a32bdac7970776f05eaad0337630ce0ec9aa1c762a7d605bddf38c20f81df7674fa521bf4b3fa1bff5ec6cbac9da924c7bba3ee66fa"
    $a9="0ccd8a5e286c335e66ca1a32bdac7970776f05eaad0337630ce0ec9aa1c762a7d605bddf38c20f81df7674fa521bf4b3fa1bff5ec6cbac9da924c7bba3ee66fa"
    $a10="f97403da71afcaa05882cb0370788c25988fb5ed3c9f1f13fb35fe5f5a6f7d5e14e82ab392230c30ec540ee48cd6820863bf33859973d603aa56ca92aea3b1b1"
    $a11="f97403da71afcaa05882cb0370788c25988fb5ed3c9f1f13fb35fe5f5a6f7d5e14e82ab392230c30ec540ee48cd6820863bf33859973d603aa56ca92aea3b1b1"
    $a12="970fe108e3c12b7f8687ae9bfa117fb8debe9650afd53772f5e81037fd598badf5ffce6f5dd05c8a5213fc5ba1ba156da1bf11bc965a3d5db9b5d9c1d6e0e91c"
    $a13="970fe108e3c12b7f8687ae9bfa117fb8debe9650afd53772f5e81037fd598badf5ffce6f5dd05c8a5213fc5ba1ba156da1bf11bc965a3d5db9b5d9c1d6e0e91c"
    $a14="dd415d4940041d6f196d1f3712e69cf2e333dd5a8272adc08793e0c5e68855371ba0d876124a4e6a797bab7f33397a52eff0fdeb739a91e80a8481bd53a47af4"
    $a15="dd415d4940041d6f196d1f3712e69cf2e333dd5a8272adc08793e0c5e68855371ba0d876124a4e6a797bab7f33397a52eff0fdeb739a91e80a8481bd53a47af4"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13) or ($a14 and $a15)
}

rule sha256_hashed_default_creds_wonderware_historian_mssql
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for wonderware_historian_mssql. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="304f5570bb8880141c743d863ce9305fe2b73da60e13a270203e8f87cf9116d8"
    $a1="47795cf8a5bab85fdedbf59fe1fd0666f91d3debd678d65855a4648e4ac2bd47"
    $a2="afe9fb4f15084c8a4dc6ae159ccd5e7815f9b2cd6abf9b3dc4d26944124fc3ae"
    $a3="cd8a927d23e14be7c437d984d32aa10136de8bc62cab864e592179731459d1b7"
    $a4="6c9f53a141ba564aee5da913fddcf10f9d7563eb5c4275eada8dba67cef57bd5"
    $a5="a9dbfc5ca2ce76300ee508d4c435bbbd1ed876044b403601a744183bdee9c242"
    $a6="97db57936ca2f82fad9c8bce485bb06bfd2b4edfe4bd8de50a3ea2ec0452d9e2"
    $a7="3489cf442b78530bebdf7759763c03b833523ecc671068f435f2ac1bd008c7b5"
    $a8="c92187d4f3cbe43aa7a7e35365a0b3f471eb64dd86b917dc46698fd552363dc1"
    $a9="c92187d4f3cbe43aa7a7e35365a0b3f471eb64dd86b917dc46698fd552363dc1"
    $a10="a89d8073c999553ccb80f1f3eff81358c2c47a2645e32947aec9769cc0983b0c"
    $a11="a89d8073c999553ccb80f1f3eff81358c2c47a2645e32947aec9769cc0983b0c"
    $a12="1c644aada850130e568f31e646f78ef65c3408b77f67bbe676f7516ebee599e1"
    $a13="1c644aada850130e568f31e646f78ef65c3408b77f67bbe676f7516ebee599e1"
    $a14="37c40d18a79eddabbafdecd7e79cb5fbda5af5be7a30cf3c5e124a325711050b"
    $a15="37c40d18a79eddabbafdecd7e79cb5fbda5af5be7a30cf3c5e124a325711050b"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13) or ($a14 and $a15)
}

rule blake2b_hashed_default_creds_wonderware_historian_mssql
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for wonderware_historian_mssql. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="932abfe220cd831fa3b7b4cdc5f7fd9198471522c654309d80e7c24c39ae2969a903555f163969742049d32f5d7cb9546447cd17743d4771b124bcb54495d97d"
    $a1="d1c1e05ffd45f3a281d9372947745ff9999f8340ff38414aa138487df84973ffba50e47d8d06f735526be7749ed51715d11c01123971f508954056dbbc3c62d5"
    $a2="25d92b87b7b2f81e3f7a2e6e80680ee7f33b7dd02904c88003633fd723d78265f8ad6ed610812fd4e3916532e6eaf9b353a574c2ad95b05918e452c6aadf426b"
    $a3="96647166937dad004f1e51893f349cd0ccac1153a4798dc052c590d5e7cfca6660b2e26fc3c0cd669d61abde4f564acdb9ca5204844e0ca838ca41322509e1b4"
    $a4="0fcc0b0bee7ea1924c4a33360a891a623488306b0bf0d506c708b6cc2f3723c317112326218da096b1b0e676fde0677738704a0746871e13d54886c41501d717"
    $a5="6b29c448b603c985e7869e30778bb14421b9c661fefb3ba8894c4482ea0ce6996f1ed2c7bd9209f74175b8f06ac19ab433e9888930064312b1f22d888751faf8"
    $a6="2aa39980656c770455ace9d06d82799dd08877ba46dec1e31b6bf303ae95316d12a1e0f394a6c92f4566ef223ba18e004d41aecf32f1475d0ecbe32488415440"
    $a7="0c3ca0b20dd53e2821df49de05c8e747d1388db0364f0329531529aff4466c4397dedb39c2bff1e2223e684b4b56f920ce8b9b16c94861009ef225c6c818c1e2"
    $a8="cf60598f6e5ec91e21e55d976a490de13eea658b88372219bcfbef5eaac003f908203478b2923aee5abe9a7f872a38ffdb52d9784d3ec588448b2dd1b917b100"
    $a9="cf60598f6e5ec91e21e55d976a490de13eea658b88372219bcfbef5eaac003f908203478b2923aee5abe9a7f872a38ffdb52d9784d3ec588448b2dd1b917b100"
    $a10="353ad966ee863d7168ae6ba7c61bc7d0376fe7186b606e0940419c8fdace080860f3368cdda4a4496b8f26bdfb53fccd35eb678831d65404fcaa6ef5570be78f"
    $a11="353ad966ee863d7168ae6ba7c61bc7d0376fe7186b606e0940419c8fdace080860f3368cdda4a4496b8f26bdfb53fccd35eb678831d65404fcaa6ef5570be78f"
    $a12="7e5ede737cc0d9f5a9855cc8af91d8e06aafaed45f9dde67376d95e0ef8c340a618ace1748453d816f6c3154339f8ab687f241a751db0db4df8b37d57a0732e9"
    $a13="7e5ede737cc0d9f5a9855cc8af91d8e06aafaed45f9dde67376d95e0ef8c340a618ace1748453d816f6c3154339f8ab687f241a751db0db4df8b37d57a0732e9"
    $a14="96c6dce3c943eb168d5ecef050b1203b6d35786b9207b7dfb0941d6de7fd84bba97265a080c8939b2d9fd4b91e24f07f5806c1e222fa4dc93c7fd6315f500643"
    $a15="96c6dce3c943eb168d5ecef050b1203b6d35786b9207b7dfb0941d6de7fd84bba97265a080c8939b2d9fd4b91e24f07f5806c1e222fa4dc93c7fd6315f500643"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13) or ($a14 and $a15)
}

rule blake2s_hashed_default_creds_wonderware_historian_mssql
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for wonderware_historian_mssql. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="6fbdca481f278ddc7f88d56e9f6e017e55d36c39f65ea1b0de9a3fd6e79974de"
    $a1="51409de7ad1370d5627c5661929c84eef6b08adf9f59280c59b44fff06fbdda1"
    $a2="34f5e5e28f39b758f8ef27a17724b191dc497e8b0b36d17a72aac98e36b576c3"
    $a3="326a7d2cd8a336fbc3878baf1a04f0ed954ab91c94fc4dc4b74729ed68d4d9e3"
    $a4="b73d8fb89e3e4769176f578c30fe3b8b5c5fd11f8014c4633bfa4e33f08de540"
    $a5="b09da05e04eed57dba48ef2735480a2890291392d192e7fcc5d13c0c411ab135"
    $a6="f6dc614f47820b7a8a201f096ed59784438bc66a9e5449bdb4e6f47eafb20cfe"
    $a7="aa605078e1d730da3720365b2ab000c4db9407b05e22accf60daabbde552abdf"
    $a8="406f0ed7696a6cb6cb457b6fdd8fa62e895d8e35e1670c454217ff91ad887a25"
    $a9="406f0ed7696a6cb6cb457b6fdd8fa62e895d8e35e1670c454217ff91ad887a25"
    $a10="5c50e191819ff413748babed9a676dda695c15e8782f91e097df1270ad8de052"
    $a11="5c50e191819ff413748babed9a676dda695c15e8782f91e097df1270ad8de052"
    $a12="252635526fda32206f835dd6c0ea42cc80ba5b4ab4dfeaffbb494fe24498e010"
    $a13="252635526fda32206f835dd6c0ea42cc80ba5b4ab4dfeaffbb494fe24498e010"
    $a14="e52425250b93ac717b41a15a15a865757fa64c9dbd228cfa3702cd858b3fe3d9"
    $a15="e52425250b93ac717b41a15a15a865757fa64c9dbd228cfa3702cd858b3fe3d9"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13) or ($a14 and $a15)
}

rule sha3_224_hashed_default_creds_wonderware_historian_mssql
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for wonderware_historian_mssql. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="5b8a21522fd9c5943185a7cf664fa54d13874de698c37a7788b9ba08"
    $a1="655918ba3de9edd2326de5717f2e295b39316ab3aeb0cd591b03a720"
    $a2="3f4438b1bfcd14db5b28aa8ce48ae06535c693ac58b027866af42194"
    $a3="8247c391f970009190b3c05269aa85b7a390bb981aa8458ee08bd9dd"
    $a4="54769524522a438f1574030fc30218c0c0a1b87ad6de70baf9f84800"
    $a5="d0af7a190d65b40c637510e78fa157d81e0429dc78754a8e29dafd46"
    $a6="d9a2ed0b27b99f419f6b650dcc5a8e12860a045b8cb110a07a31e8c3"
    $a7="f082620419b995858d6c70fdb4715f5c4eb24fce8c756f89cd0c7b04"
    $a8="77d638eba71b3a227d38c49df0c712b5c68a6485acd0d99984fe254d"
    $a9="77d638eba71b3a227d38c49df0c712b5c68a6485acd0d99984fe254d"
    $a10="5f0d218895ef0fecf829d5a48e9b29d8d30bd5c223a0451eaec27004"
    $a11="5f0d218895ef0fecf829d5a48e9b29d8d30bd5c223a0451eaec27004"
    $a12="9750d6ed0c417ba3bdef3eaebb9c6477ea554ba77086ce0293055d7f"
    $a13="9750d6ed0c417ba3bdef3eaebb9c6477ea554ba77086ce0293055d7f"
    $a14="11010051c4f6f966c5b789d7b51d433f27617bb27989688e50820245"
    $a15="11010051c4f6f966c5b789d7b51d433f27617bb27989688e50820245"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13) or ($a14 and $a15)
}

rule sha3_256_hashed_default_creds_wonderware_historian_mssql
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for wonderware_historian_mssql. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="48e2cdeddf65361fce7c46d45f601da5a9cfbbee7a4481a803fb69ae41d0d049"
    $a1="7e5c4ebec5420ea402ba8852589b32600272133f8fd417bc7d2e80afb87d9945"
    $a2="1a22edd2d67f9a1d30f5d0cd841bd89da3ac7c2e3c6222de727cc5e71a690629"
    $a3="d0005fa4a909d9c74dbc2a081a5ff45873448731191ce58f28276bad8cf0e524"
    $a4="0d1710652d53d8fe368f121c2024d013df81927c576411f2b895f763ae951d61"
    $a5="61137f36b4d307be286ae43f5bac090e280e3a1fabef1515e102479c90125b52"
    $a6="44d71ba52326358323263aa6c0a17672d44c846ea2aadc296b7d0190f46a441d"
    $a7="7e5c1765ec7a0273b580973d95ff2eb72f11141a1870a2b6d18c3b73a59d0fd4"
    $a8="ed15e9a9e067e35a498c0eb101828c41b8f006e616d8ec4fff6ce6fe711deec1"
    $a9="ed15e9a9e067e35a498c0eb101828c41b8f006e616d8ec4fff6ce6fe711deec1"
    $a10="bd4164a0e5e807d15a54087ec2ecb5472332bf4b906fd38bdf003f47a80d26ec"
    $a11="bd4164a0e5e807d15a54087ec2ecb5472332bf4b906fd38bdf003f47a80d26ec"
    $a12="31e2667321aac1c32078772ce0cd450c192a07e82f9fbf86845be34af261a365"
    $a13="31e2667321aac1c32078772ce0cd450c192a07e82f9fbf86845be34af261a365"
    $a14="2d7c82ec02ede80acbf8171b965439c45c5dc8a2e4a3f9eac24425c4579429ba"
    $a15="2d7c82ec02ede80acbf8171b965439c45c5dc8a2e4a3f9eac24425c4579429ba"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13) or ($a14 and $a15)
}

rule sha3_384_hashed_default_creds_wonderware_historian_mssql
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for wonderware_historian_mssql. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="6f9a9fdc7d7b5246044db1763aa24004f037ede2d51c811b6f0d920c3e6c529e4b972c9152892ca4f89a8e41b15fe116"
    $a1="ff30133501f6e021c8522e859a539054e0c5687be48078e0dfdec7a27e39cc1ba4bd9cd5a823acf59106f659c4991f23"
    $a2="465cb17b0721439b7300e4a15ef6dbea00adb9fd83b771db27ce7ca18fd02b99e124d791d37ee8f6e15aaed682bf18a5"
    $a3="2c3065e4f1752aadfbd3310d789685da6153be80162c7354fd2cb3916bd1219fb5d3623d4190be1fd4d57bf834ddabbe"
    $a4="816b2d96d13982ff3fcdafe3350b518de8bba9ff846abf0e5174798698a0a188d6cea0a4f6a3fa9cb7886fc821d41b8e"
    $a5="71d5542491db8c3c1bf16a70b52ecfcb6befa8f839886f4de91f684d27eb9a88189d8720a1fc9c90343bb32ae06c6c33"
    $a6="dbcd9ce419de210b5a6b7d25cc22b0ebc885a0a26848cbd3d0c41681248310818633e4b39775881f3290a54378ae5cde"
    $a7="b59ba699558c17b82c7a9435692291af1bc574c7fcc9a338d9882bff4df733ec0ae5cc700e56ffbfd6f5a371f00e15e4"
    $a8="9e4ebdcd2cfcd32fe22b92cf375b7e5a20f78bb95be8ad917dd9f4fdaae682bb1d8a3b95ddf33ce8344a6eb3ef2c3d8a"
    $a9="9e4ebdcd2cfcd32fe22b92cf375b7e5a20f78bb95be8ad917dd9f4fdaae682bb1d8a3b95ddf33ce8344a6eb3ef2c3d8a"
    $a10="ae9dc843406ba66e6c1a9bb7e578a5776e5bb4ae3e99ea44c5a921f51cd08675edf78e98f7a74b045f7c9c7c1fbf416c"
    $a11="ae9dc843406ba66e6c1a9bb7e578a5776e5bb4ae3e99ea44c5a921f51cd08675edf78e98f7a74b045f7c9c7c1fbf416c"
    $a12="9573f16637b9daa84dad3f4064cfbadee2f2790541b804d3e7c19d4b8d5ca16684bbcb1a5c8a71bbbc8d75363e88f05d"
    $a13="9573f16637b9daa84dad3f4064cfbadee2f2790541b804d3e7c19d4b8d5ca16684bbcb1a5c8a71bbbc8d75363e88f05d"
    $a14="fa2c9e767d3703086d289f145e76d82936f3ca1a94ff4bfa4fae0679a1f180e2cc6277408ab865da831f7945fc3ab39e"
    $a15="fa2c9e767d3703086d289f145e76d82936f3ca1a94ff4bfa4fae0679a1f180e2cc6277408ab865da831f7945fc3ab39e"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13) or ($a14 and $a15)
}

rule sha3_512_hashed_default_creds_wonderware_historian_mssql
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for wonderware_historian_mssql. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="984f8ad241aa596b695538ce3a5815cb8b75cdf87b34b1e7906d43e58dc96820c9c318afcfbe12b831f5e2ab98593af3985abce589a0746614caab9df3876e9c"
    $a1="88d5d2e85e64b89ae2d15cb81a1cb32c103bb5bf22e96df4841578a0ac108fb50d48d8dfeeafab9a848a07af9b68e6da5443d4b9b67aa165ebd3375ba84020ba"
    $a2="1db3d23f9d03d1955698c98968f5f06223acb1dcb55706dd43698dbb57d40d220e763238328841eba9219aaeb88b5bd2072748b18d5c4f6512f0bf8370fff9cf"
    $a3="8c581aab5237bab71a1c3d6047ad32a842acea079287555a19d417351bf74a1ad0d33d608efe8650e2136ed386c6dfe6915878483c92fddd69759d8c47d0ee80"
    $a4="6b548c74eb1cc959f6203d02beb7ee57b93a470cffc79a0984e2b5cfcdb6b96824706dfd498cb8a5a2d9de56893e68d7dc214fa0582fc645e9ede58dddea2a7c"
    $a5="12facfe624b97ebb17ec8ee049582d5c1c4b06af8f48b205c7d9bc5c25fa7ae12394fed6da1070827bc42a479f45a4986c360533e9c90664f2216cf6518e2c9d"
    $a6="7400ee86e9ec26ebd88f4b9d950e808b6ead36690f7e2505d7babe0c23a49dcf44ae346332e1d7691120b2f6a745e5243862157d3112821aadbdfb5ab697afa7"
    $a7="7abef5154be564d5c01b086595251be5ed857b65a6fb54bccfb55945e8f22195bd44d6c02ebffa66887fb0a9205784e86947cd6ae4bc1fe7690ece41ba957e67"
    $a8="1849ea9a31d62cdcd93808a2217b782705617f740a63e1e23698aeb8b0263cf4059d710cd1fd0db34d9b3a43ed7936365fd57a0a50aca9340ce1db262191be86"
    $a9="1849ea9a31d62cdcd93808a2217b782705617f740a63e1e23698aeb8b0263cf4059d710cd1fd0db34d9b3a43ed7936365fd57a0a50aca9340ce1db262191be86"
    $a10="2b491ad7e03e6c59960d9d37e4800857b963c618d0bb6e175ec17d6e5d6d5a945e36929e5e42ad45c0914c89c94f822284f33aecf135c9368f3e0f2a7d2d656b"
    $a11="2b491ad7e03e6c59960d9d37e4800857b963c618d0bb6e175ec17d6e5d6d5a945e36929e5e42ad45c0914c89c94f822284f33aecf135c9368f3e0f2a7d2d656b"
    $a12="835177b2932f2522fe068b2abf7eb3cf267ec47d5e644b30e142e00d0d23bcc62135f5aa0b47b0a0920967bc73f133c327f37638443923b4557fe9a77eaf6755"
    $a13="835177b2932f2522fe068b2abf7eb3cf267ec47d5e644b30e142e00d0d23bcc62135f5aa0b47b0a0920967bc73f133c327f37638443923b4557fe9a77eaf6755"
    $a14="dd568ed1f071c04b3b4c35a893d3fbb0ec7cb53172a259cd36e4a78cb0de65cba25a95f03b450315fdb37ab226b4cf386f93e84b13d18c0d47932c2b629d6fe4"
    $a15="dd568ed1f071c04b3b4c35a893d3fbb0ec7cb53172a259cd36e4a78cb0de65cba25a95f03b450315fdb37ab226b4cf386f93e84b13d18c0d47932c2b629d6fe4"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13) or ($a14 and $a15)
}

rule base64_hashed_default_creds_wonderware_historian_mssql
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for wonderware_historian_mssql. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="YWFBZG1pbg=="
    $a1="cHdBZG1pbg=="
    $a2="YWFkYm8="
    $a3="cHdkZGJv"
    $a4="YWFQb3dlcg=="
    $a5="cHdQb3dlcg=="
    $a6="YWFVc2Vy"
    $a7="cHdVc2Vy"
    $a8="d3dBZG1pbg=="
    $a9="d3dBZG1pbg=="
    $a10="d3dkYm8="
    $a11="d3dkYm8="
    $a12="d3dQb3dlcg=="
    $a13="d3dQb3dlcg=="
    $a14="d3dVc2Vy"
    $a15="d3dVc2Vy"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13) or ($a14 and $a15)
}

