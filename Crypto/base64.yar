rule contentis_base64 : Base64
{
    meta:
        author = "Jaume Martin"
    strings:
        $a = /([A-Za-z0-9+\/]{4})*([A-Za-z0-9+\/]{2}==|[A-Za-z0-9+\/]{3}=)?/
    condition:
        $a
}
