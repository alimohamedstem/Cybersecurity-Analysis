rule unknown_threat
{
    meta:
        description = "Rule to detect the SSH-T and SSH-One malware files"
        author = "Your Name"
        date = "2024-07-13"

    strings:
        $url1 = "http://darkl0rd.com:7758/SSH-T"
        $url2 = "http://darkl0rd.com:7758/SSH-One"

    condition:
        any of them
}
