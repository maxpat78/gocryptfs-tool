#!python3

"""

   MIT License

   Copyright (c) 2024 maxpat78

"""

# Requires pycryptodome(x)

import argparse, getpass, hashlib, struct, base64
import json, sys, io, os, operator
import time, zipfile, locale

try:
    from Cryptodome.Protocol.KDF import HKDF
    from Cryptodome.Cipher import AES
    from Cryptodome.Cipher import ChaCha20_Poly1305
    from Cryptodome.Hash import SHA256
except ImportError:
    from Crypto.Protocol.KDF import HKDF
    from Crypto.Cipher import AES
    from Crypto.Cipher import ChaCha20_Poly1305
    from Crypto.Hash import SHA256

S_AES_GCM = b"AES-GCM file content encryption"
S_AES_SIV = b"AES-SIV file content encryption"
S_AES_EME = b"EME filename encryption"
S_XCHACHA = b"XChaCha20-Poly1305 file content encryption"

ZEROED = bytearray(4096)
EZEROED = None

class AES256_EME:
    "AES-256 ECB-Mix-ECB or Encrypt-Mix-Encrypt mode (Halevi-Rogaway, 2003)"
    def __init__ (p, key):
        if not key:
            raise BaseException("must pass a valid key")
        if len(key) != 32:
            raise BaseException("must pass a 256-bit AES key")
        p.key = key

    def _decrypt(p, s):
        return AES.new(p.key, AES.MODE_ECB).decrypt(s)

    def _encrypt(p, s):
        return AES.new(p.key, AES.MODE_ECB).encrypt(s)

    def decrypt_iv(p, iv, s):
        return p.transform(iv, s)

    def encrypt_iv(p, iv, s):
        return p.transform(iv, s, 'enc')

    """Transform - EME-encrypt or EME-decrypt, according to "direction"
    The data in "inputData" is en- or decrypted with the block ciper under
    "tweak" (also known as IV).

    The tweak is used to randomize the encryption in the same way as an
    IV.  A use of this encryption mode envisioned by the authors of the
    algorithm was to encrypt each sector of a disk, with the tweak
    being the sector number.  If you encipher the same data with the
    same tweak you will get the same ciphertext.

    The result is returned in a freshly allocated slice of the same
    size as inputData.

    Limitations:
     * The block cipher must have block size 16 (usually AES).
     * The size of "tweak" must be 16
     * "inputData" must be a multiple of 16 bytes long
     If any of these pre-conditions are not met, the function will panic."""
    def transform(p, tweak, inputData, direction='dec'):
        "Main transformation routine"
        T = tweak
        P = inputData
        if len(T) != 16:
            raise BaseException("tweak must be 16 bytes long")
        if len(P)%16:
            raise BaseException("data length must be a 16 bytes multiple")
        m = len(P) // 16
        if not m or m > 16 * 8:
            raise BaseException("data must be from 1 to 128 blocks long")
        fu = p._decrypt
        if direction != 'dec':
            fu = p._encrypt

        C = bytearray(len(P))
        LTable = p.tabulateL(m)
        
        for j in range(m):
            Pj = inputData[j*16:j*16+16]
            PPj = p.xorBlocks(Pj, LTable[j])
            out = fu(PPj)
            n = len(out)
            C[j*16:j*16+n] = out[:n]

        CView = bytearray(16)
        CView[:16] = C[:16]
        MP = p.xorBlocks(CView, T)
        for j in range(1, m):
            CView[:16] = C[j*16:j*16+16]
            MP = p.xorBlocks(MP, CView)

        MC = fu(MP)
        M = p.xorBlocks(MP, MC)
        
        for j in range(1, m):
            M = p.multByTwo(M)
            CView[:16] = C[j*16:j*16+16]
            CCCj = p.xorBlocks(CView, M)
            C[j*16:j*16+16] = CCCj[:16]

        CCC1 = p.xorBlocks(MC, T)
        for j in range(1, m):
            CView[:16] = C[j*16:j*16+16]
            CCC1 = p.xorBlocks(CCC1, CView)

        C[:16] = CCC1[:16]
        for j in range(m):
            CView[:16] = C[j*16:j*16+16]
            C[j*16:j*16+16] = fu(CView)
            CView[:16] = C[j*16:j*16+16]
            C[j*16:j*16+16] = p.xorBlocks(CView, LTable[j])

        return C

    # tabulateL - calculate L_i for messages up to a length of m cipher blocks
    def tabulateL(p, m):
        eZero = bytearray(16)
        Li = p._encrypt(eZero)
        LTable = []
        for i in range(m):
            Li = p.multByTwo(Li)
            LTable +=  [Li]
        return LTable

    def xorBlocks(p, b1, b2):
        if len(b1) != len(b2):
            raise BaseException("blocks size must be equal")
        return bytearray(map(operator.xor, b1, b2))

    # multByTwo - GF multiplication as specified in the EME-32 draft
    def multByTwo(p, s):
        if len(s) != 16:
            raise BaseException("input must be 16 bytes long")
        res = bytearray(16)
        res[0] = (s[0] * 2) & 0xFF # force 8-bit
        if s[15] >= 128: # if negative byte
            res[0] ^= 135
        for j in range(1, 16):
            res[j] = (s[j] * 2) & 0xFF
            if s[j-1] >= 128:
                res[j] += 1
        return res


class Vault:
    "Handles a gocryptfs filesystem"
    def __init__ (p, directory, password=None, pk=None):
        if not os.path.isdir(directory):
            raise BaseException('A directory pathname must be passed!')
        p.base = directory
        vcs = 'gocryptfs.conf'
        config = os.path.join(p.base, vcs)
        try:
            s = open(config,'rb').read()
            assert len(s)
        except:
            raise BaseException('Unaccessible or invalid '+vcs)
        config = json.loads(s)
        # supported characteristics
        p.aessiv = 'AESSIV' in config['FeatureFlags']
        p.xchacha = 'XChaCha20Poly1305' in config['FeatureFlags'] # v 2.2.0+
        p.plain_names = 'PlaintextNames' in config['FeatureFlags'] # names are not encrypted
        p.raw64 = 'Raw64' in config['FeatureFlags'] # unpadded base64 encoded names
        p.deterministic = 'DirIV' not in config['FeatureFlags'] # per-directory IV is default
        # LongNames are supported when a long name is found
        p.longnamemax = 255 # limit to switch to gocryptfs.longname
        if 'LongNameMax' in config['FeatureFlags']:
            p.longnamemax = int(config['FeatureFlags']['LongNameMax'])
        if p.raw64 and p.plain_names:
            raise BaseException('Raw64 conflicts with PlaintextNames flag!') 
        if p.xchacha:
            EZEROED = bytearray(4096+40)
        else:
            EZEROED = bytearray(4096+32)
        assert config['Version'] == 2
        assert 'HKDF' in config['FeatureFlags'] # or it should use directly the master key or its SHA512 hash (SIV)
        if not p.xchacha: assert 'GCMIV128' in config['FeatureFlags'] # mandatory v. 1.0+
        assert 'FIDO2' not in config['FeatureFlags'] # actually unsupported
        p.config = config
        if pk:
            p.pk = pk
        else:
            scrypt = config['ScryptObject']
            block  = d64(config['EncryptedKey'])
            kek = hashlib.scrypt(password.encode('utf-8'),
                                       salt=d64(scrypt['Salt']),
                                       n=scrypt['N'], r=scrypt['R'], p=scrypt['P'],
                                       maxmem=0x7fffffff, dklen=scrypt['KeyLen'])
            key = HKDF(kek, salt=b"", key_len=32, hashmod=SHA256, context=S_AES_GCM)
            # 128-bit nonce + payload + 128-bit tag
            nonce, tag, ciphertext = block[:16], block[-16:], block[16:-16]
            aes = AES.new(key, AES.MODE_GCM, nonce=nonce)
            aes.update(struct.pack(">Q", 0)) # AAD: 64-bit BE block number
            try:
                p.pk = aes.decrypt_and_verify(ciphertext, tag)
            except:
                raise BaseException("Could not decrypt master key from config file: bad password?")
            if 'EMENames' in config['FeatureFlags']:
                # generate the AES-EME key to decrypt file names and the decryptor object
                p.ek = HKDF(p.pk, salt=b"", key_len=32, hashmod=SHA256, context=S_AES_EME)
                p.ed = AES256_EME(p.ek)
            else:
                p.ed = None

    def encryptName(p, iv, name):
        "Encrypts a name contained in a given directory"
        bname = pad16(name.encode())
        if p.ed: bname = p.ed.encrypt_iv(iv, bname)
        # python base64 module does NOT like absent padding!
        bname = base64.urlsafe_b64encode(bname)
        if p.raw64: bname = bname.strip(b'=')
        return bname.decode()

    def decryptName(p, iv, name):
        if p.plain_names: return name.decode()
        dname = d64(name, 1)
        if p.ed: bname = p.ed.decrypt_iv(iv, dname)
        bname = unpad16(bname)
        try:
            bname = bname.decode()
        except UnicodeDecodeError:
            print('warning: could not decode', name)
        return bname

    def getDirId(p, virtualpath):
        "Get the Directory IV related to a virtual path inside the vault"
        if p.plain_names or p.deterministic: return b'\x00'*16
        rp = p.getRealPath(virtualpath)
        if not os.path.exists(rp):
            raise BaseException(virtualpath+' does not exist')
        ivf = os.path.join(rp, 'gocryptfs.diriv')
        if not os.path.exists(ivf):
            raise BaseException('No gocryptfs.diriv in '+virtualpath)
        iv = open(ivf,'rb').read()
        assert len(iv) == 16
        return iv

    def getRealPath(p, virtualpath, isdir=False):
        "Get the real pathname associated to a virtual one"
        if virtualpath[0] != '/':
            raise BaseException('A virtual path inside the gocryptfs vault must be always absolute!')
        rp = p.base
        if p.plain_names:
            return os.path.join(rp, virtualpath[1:])
        parts = virtualpath.split('/')
        if not p.deterministic:
            ivs = os.path.join(rp, 'gocryptfs.diriv') # root IV
            iv = open(ivs, 'rb').read()
        else:
            iv = b'\x00'*16 # zero IV
        n = 1
        for it in parts:
            n += 1
            if not it: continue
            ite = p.encryptName(iv, it)
            if len(ite) > p.longnamemax:
                # SHA-256 hash, base64 encoded, of the encrypted longname
                hash = base64.urlsafe_b64encode(SHA256.new(ite.encode()).digest()).strip(b'=').decode()
                ite = 'gocryptfs.longname.%s'%hash
            rp = os.path.join(rp, ite)
            if not p.deterministic and os.path.isdir(rp):
                ivs = os.path.join(rp, 'gocryptfs.diriv')
                iv = open(ivs, 'rb').read()
        return rp

    def decryptFile(p, virtualpath, dest, force=False):
        "Decrypt a file from a virtual pathname and puts it in real 'dest'"
        f = open(p.getRealPath(virtualpath), 'rb')
        
        # Get header
        h = f.read(18)

        if not h: # if empty file
            if os.path.exists(dest) and not force:
                raise BaseException('destination file "%s" exists and won\'t get overwritten!'%dest)
            out = open(dest, 'wb').close()
            # restore original last access and modification time
            st = p.stat(virtualpath)
            os.utime(dest, (st.st_atime, st.st_mtime))
            return st.st_size

        assert len(h) == 18
        assert h[0:2] == b"\x00\x02"

        # Get content key
        if p.aessiv:
            key = HKDF(p.pk, salt=b"", key_len=64, hashmod=SHA256, context=S_AES_SIV)
        elif p.xchacha:
            key = HKDF(p.pk, salt=b"", key_len=32, hashmod=SHA256, context=S_XCHACHA)
        else:
            key = HKDF(p.pk, salt=b"", key_len=32, hashmod=SHA256, context=S_AES_GCM)
        
        # Process contents
        if os.path.exists(dest) and not force:
            raise BaseException('destination file "%s" exists and won\'t get overwritten!'%dest)
        out = open(dest, 'wb')
        n = 0
        while True:
            blklen = 4096+32
            if p.xchacha: blklen += 8
            s = f.read(blklen) # an encrypted block is at most 4K + 32 (40 with XChaCha) bytes
            if not s: break
            if s != EZEROED:
                if p.aessiv:
                    nonce, tag, payload = s[:16], s[16:32], s[32:]
                    cry = AES.new(key, AES.MODE_SIV, nonce=nonce)
                elif p.xchacha:
                    nonce, payload, tag = s[:24], s[24:-16], s[-16:]
                    cry = ChaCha20_Poly1305.new(key=key, nonce=nonce)
                else:
                    nonce, payload, tag = s[:16], s[16:-16], s[-16:]
                    cry = AES.new(key, AES.MODE_GCM, nonce=nonce)
                cry.update(struct.pack('>Q', n) + h[2:]) # AAD: 64-bit BE block number + fileid
                try:
                    ds = cry.decrypt_and_verify(payload, tag)
                except:
                    print("warning: block %d is damaged and won't be decrypted" % n)
                    ds = payload
            else:
                ds = ZEROED # zeroed block is not encrypted
            out.write(ds)
            n += 1
        f.close()
        out.close()
        # restore original last access and modification time
        st = p.stat(virtualpath)
        os.utime(dest, (st.st_atime, st.st_mtime))
        return st.st_size
    
    def decryptDir(p, virtualpath, dest, force=False):
        if (virtualpath[0] != '/'):
            raise BaseException('the vault path to decrypt must be absolute!')
        real = p.getRealPath(virtualpath) # test existance
        n=0
        nn=0
        total_bytes = 0
        T0 = time.time()
        for root, dirs, files in p.walk(virtualpath):
            nn+=1
            for it in files:
                fn = os.path.join(root, it).replace('\\','/')
                dn = os.path.join(dest, fn[1:]) # target pathname
                bn = os.path.dirname(dn) # target base dir
                if not os.path.exists(bn):
                    os.makedirs(bn)
                print(dn)
                total_bytes += p.decryptFile(fn, dn, force)
                n += 1
        T1 = time.time()
        print('decrypting %s bytes in %d files and %d directories took %d seconds' % (_fmt_size(total_bytes), n, nn, T1-T0))

    def stat(p, virtualpath):
        "Perform os.stat on a virtual pathname"
        target = p.getRealPath(virtualpath)
        return os.stat(target)

    def ls(p, virtualpath, recursive=False):
        "Print a list of contents of a virtual path"
        def _realsize(n):
            "Returns the decrypted file size"
            if not n: return n # empty file is really empty
            cb = (n - 18 + (4096+32-1)) // (4096+32) # number of encrypted blocks
            return n - 18 - (cb*32)
        for root, dirs, files in p.walk(virtualpath):
            print('\n  Directory of', root, '\n')
            tot_size = 0
            for it in dirs:
                full = os.path.join(root, it).replace('\\','/')
                st = v.stat(full)
                print('%12s  %s  %s' %('<DIR>', time.strftime('%Y-%m-%d %H:%M', time.localtime(st.st_mtime)), it))
            for it in files:
                full = os.path.join(root, it).replace('\\','/')
                st = v.stat(full)
                size = _realsize(st.st_size)
                tot_size += size
                print('%12s  %s  %s' %(_fmt_size(size), time.strftime('%Y-%m-%d %H:%M', time.localtime(st.st_mtime)), it))
            print('\n%s bytes in %d files and %d directories.' % (_fmt_size(tot_size), len(files), len(dirs)))
            if not recursive: break
        
    def walk(p, virtualpath):
        "Traverse the virtual file system like os.walk"
        realpath = p.getRealPath(virtualpath)
        dirId = p.getDirId(virtualpath)
        root = virtualpath
        dirs = []
        files = []
        for it in os.scandir(realpath):
            if it.name in ('gocryptfs.diriv', 'gocryptfs.conf'): continue
            isdir = it.is_dir()
            if it.name.startswith('gocryptfs.longname.'):  # deflated long name
                if it.name.endswith('.name'): continue
                fn = os.path.join(realpath, it.name)
                ename = open(fn+'.name').read()
                dname = p.decryptName(dirId, ename)
                if not os.path.isdir(fn): isdir = False
            else:
                dname = p.decryptName(dirId, it.name.encode())
            if isdir: dirs += [dname]
            else: files += [dname]
        yield root, dirs, files
        for it in dirs:
            subdir = os.path.join(root, it).replace('\\','/')
            yield from p.walk(subdir)

# Other utilities

def d64(s, safe=0):
    D = base64.b64decode
    pad = b'==='
    if safe: D = base64.urlsafe_b64decode
    if type(s) != type(b''): pad = pad.decode()
    return D(s+pad)

def unpad16(s):
    z = bytearray()
    for c in s:
        if c <= 16: break
        z += c.to_bytes(1, 'little') # Python Linux 3.10.12 wants (1, '<order>')
    return bytes(z)

def pad16(s):
    "PKCS#7 padding"
    blocks = (len(s)+15) // 16
    if not len(s)%16: blocks += 1 # if len is 16 bytes or multiple, gets additional 16 bytes
    added = blocks*16 - len(s)
    r = bytearray(added.to_bytes(1,'little')) * (blocks*16)
    r[:len(s)] = s # s must be bytes
    return r

def _fmt_size(size):
    "Internal function to format sizes"
    if size >= 10**12:
        sizes = {0:'B', 10:'K',20:'M',30:'G',40:'T',50:'E'}
        k = 0
        for k in sorted(sizes):
            if (size // (1<<k)) < 10**6: break
        size = locale.format_string('%.02f%s', (size/(1<<k), sizes[k]), grouping=1)
    else:
        size = locale.format_string('%d', size, grouping=1)
    return size

# If a Directory IV file gocryptfs.diriv gets lost or corrupted, names in that directory can't be restored!
def backupDirIds(vault_base, zip_backup):
    "Archive in a ZIP file all the Directory IVs with their encrypted tree, for backup purposes"
    if not os.path.exists(vault_base) or \
    not os.path.isdir(vault_base) or \
    not os.path.exists(os.path.join(vault_base,'gocryptfs.conf')):
        raise BaseException(vault_base+' is not a valid gocryptfs vault directory!')
    zip = zipfile.ZipFile(zip_backup, 'w', zipfile.ZIP_DEFLATED)
    n = len(vault_base)
    df = 'gocryptfs.diriv'
    for root, dirs, files in os.walk(vault_base):
        if df in files:
            it = os.path.join(root[n+1:], df) # ZIP item name (relative name)
            s =  os.path.join(vault_base, it) # source file to backup with the binary 128-bit directory IV
            zip.write(s, it)
    zip.close()



if __name__ == '__main__':
    locale.setlocale(locale.LC_ALL, '')

    parser = argparse.ArgumentParser(description="List and decrypt files in a gocryptfs filesystem")
    parser.add_argument('--print-key', help="Print the master key in ASCII85 (a85) or BASE64 (b64) format", type=str, choices=['a85','b64'])
    parser.add_argument('--master-key', nargs=1, metavar=('MASTER_KEY'), help="Master key in ASCII85 or BASE64 format")
    parser.add_argument('--password', help="Password to unlock the master key stored in config file")
    parser.add_argument('fsbase', help="Location of the gocryptfs filesystem to open")
    args, extras = parser.parse_known_args()

    if not args.password and not args.master_key:
        args.password = getpass.getpass()

    if args.master_key:
        def tryDecode(s):
            e = 0
            d = b''
            try: d = base64.a85decode(s)
            except: pass
            if len(d) == 32: return d
            try: d = base64.urlsafe_b64decode(s)
            except: pass
            if len(d) == 32: return d
            raise BaseException('Could not decode master key "%s"'%s)
        pk = tryDecode(args.master_key)
        v = Vault(args.fsbase, pk=pk)
    else:
        v = Vault(args.fsbase, args.password)

    if args.print_key:
        if args.print_key == 'a85':
            encoder = base64.a85encode
        elif args.print_key == 'b64':
            encoder = base64.urlsafe_b64encode
        else:
            print('You must specify a85 or b64 encoding')
            sys.exit(1)
        print('\n   * * *  WARNING !!!  * * *\n')
        print('KEEP THIS KEY TOP SECRET!\nFor recovering purposes only.\n')
        print('MASTER KEY :', encoder(v.pk).decode())
        sys.exit(0)

    if not extras:
        print('An operation must be specified among alias, backup, decrypt, ls')
        sys.exit(1)

    if extras[0] == 'alias':
        if len(extras) == 1:
            print('please use: alias <virtual_pathname>')
            sys.exit(1)
        print('"%s" is the real pathname for %s' % (v.getRealPath(extras[1]), extras[1]))
    elif extras[0] == 'backup':
        if len(extras) == 1:
            print('please use: backup <ZIP archive>')
            sys.exit(1)
        backupDirIds(v.base, extras[1])
        print('done.')
    elif extras[0] == 'ls':
        recursive = '-r' in extras
        if recursive: extras.remove('-r')
        if len(extras) == 1:
            print('please use: ls [-r] <virtual_path1> [...<virtual_pathN>]')
            print('(hint: try "ls /" at first)')
            sys.exit(1)
        for it in extras[1:]:
            v.ls(it, recursive)
    elif extras[0] == 'decrypt':
        force = '-f' in extras
        if force: extras.remove('-f')
        if len(extras) != 3:
            print('please use: decrypt [-f] <virtual_pathname_source> <real_pathname_destination>')
            sys.exit(1)
        isdir = 0
        try:
            isdir = os.path.isdir(v.getRealPath(extras[1]))
        except: pass
        if isdir: v.decryptDir(extras[1], extras[2], force)
        else:
            v.decryptFile(extras[1], extras[2], force)
            print('done.')
    else:
        print('Unknown operation:', extras[0])
        sys.exit(1)
