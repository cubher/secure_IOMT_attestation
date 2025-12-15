#!/usr/bin/env python3
import os, json, tempfile, base64, subprocess, requests
from pathlib import Path

# ===== Feature Flags =====
SIGN = 1
ENCRYPT = 1

PI_URL = "http://10.250.149.152:4000"
RASPI_PUB_PEM="tpm.pem"
C2_PRIV="c2.key"
OPENSSL="openssl"

# -------- Crypto ----------
def run(cmd, data=None):
    p = subprocess.run(cmd, input=data, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    if p.returncode != 0:
        raise RuntimeError(p.stderr.decode())
    return p.stdout

def sign(data):
    with tempfile.TemporaryDirectory() as d:
        i = Path(d)/"i"
        o = Path(d)/"o"
        i.write_bytes(data)
        run([OPENSSL,"pkeyutl","-sign","-inkey",C2_PRIV,"-in",str(i),"-out",str(o)])
        return o.read_bytes()

def verify(data, sig):
    with tempfile.TemporaryDirectory() as d:
        i = Path(d)/"i"
        s = Path(d)/"s"
        i.write_bytes(data)
        s.write_bytes(sig)
        return subprocess.run([OPENSSL,"pkeyutl","-pubin","-inkey",RASPI_PUB_PEM,
                               "-verify","-in",str(i),"-sigfile",str(s)]).returncode == 0

def encrypt_pub(data):
    with tempfile.TemporaryDirectory() as d:
        i = Path(d)/"i"
        o = Path(d)/"o"
        i.write_bytes(data)
        run([OPENSSL,"pkeyutl","-encrypt","-pubin","-inkey",RASPI_PUB_PEM,"-in",str(i),"-out",str(o)])
        return o.read_bytes()

def decrypt_priv(data):
    with tempfile.TemporaryDirectory() as d:
        i = Path(d)/"i"
        o = Path(d)/"o"
        i.write_bytes(data)
        run([OPENSSL,"pkeyutl","-decrypt","-inkey",C2_PRIV,"-in",str(i),"-out",str(o)])
        return o.read_bytes()

# --- Hybrid ---
def build_req(body):
    sig=b''
    block = body

    if ENCRYPT:
        key=os.urandom(32); iv=os.urandom(16)
        with tempfile.TemporaryDirectory() as d:
            i = Path(d)/"i"
            o = Path(d)/"o"
            i.write_bytes(body)
            run([OPENSSL,"enc","-aes-256-cbc","-in",str(i),"-out",str(o),"-K",key.hex(),"-iv",iv.hex()])
            cipher=o.read_bytes()
        rsa=encrypt_pub(key+iv)
        block=len(rsa).to_bytes(4,'big')+rsa+cipher

    if SIGN:
        sig=sign(block)
        block=len(sig).to_bytes(4,'big')+sig+block

    return base64.b64encode(block)

def parse_resp(raw):
    data=base64.b64decode(raw)

    if SIGN:
        l=int.from_bytes(data[:4],'big')
        sig=data[4:4+l]
        rest=data[4+l:]
        if not verify(rest,sig):
            raise RuntimeError("Bad Signature")
    else:
        rest=data

    if ENCRYPT:
        l=int.from_bytes(rest[:4],'big')
        rsa=rest[4:4+l]
        enc=rest[4+l:]
        keyiv=decrypt_priv(rsa)
        with tempfile.TemporaryDirectory() as d:
            i=Path(d)/"i"; o=Path(d)/"o"
            i.write_bytes(enc)
            run([OPENSSL,"enc","-d","-aes-256-cbc","-in",str(i),"-out",str(o),"-K",keyiv[:32].hex(),"-iv",keyiv[32:48].hex()])
            plain=o.read_bytes()
        return plain
    return rest

def post_api(path, obj=None):
    body=b'' if not obj else json.dumps(obj).encode()
    pkt=build_req(body) if (SIGN or ENCRYPT) else body
    r=requests.post(PI_URL+path,data=pkt)
    return parse_resp(r.content) if (SIGN or ENCRYPT) else r.content

# ---------- Menu ----------
def compare_pcrs(pi_str):
    golden = json.loads(Path("golden_pcrs.json").read_text())
    pi={}
    for l in pi_str.splitlines():
        if " : " in l:
            k,v=l.strip().split(" : ")
            pi[k]=v
    ok=all(pi.get(k,"").upper()==v.upper() for k,v in golden.items())
    return ok

while True:
    print("\n=== TPM C2 Menu ===")
    print("1. Get PCR Quote")
    print("2. Update PCR")
    print("3. Firmware OTA")
    print("4. RSA Decrypt Test Echo")
    print("0. Exit")
    ch=input("Choice: ")

    if ch=="1":
        res=post_api("/api/get_pcr_quote")
        data=json.loads(res.decode())["pcr_values"]
        print("PCR:",data)
        print("Trusted" if compare_pcrs(data) else "NOT Trusted")

    elif ch=="2":
        res=post_api("/api/update_pcr")
        data=json.loads(res.decode())["updated"]
        d={}
        for l in data.splitlines():
            if " : " in l:
                k,v=l.strip().split(" : ")
                d[k]=v
        Path("golden_pcrs.json").write_text(json.dumps(d,indent=4))
        print("[+] Golden PCRs updated")

    elif ch=="3":
        url=input("Image URL (blank=skip): ")
        res=post_api("/api/update_firmware",{"image_url":url})
        print("OTA:",res.decode())

    elif ch=="4":
        msg=input("Message: ").encode()
        res=post_api("/api/rsa_decrypt_test")
        print("Echo:",res.decode())

    elif ch=="0":
        break
