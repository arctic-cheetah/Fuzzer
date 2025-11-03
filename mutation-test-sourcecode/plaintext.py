#!/usr/bin/env python3
import os, random, subprocess, string, tempfile

SEED_FILE="plaintext1.txt"
TARGET="./plaintext2"
DICT=[b"%n",b"%hn",b"%hhn",b"%ln",b"%lln",b"%p%p%p%p",b"%x%x%x%x",b"%08x%08x%08x",b"%s%s%s%s",b"%*s",b"%.10240s",b"%99999999s",b"%d%d%d%d",b"%#n",b"%hhn%n",b"%s%n"]
ASCII=(string.ascii_letters+string.digits+"_-").encode()

def rs(p):
    try: return open(p,"rb").read()
    except: return b"Hello\n"

def longtok(a=256,b=8192):
    n=random.randint(a,b)
    return bytes(random.choice(ASCII) for _ in range(n))

def longline():
    s=longtok()
    return s+(b"\n" if random.random()<0.5 else b"")

def inject(b):
    a=bytearray(b)
    for _ in range(random.randint(1,8)):
        t=random.choice(DICT)
        pos=random.randrange(0,len(a)+1)
        a[pos:pos]=t
    return bytes(a)

def flip(b):
    if not b: return b
    a=bytearray(b)
    n=max(1,len(a)//32)
    for _ in range(random.randint(1,n)):
        i=random.randrange(len(a))
        a[i]=random.randint(0,255)
    return bytes(a)

def insert(b):
    a=bytearray(b)
    blk=os.urandom(random.randint(8,2048))
    pos=random.randrange(0,len(a)+1)
    return bytes(a[:pos]+blk+a[pos:])

def delete(b):
    if len(b)<=4: return b
    i=random.randrange(0,len(b)-1)
    j=random.randrange(i+1,min(len(b),i+1+random.randint(1,4096)))
    return b[:i]+b[j:]

def sprinkle(b):
    a=bytearray(b)
    for _ in range(random.randint(1,16)):
        pos=random.randrange(0,len(a)+1)
        a[pos:pos]=b"\n"
    return bytes(a)

MUT=[flip,insert,delete,sprinkle,inject]

def mut(seed):
    d=seed
    if random.random()<0.7: d=inject(d)
    for _ in range(random.randint(1,3)):
        d=random.choice(MUT)(d)
    return d

def make(seed):
    if random.random()<0.7: return mut(seed)
    p=longline() if random.random()<0.5 else longtok()
    if random.random()<0.9: p=inject(p)
    return p

def run(data,timeout=0.4):
    m=random.choices(["stdin","argv","file"],weights=[5,3,2],k=1)[0]
    try:
        if m=="stdin":
            p=subprocess.run([TARGET],input=data,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=timeout);return p,False,m
        if m=="argv":
            arg=data.replace(b"\x00",b"")[:65535] or b"A"
            p=subprocess.run([TARGET,arg.decode("latin1","ignore")],stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=timeout);return p,False,m
        with tempfile.NamedTemporaryFile(prefix="p1_",delete=False) as tf:
            tf.write(data);tf.flush();path=tf.name
        try:
            p=subprocess.run([TARGET,path],stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=timeout)
        finally:
            try: os.unlink(path)
            except: pass
        return p,False,m
    except subprocess.TimeoutExpired as e:
        return e,True,m

def is_crash(x,to):
    if to: return True
    if hasattr(x,"returncode"):
        rc=x.returncode
        if rc is None or rc<0: return True
    return False

def outfile():
    name="bad_plaintext1.txt"
    return os.path.join("/fuzzer_output",name) if os.path.isdir("/fuzzer_output") else name

def main():
    seed=rs(SEED_FILE)
    out=outfile()
    for i in range(1,1001):
        data=make(seed)
        r,to,m=run(data)
        if is_crash(r,to):
            os.makedirs(os.path.dirname(out) or ".",exist_ok=True)
            open(out,"wb").write(data)
            print(f"[CRASH] attempt #{i} via {m} -> {out}")
            return
    print("[*] No crash within 1000 attempts.")

if __name__=="__main__":
    main()
