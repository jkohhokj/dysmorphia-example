from pwn import *
with open("../firmware/gcc/protected.bin","rb") as f:
    a = f.read()
with open("../firmware/gcc/main.bin","rb") as f:
    b = f.read()
with open("../firmware/gcc/decrypted.bin","wb") as f:
    for c in a:
        f.write(p8((c-0x10+0x100)&0xFF))
with open("../firmware/gcc/decrypted.bin","rb") as f:
    d = f.read()[4:]
print(f"Protected len {len(a)}")
print(f"Decrypted len {len(d)}")
for i in range(0,len(a),16):
    print(f"{b[i:i+16]==d[i:i+16]} for {b[i:i+16]} -> {a[i:i+16]} => {d[i:i+16]}")