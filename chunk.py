import os

JS_FILE = "main.js"          
OUTPUT_DIR = "chunks"      
MAX_TOKENS = 200_000  
CHARS_PER_TOKEN = 4

MAX_CHARS = MAX_TOKENS * CHARS_PER_TOKEN

os.makedirs(OUTPUT_DIR, exist_ok=True)

with open(JS_FILE, "r", encoding="utf-8", errors="ignore") as f:
    data = f.read()

chunks = [
    data[i:i + MAX_CHARS]
    for i in range(0, len(data), MAX_CHARS)
]

for idx, chunk in enumerate(chunks, start=1):
    out_file = os.path.join(OUTPUT_DIR, f"chunk_{idx}.js")
    with open(out_file, "w", encoding="utf-8") as f:
        f.write(chunk)
    print(f"[+] Written {out_file} ({len(chunk)} chars)")

print(f"\nDone. Total chunks: {len(chunks)}")
