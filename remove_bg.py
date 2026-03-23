import json

src_path = r'C:\Users\mohaa\Desktop\monclub_access_python\Cat playing animation.json'
dest_path = r'C:\Users\mohaa\Desktop\monclub_access_python\tauri-ui\src\assets\animations\cat-playing.json'

with open(src_path, 'r', encoding='utf-8') as f:
    d = json.load(f)

for l in d.get('layers', []):
    name = l.get('nm', '').lower()
    if name == 'ellipse 6':
        # Safely set the layer's opacity transform to 0
        if 'ks' in l:
            if 'o' in l['ks']:
                l['ks']['o']['k'] = 0
            else:
                l['ks']['o'] = {'a': 0, 'k': 0, 'ix': 11}
        print(f"Set opacity of {name} to 0.")

with open(dest_path, 'w', encoding='utf-8') as f:
    json.dump(d, f)
    
print("Saved perfectly transparent Lottie file without breaking the structure!")
