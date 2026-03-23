import json

path = r'C:\Users\mohaa\Desktop\monclub_access_python\Cat playing animation.json'
with open(path, 'r', encoding='utf-8') as f:
    d = json.load(f)

for i, l in enumerate(d.get('layers', [])):
    ind = l.get('ind')
    parent = l.get('parent')
    name = l.get('nm', '')
    print(f"Layer {i}: '{name}' ind={ind} parent={parent}")
