import sys
with open("app/core/tv_local_cache.py", "a", encoding="utf-8") as f1, open("tmp/a10_support.py", "r", encoding="utf-8") as f2:
    f1.write("\n" + f2.read() + "\n")
