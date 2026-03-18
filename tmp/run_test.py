import sys
import traceback

with open("tmp/stdout3.txt", "w", encoding="utf-8") as f:
    sys.stdout = f
    sys.stderr = f
    try:
        import tmp.test_a5_activation as t
        t.run_tests()
    except Exception as e:
        traceback.print_exc()
