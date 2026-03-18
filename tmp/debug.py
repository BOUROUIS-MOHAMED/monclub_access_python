import sys
import traceback

with open("tmp/a5_debug_log.txt", "w", encoding="utf-8") as f:
    try:
        import tmp.test_a5_activation as t
        t.run_tests()
    except Exception as e:
        traceback.print_exc(file=f)
