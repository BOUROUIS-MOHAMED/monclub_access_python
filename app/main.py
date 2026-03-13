import faulthandler
faulthandler.enable(all_threads=True)

print("step 1: starting main.py", flush=True)

if __name__ == "__main__":
    print("step 2: before importing run_app", flush=True)
    from app.ui.app import run_app
    print("step 3: after importing run_app", flush=True)
    run_app()
    print("step 4: after run_app()", flush=True)