import sqlite3
import app.core.tv_local_cache as tc

conn = sqlite3.connect(":memory:")

# We run the statements one by one using AST to catch the exact string
import ast
with open("app/core/tv_local_cache.py", "r") as f:
    tree = ast.parse(f.read())
    
for node in ast.walk(tree):
    if isinstance(node, ast.FunctionDef) and node.name == "_create_tv_schema":
        for stmt in node.body:
            if isinstance(stmt, ast.Expr) and isinstance(stmt.value, ast.Call):
                if getattr(stmt.value.func, "attr", "") == "execute":
                    try:
                        # stmt.value.args[0] is the SQL string node
                        sql = stmt.value.args[0].value
                        conn.execute(sql)
                    except Exception as err:
                        print("==== FAILING SQL ====")
                        print(sql)
                        print("ERROR:", err)
                        break
