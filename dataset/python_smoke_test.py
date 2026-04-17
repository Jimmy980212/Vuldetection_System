import os
import sqlite3


def run(user_cmd: str, user_id: str) -> None:
    os.system("echo " + user_cmd)  # CWE-78

    conn = sqlite3.connect(":memory:")
    cur = conn.cursor()
    cur.execute("create table t(id text)")
    cur.execute("select * from t where id = '" + user_id + "'")  # CWE-89
    conn.close()


if __name__ == "__main__":
    run("demo", "1")
