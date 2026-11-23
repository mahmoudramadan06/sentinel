"""Synthetic vulnerable app for sentinel-triage's test fixtures.

Every secret below is a documented placeholder (AWS's published example
key, obviously fake tokens). Nothing here is a real credential and this
app is never meant to run; it only exists to exercise the scanners.
"""

import hashlib
import pickle
import sqlite3
import subprocess

# AWS's own documented EXAMPLE key pair (not real):
AWS_ACCESS_KEY = "AKIAIOSFODNN7EXAMPLE"

API_KEY = "sk-live-fake0000000000000000"  # fake placeholder for the generic rule

GITHUB_TOKEN = "ghp_faketoken0000000000000000000000000000"  # fake placeholder


def get_user(conn: sqlite3.Connection, name: str):
    cur = conn.cursor()
    cur.execute(f"SELECT * FROM users WHERE name = '{name}'")
    return cur.fetchone()


def add_student(conn, name: str):
    q = ("INSERT INTO students (name) "
         "VALUES ('%(name)s')" % {'name': name})
    conn.execute(q)


def hash_password(password: str) -> str:
    return hashlib.md5(password.encode()).hexdigest()


def run_report(report_name: str):
    subprocess.run("generate-report " + report_name, shell=True)


def load_config(blob: bytes):
    return pickle.loads(blob)


def render(expr: str):
    return eval(expr)


def main():
    debug = True
    print(debug)
