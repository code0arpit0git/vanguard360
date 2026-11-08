import subprocess

AWS_SECRET_KEY = "AKIAIOSFODNN7EXAMPLEKEY999"
ETH_PRIVATE_KEY = "0x4c0883a69102937d6231471b5dbb6204fe5129617082792ae468d01a3f362318"
DEBUG = True

def execute_command(cmd):
    subprocess.Popen(cmd, shell=True)
    eval(cmd)
