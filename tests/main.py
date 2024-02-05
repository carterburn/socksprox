import subprocess
import os

# create the echo server (the "web" server)
web = subprocess.Popen(['python3', 'tests/echo.py'], shell = False)

# open the socks proxy (after we build)
if not os.path.exists('./target/debug/socksprox'):
    # build it
    subprocess.run(['cargo', 'build'])

socks = subprocess.Popen(['./target/debug/socksprox'], env={'RUST_LOG': 'info'},
                         shell = False, stdout=subprocess.PIPE)

# create the client subprocess to kick it all off
client = subprocess.Popen(['python3', 'tests/client.py'], shell=False,
                 stdout=subprocess.PIPE, stderr = subprocess.PIPE)

_, client_err = client.communicate()

if b'PASSED' not in client_err:
    print("\033[91mTEST FAILED\033[0m")


print("\033[92mTEST PASSED\033[0m")
