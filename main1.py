import string
import argparse
import sys
import trotter
from tqdm import tqdm
from time import sleep, time
from hdwallet import HDWallet
from hdwallet.symbols import BTC
from btc_com import explorer as btc_explorer
import concurrent.futures
import threading

log_lock = threading.Lock()
found_flag = threading.Event()

def write_to_log(data):
    with log_lock:
        with open("output_log.txt", "a") as file:
            file.write(data + '\n')

def complete_key(masked_key_string, missing_letters):
    for letter in missing_letters:
        masked_key_string = masked_key_string.replace('*', letter, 1)
    return masked_key_string

def fetch_balance_for_btc_address(btc_address):
    try:
        address_info = btc_explorer.get_address(btc_address)
        sleep(1.25)
        return address_info.balance, address_info.tx_count
    except Exception as e:
        print(f"Error fetching balance: {e}")
        return None, None

def btc_address_from_private_key(my_secret, secret_type='WIF'):
    hdwallet = HDWallet(symbol=BTC)
    if secret_type == 'WIF':
        hdwallet.from_wif(wif=my_secret)
    elif secret_type == 'classic':
        hdwallet.from_private_key(private_key=my_secret)
    elif secret_type == 'extended':
        hdwallet.from_xprivate_key(xprivate_key=my_secret)
    else:
        raise ValueError("Unsupported key format.")
    return hdwallet.p2pkh_address()

def parse_arguments():
    parser = argparse.ArgumentParser(description='Recover incomplete BTC private keys')
    parser.add_argument("--maskedkey", required=True, help="Private key with * for unknown characters")
    parser.add_argument("--address", default=None, help="Target BTC address")
    parser.add_argument("--fetchbalances", action='store_true', help="Also check balance (slower)")
    parser.add_argument("--mode", choices=['sequential', 'random'], default='sequential', help="Search mode")
    return parser.parse_args()

cli_arguments = parse_arguments()
masked_key = cli_arguments.maskedkey
target_address = cli_arguments.address
fetch_balances = cli_arguments.fetchbalances
mode = cli_arguments.mode

missing_length = masked_key.count('*')
key_length = len(masked_key)

print(f"Looking for {missing_length} characters in {masked_key} to match address {target_address}", flush=True)

if key_length in [51, 52]:
    secret_type = 'WIF'
    allowed_characters = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'
elif key_length == 64:
    secret_type = 'classic'
    allowed_characters = string.digits + "ABCDEF"
elif key_length == 111:
    secret_type = 'extended'
    allowed_characters = string.ascii_letters + string.digits
else:
    print("Unsupported key length.")
    sys.exit(1)

missing_letters_master_list = trotter.Amalgams(missing_length, allowed_characters)
total_combinations = len(missing_letters_master_list)

progress_bar = tqdm(total=total_combinations, desc="Progress", unit="keys", ncols=80)
match_info = {"index": None, "key": None, "address": None}

def process_combination(index):
    if found_flag.is_set():
        return

    if mode == 'sequential':
        letters = missing_letters_master_list[index]
    else:
        letters = missing_letters_master_list.random()

    potential_key = complete_key(masked_key, letters)

    try:
        address = btc_address_from_private_key(potential_key, secret_type)

        if target_address and address != target_address:
            return
        # MATCH FOUND!
        found_flag.set()
        match_info["index"] = index
        match_info["key"] = potential_key
        match_info["address"] = address

        output = f"\n✅ MATCH FOUND!\nKey: {potential_key}\nAddress: {address}"
        print(output, flush=True)

        if fetch_balances:
            balance, tx_count = fetch_balance_for_btc_address(address)
            output += f"\nTransactions: {tx_count}, Balance: {balance}"
            print(f"Transactions: {tx_count}, Balance: {balance}", flush=True)

        write_to_log(output)

        # Force stop this thread
        raise SystemExit

    except Exception:
        pass
    finally:
        progress_bar.update(1)

# 🧵 Number of threads
num_threads = 8

start_time = time()

with concurrent.futures.ThreadPoolExecutor(max_workers=num_threads) as executor:
    futures = [executor.submit(process_combination, i) for i in range(total_combinations)]

    try:
        for future in concurrent.futures.as_completed(futures):
            if found_flag.is_set():
                break
    except KeyboardInterrupt:
        found_flag.set()
        print("Interrupted by user.")

progress_bar.close()
elapsed = time() - start_time

if match_info["key"]:
    print(f"\n🔍 Found after {match_info['index']+1:,} attempts")
else:
    print("\n❌ No match found.")

print(f"⏱️ Recovery completed in {elapsed:.2f} seconds ({elapsed/60:.2f} minutes)")
