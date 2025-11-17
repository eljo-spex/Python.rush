import pikepdf
import sys
import itertools
import threading
from tqdm import tqdm
from concurrent.futures import ThreadPoolExecutor, as_completed

def generate_passwords(chars, min_length, max_length):
    for length in range(min_length, max_length + 1):
        for password in itertools.product(chars, repeat=length):
            yield ''.join(password)

def read_passwords(wordlist_file):
    with open(wordlist_file, 'r') as file:
        for line in file:
            yield line.strip()

def check_password(pdf_file, password, stop_event):
    if stop_event.is_set():  
        return None
    try:
        with pikepdf.open(pdf_file, password=password):
            stop_event.set()  
            return password
    except pikepdf._core.PasswordError:
        return None

def decrypt_pdf(pdf_file, passwords, total_passwords, max_workers):
    stop_event = threading.Event()
    found = None
    futures = []

    with tqdm(total=total_passwords, desc="Decrypting PDF", unit="password", colour='red') as pbar:
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            for pwd in passwords:
                futures.append(executor.submit(check_password, pdf_file, pwd, stop_event))

            for future in as_completed(futures):
                pbar.update(1)
                result = future.result()
                if result:
                    found = result
                    stop_event.set()
                    break

    if found:
        tqdm.write(f"\n.....Password found.........")
        return found
    else:
        print("\n Unable to decrypt PDF. Password not found!")
        return None

def calculate_total_passwords(charset, min_length, max_length):
    n = len(charset)
    return sum(n**L for L in range(min_length, max_length + 1))

def count_lines(wordlist):
    with open(wordlist, 'r') as f:
        return sum(1 for _ in f)

if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="Crack the password of a PDF file")

    parser.add_argument('-pdf', help='Path to password protected PDF file', required=True)
    parser.add_argument('-w', '--wordlist', help='Path to wordlist file', default=None)
    parser.add_argument('-g', '--generate', action='store_true', help='Generate passwords from a charset')
    parser.add_argument('-min', '--min_length', type=int, help='Minimum password length', default=4)
    parser.add_argument('-max', '--max_length', type=int, help='Maximum password length', default=6)
    parser.add_argument('-char', '--charset', type=str, help='Charset for brute-force generation', default=None)
    parser.add_argument('-t', '--thread', type=int, help='Number of threads', default=10)

    args = parser.parse_args()

    if args.generate:
        if not args.charset:
            print("\nError: --charset is required when using --generate")
            sys.exit(1)

        passwords = generate_passwords(args.charset, args.min_length, args.max_length)
        total_passwords = calculate_total_passwords(args.charset, args.min_length, args.max_length)
        print(f"cracking the pdf with charset {args.charset} | min_length: {args.min_length} | max_length: {args.max_length}")
    
    elif args.wordlist:
        try:
            total_passwords = count_lines(args.wordlist)
            passwords = read_passwords(args.wordlist)
            
        except FileNotFoundError:
            print("\nError: Wordlist not found!")
            sys.exit(1)

    else:
        print("\nError: Provide either a wordlist (--wordlist) or --generate with character_set (--charset).\n")
        sys.exit(1)

    decrypted_password = decrypt_pdf(args.pdf, passwords, total_passwords, args.thread)

    if decrypted_password:
        print("PDF decrypted successfully with password:", decrypted_password,'\n')
    else:
        print("Unable to decrypt PDF. Password not found !")
