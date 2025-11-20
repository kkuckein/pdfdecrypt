#!/usr/bin/env python3
"""
PDF Decryption Tool
Decrypts password-protected PDF files and saves them as unencrypted PDFs.
Supports password guessing via wordlists, common patterns, and brute force.
"""

import sys
import os
import argparse
import itertools
import string
import time
from pathlib import Path
from typing import Optional, Iterator
from concurrent.futures import ThreadPoolExecutor, ProcessPoolExecutor, as_completed
from functools import lru_cache
import threading

try:
    from pypdf import PdfReader, PdfWriter
except ImportError:
    try:
        from PyPDF2 import PdfFileReader, PdfFileWriter
        # Compatibility layer for older PyPDF2
        PdfReader = PdfFileReader
        PdfWriter = PdfFileWriter
    except ImportError:
        print("Error: pypdf or PyPDF2 library is required.")
        print("Install it with: pip install pypdf")
        sys.exit(1)


# Thread-local storage for PDF readers (to avoid recreating them)
_thread_local = threading.local()


def get_pdf_reader(input_path: str):
    """
    Get or create a PDF reader for the current thread.
    Caches the reader to avoid recreating it for each password test.
    """
    if not hasattr(_thread_local, 'reader') or _thread_local.reader_path != input_path:
        _thread_local.reader = PdfReader(input_path)
        _thread_local.reader_path = input_path
    return _thread_local.reader


def test_password(input_path: str, password: str) -> bool:
    """
    Test if a password can decrypt the PDF without saving.
    Uses cached PDF reader for better performance.
    
    Args:
        input_path: Path to the encrypted PDF file
        password: Password to test
        
    Returns:
        True if password is correct, False otherwise
    """
    try:
        reader = get_pdf_reader(input_path)
        if not reader.is_encrypted:
            return False
        return reader.decrypt(password)
    except ImportError as e:
        if 'cryptography' in str(e).lower():
            print(f"\nError: Missing 'cryptography' library required for AES encryption.")
            print("Install it with: pip install cryptography")
            sys.exit(1)
        raise
    except Exception as e:
        # For other exceptions during password testing, return False
        # but don't print errors for every failed password attempt
        return False


def test_passwords_batch(args_tuple) -> Optional[str]:
    """
    Test a batch of passwords in parallel.
    Returns the correct password if found, None otherwise.
    
    Args:
        args_tuple: (input_path, password_list) tuple
        
    Returns:
        The correct password if found, None otherwise
    """
    input_path, password_list = args_tuple
    for password in password_list:
        if test_password(input_path, password):
            return password
    return None


def decrypt_pdf(input_path: str, output_path: str, password: str) -> bool:
    """
    Decrypt a PDF file and save it as an unencrypted PDF.
    
    Args:
        input_path: Path to the encrypted PDF file
        output_path: Path where the decrypted PDF will be saved
        password: Password to decrypt the PDF
        
    Returns:
        True if decryption was successful, False otherwise
    """
    try:
        # Read the encrypted PDF
        reader = PdfReader(input_path)
        
        # Check if PDF is encrypted
        if not reader.is_encrypted:
            print(f"Warning: The PDF file '{input_path}' is not encrypted.")
            return False
        
        # Try to decrypt with the provided password
        if not reader.decrypt(password):
            print(f"Error: Incorrect password for '{input_path}'")
            return False
    except ImportError as e:
        if 'cryptography' in str(e).lower():
            print(f"\nError: Missing 'cryptography' library required for AES encryption.")
            print("Install it with: pip install cryptography")
            sys.exit(1)
        raise
        
        # Create a new PDF writer
        writer = PdfWriter()
        
        # Copy all pages from the decrypted reader to the writer
        for page_num in range(len(reader.pages)):
            writer.add_page(reader.pages[page_num])
        
        # Write the decrypted PDF to the output file
        with open(output_path, 'wb') as output_file:
            writer.write(output_file)
        
        print(f"Successfully decrypted PDF!")
        print(f"Input:  {input_path}")
        print(f"Output: {output_path}")
        return True
        
    except FileNotFoundError:
        print(f"Error: File '{input_path}' not found.")
        return False
    except Exception as e:
        print(f"Error decrypting PDF: {str(e)}")
        return False


def load_wordlist(wordlist_path: str) -> Iterator[str]:
    """
    Load passwords from a wordlist file.
    
    Args:
        wordlist_path: Path to the wordlist file
        
    Yields:
        Each password from the wordlist
    """
    try:
        with open(wordlist_path, 'r', encoding='utf-8', errors='ignore') as f:
            for line in f:
                password = line.strip()
                if password:  # Skip empty lines
                    yield password
    except FileNotFoundError:
        print(f"Error: Wordlist file '{wordlist_path}' not found.")
        return
    except Exception as e:
        print(f"Error reading wordlist: {str(e)}")
        return


def generate_common_passwords() -> Iterator[str]:
    """
    Generate common passwords and patterns.
    
    Yields:
        Common password patterns
    """
    # Common passwords
    common = [
        'password', '123456', '12345678', 'qwerty', 'abc123', 'password1',
        'admin', 'letmein', 'welcome', 'monkey', '1234567890', 'password123',
        '1234', '12345', '1234567', 'sunshine', 'princess', 'dragon',
        'passw0rd', 'master', 'hello', 'freedom', 'whatever', 'qazwsx',
        'trustno1', 'jordan23', 'harley', 'robert', 'matthew', 'jordan',
        'michelle', 'charlie', 'andrew', 'michael', 'shadow', 'baseball',
        'football', 'jesus', 'ninja', 'mustang', 'password', 'welcome',
        'admin', '123456789', '12345678', '1234567', 'sunshine', 'princess',
        'dragon', 'passw0rd', 'master', 'hello', 'freedom', 'whatever',
        'qazwsx', 'trustno1', '654321', 'jordan23', 'harley', 'robert',
        'matthew', 'jordan', 'michelle', 'charlie', 'andrew', 'michael',
        'shadow', 'baseball', 'football', 'jesus', 'ninja', 'mustang'
    ]
    
    for pwd in common:
        yield pwd
    
    # Numeric sequences
    for i in range(10000):
        yield str(i)
        yield f"{i:04d}"  # Zero-padded
    
    # Years
    for year in range(1900, 2025):
        yield str(year)
    
    # Common patterns: password + number
    for base in ['password', 'admin', 'user', 'test', 'demo']:
        for num in range(100):
            yield f"{base}{num}"
            yield f"{base}{num:02d}"
            yield f"{num}{base}"
    
    # Common patterns: word + year
    for word in ['password', 'admin', 'user', 'test']:
        for year in range(2000, 2025):
            yield f"{word}{year}"


def brute_force_passwords(min_length: int = 1, max_length: int = 4, 
                         charset: str = string.ascii_lowercase + string.digits) -> Iterator[str]:
    """
    Generate passwords for brute force attack.
    
    Args:
        min_length: Minimum password length
        max_length: Maximum password length
        charset: Character set to use
        
    Yields:
        Generated password combinations
    """
    for length in range(min_length, max_length + 1):
        for attempt in itertools.product(charset, repeat=length):
            yield ''.join(attempt)


def guess_password(input_path: str, wordlist: Optional[str] = None, 
                  use_common: bool = True, brute_force: bool = False,
                  max_length: int = 4, charset: str = None, 
                  threads: int = None) -> Optional[str]:
    """
    Attempt to guess the PDF password using various methods.
    
    Args:
        input_path: Path to the encrypted PDF file
        wordlist: Path to wordlist file (optional)
        use_common: Whether to try common passwords
        brute_force: Whether to use brute force (warning: can be slow)
        max_length: Maximum length for brute force (default: 4)
        charset: Character set for brute force (default: lowercase + digits)
        
    Returns:
        The correct password if found, None otherwise
    """
    print(f"Attempting to guess password for '{input_path}'...")
    print("This may take a while...\n")
    
    attempts = 0
    tested_passwords = set()  # Avoid testing duplicates
    start_time = time.time()
    last_update_time = start_time
    last_update_attempts = 0
    
    # Determine number of threads (default to CPU count)
    if threads is None:
        try:
            threads = os.cpu_count() or 4
        except:
            threads = 4
    
    def update_progress(current_attempts: int, force: bool = False):
        """Update progress display with elapsed time and rate."""
        nonlocal last_update_time, last_update_attempts
        
        current_time = time.time()
        elapsed = current_time - start_time
        
        # Update every 0.5 seconds or when forced
        if force or (current_time - last_update_time) >= 0.5:
            rate = 0
            if elapsed > 0:
                rate = current_attempts / elapsed
            
            # Format the display
            elapsed_str = f"{elapsed:.1f}s"
            if elapsed > 60:
                elapsed_str = f"{int(elapsed // 60)}m {int(elapsed % 60)}s"
            
            rate_str = f"{rate:.0f}/s" if rate > 0 else "0/s"
            
            # Show progress with formatting
            if current_attempts < 1000:
                print(f"  Progress: {current_attempts} passwords tried | {elapsed_str} elapsed | {rate_str}        ", end='\r')
            elif current_attempts < 1000000:
                print(f"  Progress: {current_attempts:,} passwords tried | {elapsed_str} elapsed | {rate_str}        ", end='\r')
            else:
                print(f"  Progress: {current_attempts/1000000:.2f}M passwords tried | {elapsed_str} elapsed | {rate_str}        ", end='\r')
            
            last_update_time = current_time
            last_update_attempts = current_attempts
    
    # Method 1: Wordlist (with parallel processing)
    if wordlist:
        print(f"Trying passwords from wordlist: {wordlist}")
        wordlist_passwords = [pwd for pwd in load_wordlist(wordlist) if pwd not in tested_passwords]
        
        if threads > 1 and len(wordlist_passwords) > 100:
            # Use parallel processing for larger wordlists
            print(f"Using {threads} parallel threads...")
            batch_size = max(50, len(wordlist_passwords) // (threads * 4))
            
            with ThreadPoolExecutor(max_workers=threads) as executor:
                futures = []
                for i in range(0, len(wordlist_passwords), batch_size):
                    batch = wordlist_passwords[i:i+batch_size]
                    tested_passwords.update(batch)
                    batch_tuple = (input_path, batch)
                    future = executor.submit(test_passwords_batch, batch_tuple)
                    futures.append((future, len(batch)))
                
                for future, batch_count in futures:
                    attempts += batch_count
                    update_progress(attempts)
                    
                    result = future.result()
                    if result:
                        # Cancel remaining futures
                        for f, _ in futures:
                            if f != future:
                                f.cancel()
                        elapsed = time.time() - start_time
                        print(f"\n✓ Password found after {attempts} attempts in {elapsed:.1f} seconds!")
                        return result
        else:
            # Sequential processing for small wordlists
            for password in wordlist_passwords:
                tested_passwords.add(password)
                attempts += 1
                update_progress(attempts)
                
                if test_password(input_path, password):
                    elapsed = time.time() - start_time
                    print(f"\n✓ Password found after {attempts} attempts in {elapsed:.1f} seconds!")
                    return password
    
    # Method 2: Common passwords (with parallel processing)
    if use_common:
        print("Trying common passwords...")
        common_passwords = [pwd for pwd in generate_common_passwords() if pwd not in tested_passwords]
        
        if threads > 1 and len(common_passwords) > 200:
            # Use parallel processing for common passwords
            print(f"Using {threads} parallel threads...")
            batch_size = max(100, len(common_passwords) // (threads * 4))
            
            with ThreadPoolExecutor(max_workers=threads) as executor:
                futures = []
                for i in range(0, len(common_passwords), batch_size):
                    batch = common_passwords[i:i+batch_size]
                    tested_passwords.update(batch)
                    batch_tuple = (input_path, batch)
                    future = executor.submit(test_passwords_batch, batch_tuple)
                    futures.append((future, len(batch)))
                
                for future, batch_count in futures:
                    attempts += batch_count
                    update_progress(attempts)
                    
                    result = future.result()
                    if result:
                        # Cancel remaining futures
                        for f, _ in futures:
                            if f != future:
                                f.cancel()
                        elapsed = time.time() - start_time
                        print(f"\n✓ Password found after {attempts} attempts in {elapsed:.1f} seconds!")
                        return result
        else:
            # Sequential processing
            for password in common_passwords:
                tested_passwords.add(password)
                attempts += 1
                update_progress(attempts)
                
                if test_password(input_path, password):
                    elapsed = time.time() - start_time
                    print(f"\n✓ Password found after {attempts} attempts in {elapsed:.1f} seconds!")
                    return password
    
    # Method 3: Brute force (warning: very slow for longer passwords)
    if brute_force:
        if charset is None:
            charset = string.ascii_lowercase + string.digits
        
        # Show charset info
        charset_info = f"{len(charset)} chars"
        if len(charset) <= 50:
            # Show actual characters for small charsets
            charset_preview = charset[:30] + ('...' if len(charset) > 30 else '')
            charset_info = f"{charset_preview} ({len(charset)} chars)"
        
        print(f"Starting brute force attack (max length: {max_length}, charset: {charset_info})...")
        print(f"Using {threads} parallel threads for faster processing...")
        print("Warning: This can take a very long time!")
        
        # Generate all passwords first (for parallel processing)
        password_generator = brute_force_passwords(min_length=1, max_length=max_length, charset=charset)
        password_list = []
        batch_size = 1000  # Process passwords in batches
        
        # Use parallel processing for brute force
        with ThreadPoolExecutor(max_workers=threads) as executor:
            batch = []
            futures = []
            
            for password in password_generator:
                if password in tested_passwords:
                    continue
                tested_passwords.add(password)
                batch.append(password)
                
                # Submit batch when it reaches batch_size
                if len(batch) >= batch_size:
                    batch_tuple = (input_path, batch)
                    future = executor.submit(test_passwords_batch, batch_tuple)
                    futures.append((future, len(batch)))
                    batch = []
                
                # Check completed futures periodically
                if len(futures) >= threads * 2:  # Keep pipeline full
                    for future, batch_count in futures[:]:
                        if future.done():
                            attempts += batch_count
                            update_progress(attempts)
                            
                            result = future.result()
                            if result:
                                # Cancel remaining futures
                                for f, _ in futures:
                                    f.cancel()
                                elapsed = time.time() - start_time
                                print(f"\n✓ Password found after {attempts} attempts in {elapsed:.1f} seconds!")
                                return result
                            futures.remove((future, batch_count))
            
            # Submit remaining batch
            if batch:
                batch_tuple = (input_path, batch)
                future = executor.submit(test_passwords_batch, batch_tuple)
                futures.append((future, len(batch)))
            
            # Wait for all remaining futures
            for future, batch_count in futures:
                attempts += batch_count
                update_progress(attempts)
                
                result = future.result()
                if result:
                    # Cancel remaining futures
                    for f, _ in futures:
                        if f != future:
                            f.cancel()
                    elapsed = time.time() - start_time
                    print(f"\n✓ Password found after {attempts} attempts in {elapsed:.1f} seconds!")
                    return result
    
    # Final progress update
    elapsed = time.time() - start_time
    update_progress(attempts, force=True)
    print(f"\n✗ Password not found after {attempts} attempts in {elapsed:.1f} seconds.")
    return None


def main():
    """Main function to handle command-line arguments and execute decryption."""
    parser = argparse.ArgumentParser(
        description='Decrypt password-protected PDF files',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Decrypt with known password:
  %(prog)s input.pdf -p mypassword
  
  # Guess password using common passwords:
  %(prog)s input.pdf --guess
  
  # Use wordlist file:
  %(prog)s input.pdf --guess --wordlist passwords.txt
  
  # Brute force (up to 4 characters):
  %(prog)s input.pdf --guess --brute-force --max-length 4
        """
    )
    
    parser.add_argument(
        'input',
        help='Path to the encrypted PDF file'
    )
    
    parser.add_argument(
        '-o', '--output',
        help='Path for the decrypted PDF output file (default: adds "_decrypted" to input filename)'
    )
    
    parser.add_argument(
        '-p', '--password',
        help='Password to decrypt the PDF (required unless using --guess)'
    )
    
    # Password guessing options
    parser.add_argument(
        '--guess',
        action='store_true',
        help='Attempt to guess the password (tries common passwords and wordlists)'
    )
    
    parser.add_argument(
        '--wordlist',
        help='Path to a wordlist file containing passwords to try'
    )
    
    parser.add_argument(
        '--no-common',
        action='store_true',
        help='Skip trying common passwords (only use wordlist/brute force)'
    )
    
    parser.add_argument(
        '--brute-force',
        action='store_true',
        help='Enable brute force attack (WARNING: very slow for longer passwords)'
    )
    
    parser.add_argument(
        '--max-length',
        type=int,
        default=4,
        help='Maximum password length for brute force (default: 4, WARNING: higher values take exponentially longer)'
    )
    
    parser.add_argument(
        '--charset',
        help='Character set for brute force (default: lowercase letters and digits). Examples: "abc123", "abcdefghijklmnopqrstuvwxyz0123456789"'
    )
    
    parser.add_argument(
        '--charset-preset',
        choices=['lower', 'upper', 'mixed', 'alphanumeric', 'alphanumeric-upper', 'alphanumeric-mixed', 'all', 'common-special'],
        help='Preset character sets: lower (a-z, 0-9), upper (A-Z, 0-9), mixed (a-z, A-Z, 0-9), alphanumeric (same as mixed), alphanumeric-upper (A-Z, 0-9), alphanumeric-mixed (a-z, A-Z, 0-9), all (all printable ASCII), common-special (a-z, A-Z, 0-9, common special characters)'
    )
    
    parser.add_argument(
        '--threads',
        type=int,
        default=None,
        help='Number of parallel threads to use for password guessing (default: number of CPU cores). More threads = faster but uses more CPU.'
    )
    
    args = parser.parse_args()
    
    # Validate input file exists
    input_path = Path(args.input)
    if not input_path.exists():
        print(f"Error: Input file '{args.input}' does not exist.")
        sys.exit(1)
    
    if not input_path.suffix.lower() == '.pdf':
        print(f"Warning: Input file '{args.input}' does not have a .pdf extension.")
    
    # Determine output path
    if args.output:
        output_path = Path(args.output)
    else:
        # Create output filename by adding "_decrypted" before the extension
        output_path = input_path.parent / f"{input_path.stem}_decrypted{input_path.suffix}"
    
    # Check if output file already exists
    if output_path.exists():
        response = input(f"Output file '{output_path}' already exists. Overwrite? (y/N): ")
        if response.lower() != 'y':
            print("Operation cancelled.")
            sys.exit(0)
    
    # Handle password guessing or direct decryption
    password = args.password
    
    if args.guess or not password:
        if not args.guess and not password:
            print("Error: Either provide a password with -p/--password or use --guess to attempt password cracking.")
            sys.exit(1)
        
        # Attempt to guess the password
        # Handle charset preset or custom charset
        if args.charset_preset:
            preset_charsets = {
                'lower': string.ascii_lowercase + string.digits,  # a-z, 0-9 (36 chars)
                'upper': string.ascii_uppercase + string.digits,  # A-Z, 0-9 (36 chars)
                'mixed': string.ascii_lowercase + string.ascii_uppercase + string.digits,  # a-z, A-Z, 0-9 (62 chars)
                'alphanumeric': string.ascii_lowercase + string.ascii_uppercase + string.digits,  # Same as mixed
                'alphanumeric-upper': string.ascii_uppercase + string.digits,  # A-Z, 0-9 (36 chars)
                'alphanumeric-mixed': string.ascii_lowercase + string.ascii_uppercase + string.digits,  # Same as mixed
                'all': string.ascii_letters + string.digits + string.punctuation,  # All printable ASCII (94 chars)
                'common-special': string.ascii_letters + string.digits + '!@#$%^&*',  # a-z, A-Z, 0-9, common special (70 chars)
            }
            charset = preset_charsets[args.charset_preset]
        else:
            charset = args.charset if args.charset else None
        
        password = guess_password(
            str(input_path),
            wordlist=args.wordlist,
            use_common=not args.no_common,
            brute_force=args.brute_force,
            max_length=args.max_length,
            charset=charset,
            threads=args.threads
        )
        
        if not password:
            print("\nFailed to guess the password. Try:")
            print("  - Using a larger wordlist with --wordlist")
            print("  - Increasing --max-length for brute force (warning: very slow)")
            print("  - Providing the password directly with -p/--password")
            sys.exit(1)
        
        print(f"\nFound password: '{password}'")
        print("Proceeding to decrypt...\n")
    
    # Perform decryption
    success = decrypt_pdf(str(input_path), str(output_path), password)
    
    if not success:
        sys.exit(1)


if __name__ == '__main__':
    main()

