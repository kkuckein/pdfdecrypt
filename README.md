# PDF Decryption Tool

A Python command-line tool to decrypt password-protected PDF files and save them as unencrypted PDFs.

## Features

- Decrypt password-protected PDF files
- **Password guessing/cracking** - Automatically try to find the password
  - Common password patterns (password, 123456, etc.)
  - Wordlist support
  - Brute force attack (configurable length)
- Automatic output filename generation (adds "_decrypted" suffix)
- Password validation
- Error handling for incorrect passwords and missing files

## Installation

1. Install Python 3.7 or higher
2. Install required dependencies:

```bash
pip install -r requirements.txt
```

Or install directly:

```bash
pip install pypdf
```

## Usage

### Basic Usage (With Known Password)

```bash
python pdfdecrypt.py input.pdf -p password
```

This will create `input_decrypted.pdf` in the same directory.

### Password Guessing (When You Don't Know the Password)

The tool can automatically try to guess the password using multiple methods:

#### Try Common Passwords

```bash
python pdfdecrypt.py input.pdf --guess
```

This will try common passwords like "password", "123456", numeric sequences, years, and common patterns.

#### Use a Wordlist File

```bash
python pdfdecrypt.py input.pdf --guess --wordlist passwords.txt
```

Create a text file with one password per line, and the tool will try each one.

#### Brute Force Attack

```bash
python pdfdecrypt.py input.pdf --guess --brute-force --max-length 4
```

**Warning**: Brute force can be very slow. Each additional character increases the time exponentially:
- 4 characters: ~1.5 million combinations
- 5 characters: ~60 million combinations
- 6 characters: ~2.2 billion combinations

#### Combine Methods

```bash
# Try wordlist first, then common passwords, then brute force
python pdfdecrypt.py input.pdf --guess --wordlist mylist.txt --brute-force --max-length 3
```

### Specify Output File

```bash
python pdfdecrypt.py input.pdf -o output.pdf -p password
# or with guessing:
python pdfdecrypt.py input.pdf --guess -o output.pdf
```

## Command-Line Arguments

### Required Arguments
- `input`: Path to the encrypted PDF file

### Password Options (choose one)
- `-p, --password`: Password to decrypt the PDF (use if you know the password)
- `--guess`: Attempt to guess the password automatically

### Password Guessing Options
- `--wordlist PATH`: Path to a wordlist file (one password per line)
- `--no-common`: Skip trying common passwords (only use wordlist/brute force)
- `--brute-force`: Enable brute force attack (WARNING: very slow)
- `--max-length N`: Maximum password length for brute force (default: 4)
- `--charset STRING`: Custom character set for brute force (default: lowercase letters + digits)
- `--charset-preset PRESET`: Use a preset character set (see Character Sets section below)
- `--threads N`: Number of parallel threads to use (default: number of CPU cores). More threads = faster processing

### Output Options
- `-o, --output`: Path for the decrypted PDF output file. If not specified, adds "_decrypted" to the input filename

## Examples

### With Known Password

```bash
# Decrypt with automatic output naming
python pdfdecrypt.py document.pdf -p secret123

# Decrypt with custom output name
python pdfdecrypt.py file.pdf -p password --output unlocked.pdf

# Decrypt with short flags
python pdfdecrypt.py input.pdf -o output.pdf -p pass
```

### Password Guessing Examples

```bash
# Try common passwords only
python pdfdecrypt.py encrypted.pdf --guess

# Use a wordlist file
python pdfdecrypt.py encrypted.pdf --guess --wordlist common-passwords.txt

# Brute force up to 3 characters (relatively fast, uses all CPU cores)
python pdfdecrypt.py encrypted.pdf --guess --brute-force --max-length 3

# Use more threads for faster brute force (if you have many CPU cores)
python pdfdecrypt.py encrypted.pdf --guess --brute-force --max-length 4 --threads 8

# Try wordlist, then common passwords, then brute force
python pdfdecrypt.py encrypted.pdf --guess --wordlist mylist.txt --brute-force --max-length 3

# Custom character set for brute force (only numbers)
python pdfdecrypt.py encrypted.pdf --guess --brute-force --max-length 6 --charset "0123456789"

# Use preset with special characters
python pdfdecrypt.py encrypted.pdf --guess --brute-force --max-length 4 --charset-preset common-special

# Use all printable ASCII characters (includes all special chars)
python pdfdecrypt.py encrypted.pdf --guess --brute-force --max-length 3 --charset-preset all

# Skip common passwords, only use wordlist
python pdfdecrypt.py encrypted.pdf --guess --wordlist passwords.txt --no-common
```

## Character Sets

### Default Character Set
By default, brute force uses: **lowercase letters (a-z) and digits (0-9)** = 36 characters
- Does NOT include uppercase letters or special characters

### Character Set Presets

Use `--charset-preset` for convenient character set selection:

- **`lower`**: a-z, 0-9 (36 chars) - Default
- **`upper`**: A-Z, 0-9 (36 chars)
- **`mixed`**: a-z, A-Z, 0-9 (62 chars)
- **`alphanumeric`**: Same as `mixed` (62 chars)
- **`alphanumeric-upper`**: A-Z, 0-9 (36 chars)
- **`alphanumeric-mixed`**: a-z, A-Z, 0-9 (62 chars)
- **`common-special`**: a-z, A-Z, 0-9, !@#$%^&* (70 chars) - Includes common special characters
- **`all`**: All printable ASCII (a-z, A-Z, 0-9, and all punctuation) (94 chars)

### Custom Character Sets

You can also specify a custom character set with `--charset`:

```bash
# Only numbers
--charset "0123456789"

# Numbers and common special chars
--charset "0123456789!@#$%"

# Custom mix
--charset "abcdefghijklmnopqrstuvwxyz0123456789!@#"
```

**Note**: Adding more characters exponentially increases the search space. For example:
- 4 chars with 36 chars (lower+digits): 36^4 = 1.6 million combinations
- 4 chars with 70 chars (common-special): 70^4 = 24 million combinations  
- 4 chars with 94 chars (all): 94^4 = 78 million combinations

## Creating a Wordlist

You can create your own wordlist file with potential passwords. Create a text file with one password per line:

```text
password
123456
mypassword
birthday2023
companyname
```

Save it as `passwords.txt` and use it with `--wordlist passwords.txt`.

## Performance Optimization

The tool uses **parallel processing** to speed up password guessing:

- **Automatic multithreading**: Uses all available CPU cores by default
- **Cached PDF readers**: Reuses PDF readers per thread to avoid overhead
- **Batch processing**: Tests passwords in batches for better efficiency
- **Custom thread count**: Use `--threads N` to control parallelism

**Speed improvements:**
- Wordlists: 4-8x faster with parallel processing
- Brute force: 4-8x faster (scales with CPU cores)
- Common passwords: 2-4x faster

Example: On an 8-core CPU, brute force can be **6-8x faster** than single-threaded!

## Password Guessing Strategy

The tool tries passwords in this order (when using `--guess`):

1. **Wordlist** (if provided): Tries each password from your wordlist file
2. **Common Passwords**: Tries hundreds of common passwords and patterns including:
   - Common passwords (password, 123456, etc.)
   - Numeric sequences (0-9999)
   - Years (1900-2024)
   - Common patterns (password123, admin2023, etc.)
3. **Brute Force** (if enabled): Systematically tries all combinations up to the specified length

**Tips for Success:**
- Start with `--guess` (common passwords) - it's fast and often works
- If that fails, create a wordlist with passwords you think might work
- Only use brute force as a last resort, and keep `--max-length` low (3-4) unless you have time
- For numeric-only passwords, use `--charset "0123456789"` to speed up brute force

## Error Handling

The tool handles various error cases:
- Missing input files
- Incorrect passwords
- Non-encrypted PDFs (warns and exits)
- File permission issues
- Wordlist file errors

## Requirements

- Python 3.7+
- pypdf library (or PyPDF2 for older compatibility)

## License

This project is provided as-is for educational and personal use.

