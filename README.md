# pydecrypt

**pydecrypt** is a Python-based tool designed for parsing and decrypting protected media files, including **MP4 (CENC/CBCS)** and **WebM** formats. The project emphasizes accurate handling of encryption metadata, sample-level processing, and reliable stream-based decryption.

---

## Features

* Support for **fragmented and non-fragmented MP4** files
* Decryption of **CENC (CTR)** and **CBCS** protected content
* **WebM (EBML)** parsing with encrypted stream support
* Proper handling of **IVs, subsamples, and track-level metadata**
* Stream-oriented processing suitable for large media files

---

## Requirements

* Python 3.9 or higher
* `cryptography` library

Installation:

```bash
pip install cryptography
```

---

## Usage

```bash
python pydecrypt.py -i input_file -o output_file -k KID:KEY
```

---

## Notes

This project was developed primarily as a personal initiative to better understand the structure and encryption mechanisms of **WebM files**.
Support for additional media formats was later incorporated to broaden the scope and functionality of the project.

---

## Issues and Support

If you encounter any issues, please open an issue in the repository.
Support and maintenance will be provided as time permits.

---

## Acknowledgements

Thank you for your interest in this project.
