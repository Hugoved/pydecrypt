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

## Script Example

The following example demonstrates a structured way to use **pydecrypt** within a standalone script:

```python
import sys
import pydecrypt

input_file = "encrypted_media.mp4"
output_file = "decrypted_media.mp4"
decryption_key = "de16439108cc4754bfb9dadc03a258a0:331a70d43154c5aca52a37e875623ac4"

show_tracks = True
preserve_text_tracks = False

try:
    keys_by_track, keys_by_kid = pydecrypt.parse_keys([decryption_key])

    if pydecrypt.is_webm_file(input_file):
        pydecrypt.decrypt_webm_file(
            input_path=input_file,
            output_path=output_file,
            keys_by_track=keys_by_track,
            keys_by_kid=keys_by_kid,
            show_tracks=show_tracks,
            drop_text=not preserve_text_tracks,
        )
    else:
        pydecrypt.decrypt_mp4_file(
            input_path=input_file,
            output_path=output_file,
            keys_by_track=keys_by_track,
            keys_by_kid=keys_by_kid,
            show_tracks=show_tracks,
        )

except KeyboardInterrupt:
    raise SystemExit(130)
except Exception as error:
    print(f"Decryption failed: {error}", file=sys.stderr)
    raise SystemExit(1)
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
