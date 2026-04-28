import argparse
import mmap
import os
import struct
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Tuple
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

CONTAINER_TYPES = {
    b"moov", b"trak", b"mdia", b"minf", b"stbl", b"edts", b"dinf", b"mvex", b"moof", b"traf",
    b"mfra", b"skip", b"meta", b"ipro", b"sinf", b"schi", b"udta", b"ilst", b"stsd", b"mvhd"
}
FULL_BOX_TYPES = {
    b"mvhd", b"tkhd", b"mdhd", b"hdlr", b"vmhd", b"smhd", b"hmhd", b"nmhd", b"dref", b"stsd",
    b"stts", b"ctts", b"stsc", b"stsz", b"stz2", b"stco", b"co64", b"stss", b"mvex", b"trex",
    b"mfhd", b"tfhd", b"trun", b"tfdt", b"sidx", b"saiz", b"saio", b"sbgp", b"sgpd", b"senc",
    b"mehd", b"elst", b"url ", b"urn ", b"schm", b"pssh"
}
PROTECTED_SAMPLE_ENTRY_TYPES = {b"enca", b"encv", b"enct", b"encs", b"drms", b"drmi", b"p608"}
VISUAL_SAMPLE_ENTRY_TYPES = {b"avc1", b"avc2", b"avc3", b"avc4", b"hev1", b"hvc1", b"dvhe", b"dvh1", b"encv", b"av01", b"vp09"}
AUDIO_SAMPLE_ENTRY_TYPES = {b"mp4a", b"ac-3", b"ec-3", b"ac-4", b"enca", b"alac", b"fLaC", b"opus"}
HINT_SAMPLE_ENTRY_TYPES = {b"rtp ", b"srtp", b"rrtp"}
TEXT_SAMPLE_ENTRY_TYPES = {b"tx3g", b"wvtt", b"stpp", b"sbtt", b"enct", b"c608"}
SUBTITLE_SAMPLE_ENTRY_TYPES = {b"stpp", b"wvtt", b"sbtt", b"tx3g", b"enct"}
TEXT_HANDLER_TYPES = {b"text", b"sbtl", b"subt", b"clcp"}
PIFF_TRACK_ENCRYPTION_UUID = bytes.fromhex("8974dbce7be74c5184f97148f9882554")
PIFF_SAMPLE_ENCRYPTION_UUID = bytes.fromhex("a2394f525a9b4f14a2446c427c648df4")

DEFAULT_COPY_CHUNK = 32 * 1024 * 1024
PROGRESS_UPDATE_INTERVAL = 0.50

WEBM_ID_EBML = 0x1A45DFA3
WEBM_ID_SEGMENT = 0x18538067
WEBM_ID_SEEK_HEAD = 0x114D9B74
WEBM_ID_INFO = 0x1549A966
WEBM_ID_TRACKS = 0x1654AE6B
WEBM_ID_CLUSTER = 0x1F43B675
WEBM_ID_CUES = 0x1C53BB6B
WEBM_ID_TAGS = 0x1254C367
WEBM_ID_CHAPTERS = 0x1043A770
WEBM_ID_ATTACHMENTS = 0x1941A469
WEBM_ID_VOID = 0xEC
WEBM_ID_CRC32 = 0xBF
WEBM_ID_TRACK_ENTRY = 0xAE
WEBM_ID_TRACK_NUMBER = 0xD7
WEBM_ID_TRACK_UID = 0x73C5
WEBM_ID_TRACK_TYPE = 0x83
WEBM_ID_CODEC_ID = 0x86
WEBM_ID_NAME = 0x536E
WEBM_ID_LANGUAGE = 0x22B59C
WEBM_ID_CONTENT_ENCODINGS = 0x6D80
WEBM_ID_CONTENT_ENCODING = 0x6240
WEBM_ID_CONTENT_ENCRYPTION = 0x5035
WEBM_ID_CONTENT_ENC_KEY_ID = 0x47E2
WEBM_ID_SIMPLE_BLOCK = 0xA3
WEBM_ID_BLOCK_GROUP = 0xA0
WEBM_ID_BLOCK = 0xA1
WEBM_TRACK_TYPE_VIDEO = 1
WEBM_TRACK_TYPE_AUDIO = 2
WEBM_TRACK_TYPE_SUBTITLE = 0x11
WEBM_TRACK_TYPE_METADATA = 0x21
WEBM_SIGNAL_BYTE_SIZE = 1
WEBM_IV_SIZE = 8
WEBM_ENCRYPTED_SIGNAL = 0x01
WEBM_PARTITIONED_SIGNAL = 0x02
WEBM_NUM_PARTITIONS_SIZE = 1
WEBM_PARTITION_OFFSET_SIZE = 4

def u8(data, offset):
    return data[offset]

def u16(data, offset):
    return struct.unpack_from(">H", data, offset)[0]

def u24(data, offset):
    return (data[offset] << 16) | (data[offset + 1] << 8) | data[offset + 2]

def u32(data, offset):
    return struct.unpack_from(">I", data, offset)[0]

def u64(data, offset):
    return struct.unpack_from(">Q", data, offset)[0]

def normalize_kid(text: str) -> bytes:
    text = text.strip().lower().replace("0x", "").replace("-", "")
    if len(text) != 32:
        raise ValueError("KID must be 32 hex characters")
    return bytes.fromhex(text)

def normalize_key(text: str) -> bytes:
    text = text.strip().lower().replace("0x", "").replace("-", "")
    if len(text) != 32:
        raise ValueError("Key must be 32 hex characters")
    return bytes.fromhex(text)

@dataclass
class Box:
    start: int
    size: int
    type: bytes
    header_size: int
    end: int
    uuid: Optional[bytes] = None
    children: List["Box"] = field(default_factory=list)


@dataclass
class SampleAuxInfo:
    iv: bytes
    subsamples: List[Tuple[int, int]]


@dataclass
class TencInfo:
    is_encrypted: int
    iv_size: int
    kid: bytes
    constant_iv: bytes
    crypt_byte_block: int
    skip_byte_block: int
    scheme: bytes


@dataclass
class TrackInfo:
    track_id: int
    timescale: int = 0
    handler_type: bytes = b""
    sample_count: int = 0
    sample_sizes: List[int] = field(default_factory=list)
    sample_offsets: List[int] = field(default_factory=list)
    scheme: bytes = b""
    tenc: Optional[TencInfo] = None
    sample_entry_box: Optional[Box] = None
    original_format: Optional[bytes] = None
    aux_info: List[SampleAuxInfo] = field(default_factory=list)
    default_sample_size: int = 0
    codec_format: bytes = b""
    nal_length_size: int = 0
    nal_header_clear_bytes: int = 0


@dataclass
class FragmentRun:
    track_id: int
    trun_box: Box
    tfhd_box: Optional[Box]
    traf_box: Box
    data_offset: int
    sample_sizes: List[int]
    sample_offsets: List[int]
    aux_info: List[SampleAuxInfo]
    scheme: bytes
    tenc: Optional[TencInfo]


@dataclass
class BytePatch:
    start: int
    data: bytes

    @property
    def end(self) -> int:
        return self.start + len(self.data)


@dataclass
class DecryptTask:
    start: int
    size: int
    key: bytes
    info: SampleAuxInfo
    scheme: bytes
    tenc: TencInfo
    codec_format: bytes = b""
    nal_length_size: int = 0
    nal_header_clear_bytes: int = 0

    @property
    def end(self) -> int:
        return self.start + self.size


@dataclass
class StreamEvent:
    start: int
    end: int
    kind: str
    payload: object


@dataclass
class EbmlElement:
    id_value: int
    id_bytes: bytes
    size_value: Optional[int]
    size_len: int
    data_start: int
    data_end: int
    header_start: int
    header_end: int
    end: int
    unknown_size: bool


@dataclass
class WebMTrack:
    track_number: int
    track_uid: Optional[int] = None
    track_type: Optional[int] = None
    codec_id: str = ""
    name: str = ""
    language: str = ""
    key_id: bytes = b""
    encrypted: bool = False
    content_encodings_start_rel: Optional[int] = None
    content_encodings_end_rel: Optional[int] = None


class ProgressPrinter:
    def __init__(self, total_size: int):
        self.total_size = max(total_size, 1)
        self.started_at = time.monotonic()
        self.last_update = 0.0
        self.last_line_length = 0
        self.done = 0

    @staticmethod
    def _format_hms(seconds: float) -> str:
        seconds = max(0, int(seconds))
        hours, rem = divmod(seconds, 3600)
        minutes, seconds = divmod(rem, 60)
        return f"{hours:02d}:{minutes:02d}:{seconds:02d}"

    def _line(self) -> str:
        ratio = min(max(self.done / self.total_size, 0.0), 1.0)
        width = 40
        filled = min(width, int(ratio * width))
        bar = "■" * filled + " " * (width - filled)
        percent = ratio * 100.0
        elapsed = time.monotonic() - self.started_at
        speed = self.done / elapsed if elapsed > 0 else 0.0
        remaining = (self.total_size - self.done) / speed if speed > 0 else 0.0
        return (
            f"[{bar}] {percent:6.2f}% "
            f"(elapsed: {self._format_hms(elapsed)}, remaining: {self._format_hms(remaining)})"
        )

    def update(self, done: int, force: bool = False):
        self.done = max(0, min(done, self.total_size))
        now = time.monotonic()
        if not force and (now - self.last_update) < PROGRESS_UPDATE_INTERVAL and self.done < self.total_size:
            return
        line = self._line()
        clear_pad = " " * max(0, self.last_line_length - len(line))
        sys.stdout.write("\r" + line + clear_pad)
        sys.stdout.flush()
        self.last_line_length = len(line)
        self.last_update = now

    def finish(self):
        self.update(self.total_size, force=True)
        sys.stdout.write("\n")
        sys.stdout.flush()

class Mp4Parser:
    def __init__(self, data: bytes):
        self.data = data
        self.root = self.parse_children(0, len(data), None)

    def parse_children(self, start: int, end: int, parent_type: Optional[bytes]) -> List[Box]:
        boxes = []
        pos = start
        while pos + 8 <= end:
            size = u32(self.data, pos)
            box_type = self.data[pos + 4:pos + 8]
            header_size = 8
            if size == 1:
                if pos + 16 > end:
                    break
                size = u64(self.data, pos + 8)
                header_size = 16
            elif size == 0:
                size = end - pos
            if size < header_size or pos + size > end:
                break
            box_uuid = None
            if box_type == b"uuid":
                if pos + header_size + 16 > end:
                    break
                box_uuid = self.data[pos + header_size:pos + header_size + 16]
                header_size += 16
            box = Box(pos, size, box_type, header_size, pos + size, box_uuid)
            content_start = pos + header_size
            if box_type == b"meta" and content_start + 4 <= box.end:
                content_start += 4
                box.header_size += 4
            if self.is_container(box, parent_type):
                box.children = self.parse_children(content_start, box.end, box_type)
            boxes.append(box)
            pos += size
        return boxes

    def is_container(self, box: Box, parent_type: Optional[bytes]) -> bool:
        if box.type in {b"moov", b"trak", b"mdia", b"minf", b"stbl", b"edts", b"dinf", b"mvex", b"moof", b"traf", b"mfra", b"skip", b"udta", b"ipro", b"sinf", b"schi", b"ilst"}:
            return True
        if box.type == b"stsd":
            return False
        if box.type == b"meta":
            return True
        return False

    def find_children(self, parent: Box, box_type: bytes) -> List[Box]:
        return [child for child in parent.children if child.type == box_type]

    def find_child(self, parent: Box, box_type: bytes) -> Optional[Box]:
        for child in parent.children:
            if child.type == box_type:
                return child
        return None

    def find_uuid_child(self, parent: Box, uuid_value: bytes) -> Optional[Box]:
        for child in parent.children:
            if child.type == b"uuid" and child.uuid == uuid_value:
                return child
        return None


def parse_tkhd(data: bytes, tkhd: Box) -> int:
    version = u8(data, tkhd.start + tkhd.header_size)
    offset = tkhd.start + tkhd.header_size + 4
    if version == 1:
        return u32(data, offset + 16)
    return u32(data, offset + 8)


def parse_mdhd_timescale(data: bytes, mdhd: Box) -> int:
    version = u8(data, mdhd.start + mdhd.header_size)
    offset = mdhd.start + mdhd.header_size + 4
    if version == 1:
        return u32(data, offset + 16)
    return u32(data, offset + 8)


def parse_hdlr(data: bytes, hdlr: Box) -> bytes:
    return data[hdlr.start + hdlr.header_size + 8:hdlr.start + hdlr.header_size + 12]


def parse_stsz(data: bytes, box: Box) -> List[int]:
    offset = box.start + box.header_size + 4
    sample_size = u32(data, offset)
    sample_count = u32(data, offset + 4)
    sizes = []
    if sample_size:
        sizes = [sample_size] * sample_count
    else:
        pos = offset + 8
        for _ in range(sample_count):
            sizes.append(u32(data, pos))
            pos += 4
    return sizes


def parse_stz2(data: bytes, box: Box) -> List[int]:
    offset = box.start + box.header_size + 4
    field_size = u8(data, offset + 3)
    sample_count = u32(data, offset + 4)
    pos = offset + 8
    sizes: List[int] = []
    if field_size == 4:
        for _ in range((sample_count + 1) // 2):
            packed = u8(data, pos)
            pos += 1
            sizes.append((packed >> 4) & 0x0F)
            if len(sizes) < sample_count:
                sizes.append(packed & 0x0F)
    elif field_size == 8:
        for _ in range(sample_count):
            sizes.append(u8(data, pos))
            pos += 1
    elif field_size == 16:
        for _ in range(sample_count):
            sizes.append(u16(data, pos))
            pos += 2
    else:
        raise ValueError(f"Unsupported stz2 field size: {field_size}")
    return sizes


def parse_stco(data: bytes, box: Box) -> List[int]:
    offset = box.start + box.header_size + 4
    entry_count = u32(data, offset)
    pos = offset + 4
    values = []
    if box.type == b"stco":
        for _ in range(entry_count):
            values.append(u32(data, pos))
            pos += 4
    else:
        for _ in range(entry_count):
            values.append(u64(data, pos))
            pos += 8
    return values


def parse_stsc(data: bytes, box: Box) -> List[Tuple[int, int, int]]:
    offset = box.start + box.header_size + 4
    entry_count = u32(data, offset)
    pos = offset + 4
    values = []
    for _ in range(entry_count):
        values.append((u32(data, pos), u32(data, pos + 4), u32(data, pos + 8)))
        pos += 12
    return values


def compute_sample_offsets(chunk_offsets: List[int], stsc: List[Tuple[int, int, int]], sample_sizes: List[int]) -> List[int]:
    if not chunk_offsets or not stsc or not sample_sizes:
        return []
    offsets = []
    sample_index = 0
    for i, (first_chunk, samples_per_chunk, _) in enumerate(stsc):
        next_first_chunk = stsc[i + 1][0] if i + 1 < len(stsc) else len(chunk_offsets) + 1
        for chunk_number in range(first_chunk, next_first_chunk):
            if chunk_number - 1 >= len(chunk_offsets):
                break
            current = chunk_offsets[chunk_number - 1]
            for _ in range(samples_per_chunk):
                if sample_index >= len(sample_sizes):
                    break
                offsets.append(current)
                current += sample_sizes[sample_index]
                sample_index += 1
    return offsets


def parse_tenc_from_bytes(data: bytes, start: int, size: int, scheme: bytes) -> TencInfo:
    header_size = 8
    if u32(data, start) == 1:
        header_size = 16
    if data[start + 4:start + 8] == b"uuid":
        header_size += 16
    version = u8(data, start + header_size)
    pos = start + header_size + 4
    crypt_byte_block = 0
    skip_byte_block = 0

    if version == 0:
        pos += 2
    else:
        # Version 1 tenc in the wild is commonly laid out as:
        #   reserved (8)
        #   default_crypt_byte_block (4) + default_skip_byte_block (4)
        #   default_isProtected (8)
        #   default_Per_Sample_IV_Size (8)
        #
        # Some files use 0x00 0x19 0x01 0x00... for CBCS/HEVC, where 0x19 means
        # crypt_byte_block=1 and skip_byte_block=9. Reading the first byte as the
        # pattern byte produces 0/0 and breaks decryption badly.
        reserved_or_pattern = u8(data, pos)
        next_byte = u8(data, pos + 1)

        if reserved_or_pattern == 0 and next_byte != 0:
            block_info = next_byte
            pos += 2
        else:
            block_info = reserved_or_pattern
            pos += 2

        crypt_byte_block = block_info >> 4
        skip_byte_block = block_info & 0x0F

    is_encrypted = u8(data, pos)
    iv_size = u8(data, pos + 1)
    kid = data[pos + 2:pos + 18]
    pos += 18
    constant_iv = b""
    if is_encrypted and iv_size == 0 and pos < start + size:
        constant_iv_size = u8(data, pos)
        constant_iv = data[pos + 1:pos + 1 + constant_iv_size]
    return TencInfo(is_encrypted, iv_size, kid, constant_iv, crypt_byte_block, skip_byte_block, scheme)


def parse_avcc_nal_length_size(payload: bytes) -> int:
    if len(payload) < 5:
        return 0
    return (payload[4] & 0x03) + 1


def parse_hvcc_nal_length_size(payload: bytes) -> int:
    if len(payload) < 22:
        return 0
    return (payload[21] & 0x03) + 1


def parse_codec_fallback_info(data: bytes, entry_start: int, entry_end: int) -> Tuple[bytes, int, int]:
    scan = entry_start
    while scan + 8 <= entry_end:
        child_size = u32(data, scan)
        child_type = data[scan + 4:scan + 8]
        child_header = 8
        if child_size == 1:
            if scan + 16 > entry_end:
                break
            child_size = u64(data, scan + 8)
            child_header = 16
        elif child_size == 0:
            child_size = entry_end - scan
        if child_size < child_header or scan + child_size > entry_end:
            break
        payload = data[scan + child_header:scan + child_size]
        if child_type == b"avcC":
            nal_length_size = parse_avcc_nal_length_size(payload)
            return b"avc1", nal_length_size, 1
        if child_type == b"hvcC":
            nal_length_size = parse_hvcc_nal_length_size(payload)
            return b"hvc1", nal_length_size, 2
        scan += child_size
    return b"", 0, 0


def parse_stsd_sample_entry(data: bytes, stsd: Box) -> Tuple[Optional[Box], Optional[bytes], bytes, Optional[TencInfo], bytes, int, int]:
    pos = stsd.start + stsd.header_size + 4
    entry_count = u32(data, pos)
    pos += 4
    if entry_count < 1 or pos + 8 > stsd.end:
        return None, None, b"", None, b"", 0, 0
    entry_size = u32(data, pos)
    entry_type = data[pos + 4:pos + 8]
    if entry_size < 8 or pos + entry_size > stsd.end:
        return None, None, b"", None, b"", 0, 0
    entry_box = Box(pos, entry_size, entry_type, 8, pos + entry_size)
    original_format = None
    scheme = b""
    tenc = None
    sinf_pos = None
    scan_start = entry_box.start + entry_box.header_size
    scan_end = entry_box.end - 8
    for candidate in range(scan_start, scan_end + 1):
        child_size = u32(data, candidate)
        child_type = data[candidate + 4:candidate + 8]
        child_header = 8
        if child_size == 1:
            if candidate + 16 > entry_box.end:
                continue
            child_size = u64(data, candidate + 8)
            child_header = 16
        elif child_size == 0:
            child_size = entry_box.end - candidate
        if child_type == b"uuid":
            if candidate + child_header + 16 > entry_box.end:
                continue
            child_header += 16
        if child_type == b"sinf" and child_size >= child_header and candidate + child_size <= entry_box.end:
            sinf_pos = candidate
            break
    if sinf_pos is None:
        codec_format, nal_length_size, nal_header_clear_bytes = parse_codec_fallback_info(data, entry_box.start + entry_box.header_size, entry_box.end)
        return entry_box, None, b"", None, codec_format, nal_length_size, nal_header_clear_bytes
    sinf_size = u32(data, sinf_pos)
    sinf_header = 8
    if sinf_size == 1:
        sinf_size = u64(data, sinf_pos + 8)
        sinf_header = 16
    elif sinf_size == 0:
        sinf_size = entry_box.end - sinf_pos
    sinf_end = sinf_pos + sinf_size
    sub = sinf_pos + sinf_header
    while sub + 8 <= sinf_end:
        sub_size = u32(data, sub)
        sub_type = data[sub + 4:sub + 8]
        sub_header = 8
        sub_uuid = None
        if sub_size == 1:
            sub_size = u64(data, sub + 8)
            sub_header = 16
        elif sub_size == 0:
            sub_size = sinf_end - sub
        if sub_type == b"uuid":
            if sub + sub_header + 16 > sinf_end:
                break
            sub_uuid = data[sub + sub_header:sub + sub_header + 16]
            sub_header += 16
        if sub_size < sub_header or sub + sub_size > sinf_end:
            break
        if sub_type == b"frma":
            original_format = data[sub + sub_header:sub + sub_header + 4]
        elif sub_type == b"schm":
            scheme = data[sub + sub_header + 4:sub + sub_header + 8]
        elif sub_type == b"schi":
            schi_end = sub + sub_size
            schi_pos = sub + sub_header
            while schi_pos + 8 <= schi_end:
                schi_size = u32(data, schi_pos)
                schi_type = data[schi_pos + 4:schi_pos + 8]
                schi_header = 8
                schi_uuid = None
                if schi_size == 1:
                    schi_size = u64(data, schi_pos + 8)
                    schi_header = 16
                elif schi_size == 0:
                    schi_size = schi_end - schi_pos
                if schi_type == b"uuid":
                    if schi_pos + schi_header + 16 > schi_end:
                        break
                    schi_uuid = data[schi_pos + schi_header:schi_pos + schi_header + 16]
                    schi_header += 16
                if schi_size < schi_header or schi_pos + schi_size > schi_end:
                    break
                if schi_type == b"tenc" or (schi_type == b"uuid" and schi_uuid == PIFF_TRACK_ENCRYPTION_UUID):
                    tenc = parse_tenc_from_bytes(data, schi_pos, schi_size, scheme)
                schi_pos += schi_size
        sub += sub_size
    codec_format, nal_length_size, nal_header_clear_bytes = parse_codec_fallback_info(data, entry_box.start + entry_box.header_size, entry_box.end)
    return entry_box, original_format, scheme, tenc, codec_format, nal_length_size, nal_header_clear_bytes


def parse_senc_payload(blob: bytes, iv_size_hint: int, default_constant_iv: bytes) -> List[SampleAuxInfo]:
    if len(blob) < 8:
        return []
    flags = (blob[1] << 16) | (blob[2] << 8) | blob[3]
    sample_count = struct.unpack_from(">I", blob, 4)[0]
    pos = 8
    records = []
    use_subsamples = (flags & 0x000002) != 0
    for _ in range(sample_count):
        if iv_size_hint == 0:
            iv = default_constant_iv
        else:
            if pos + iv_size_hint > len(blob):
                break
            iv = blob[pos:pos + iv_size_hint]
            pos += iv_size_hint
        subsamples = []
        if use_subsamples:
            if pos + 2 > len(blob):
                break
            subsample_count = struct.unpack_from(">H", blob, pos)[0]
            pos += 2
            for _ in range(subsample_count):
                if pos + 6 > len(blob):
                    break
                clear_bytes = struct.unpack_from(">H", blob, pos)[0]
                encrypted_bytes = struct.unpack_from(">I", blob, pos + 2)[0]
                subsamples.append((clear_bytes, encrypted_bytes))
                pos += 6
        records.append(SampleAuxInfo(iv, subsamples))
    return records


def parse_saiz(data: bytes, box: Box) -> List[int]:
    pos = box.start + box.header_size
    flags = u24(data, pos + 1)
    pos += 4
    if flags & 1:
        pos += 8
    default_info_size = u8(data, pos)
    sample_count = u32(data, pos + 1)
    pos += 5
    if default_info_size:
        return [default_info_size] * sample_count
    sizes = []
    for _ in range(sample_count):
        sizes.append(u8(data, pos))
        pos += 1
    return sizes


def parse_saio(data: bytes, box: Box) -> List[int]:
    pos = box.start + box.header_size
    flags = u24(data, pos + 1)
    version = u8(data, pos)
    pos += 4
    if flags & 1:
        pos += 8
    entry_count = u32(data, pos)
    pos += 4
    offsets = []
    for _ in range(entry_count):
        offsets.append(u64(data, pos) if version == 1 else u32(data, pos))
        pos += 8 if version == 1 else 4
    return offsets


def parse_senc_box(data: bytes, box: Box, iv_size_hint: int, default_constant_iv: bytes) -> List[SampleAuxInfo]:
    payload = data[box.start + box.header_size:box.end]
    return parse_senc_payload(payload, iv_size_hint, default_constant_iv)


def parse_aux_info_via_saiz_saio(data: bytes, sample_info_sizes: List[int], offsets: List[int], iv_size_hint: int, default_constant_iv: bytes, offset_base: int = 0) -> List[SampleAuxInfo]:
    if not sample_info_sizes or not offsets:
        return []
    base = offset_base + offsets[0]
    total = sum(sample_info_sizes)
    if base + total > len(data):
        total = max(0, len(data) - base)
    blob = data[base:base + total]
    records = []
    pos = 0
    for sample_size in sample_info_sizes:
        if pos + sample_size > len(blob):
            break
        sample_blob = blob[pos:pos + sample_size]
        if iv_size_hint == 0:
            iv = default_constant_iv
            sub_pos = 0
        else:
            iv = sample_blob[:iv_size_hint]
            sub_pos = iv_size_hint
        subsamples = []
        if sub_pos < len(sample_blob) and sub_pos + 2 <= len(sample_blob):
            subsample_count = struct.unpack_from(">H", sample_blob, sub_pos)[0]
            sub_pos += 2
            for _ in range(subsample_count):
                if sub_pos + 6 > len(sample_blob):
                    break
                clear_bytes = struct.unpack_from(">H", sample_blob, sub_pos)[0]
                encrypted_bytes = struct.unpack_from(">I", sample_blob, sub_pos + 2)[0]
                subsamples.append((clear_bytes, encrypted_bytes))
                sub_pos += 6
        records.append(SampleAuxInfo(iv, subsamples))
        pos += sample_size
    return records


def parse_trex(data: bytes, box: Box) -> Tuple[int, int]:
    pos = box.start + box.header_size + 4
    track_id = u32(data, pos)
    default_sample_size = u32(data, pos + 12)
    return track_id, default_sample_size


def parse_tfhd(data: bytes, box: Box) -> Dict[str, int]:
    pos = box.start + box.header_size
    flags = u24(data, pos + 1)
    pos += 4
    values = {"flags": flags, "track_id": u32(data, pos)}
    pos += 4
    if flags & 0x000001:
        values["base_data_offset"] = u64(data, pos)
        pos += 8
    if flags & 0x000002:
        values["sample_description_index"] = u32(data, pos)
        pos += 4
    if flags & 0x000008:
        values["default_sample_duration"] = u32(data, pos)
        pos += 4
    if flags & 0x000010:
        values["default_sample_size"] = u32(data, pos)
        pos += 4
    if flags & 0x000020:
        values["default_sample_flags"] = u32(data, pos)
        pos += 4
    return values


def parse_trun(data: bytes, box: Box) -> Dict[str, object]:
    pos = box.start + box.header_size
    version = u8(data, pos)
    flags = u24(data, pos + 1)
    pos += 4
    sample_count = u32(data, pos)
    pos += 4
    info = {"version": version, "flags": flags, "sample_count": sample_count, "data_offset": 0, "first_sample_flags": None, "samples": []}
    if flags & 0x000001:
        info["data_offset"] = struct.unpack_from(">i", data, pos)[0]
        pos += 4
    if flags & 0x000004:
        info["first_sample_flags"] = u32(data, pos)
        pos += 4
    samples = []
    for _ in range(sample_count):
        sample = {}
        if flags & 0x000100:
            sample["duration"] = u32(data, pos)
            pos += 4
        if flags & 0x000200:
            sample["size"] = u32(data, pos)
            pos += 4
        if flags & 0x000400:
            sample["flags"] = u32(data, pos)
            pos += 4
        if flags & 0x000800:
            sample["cto"] = struct.unpack_from(">i", data, pos)[0] if version == 1 else u32(data, pos)
            pos += 4
        samples.append(sample)
    info["samples"] = samples
    return info


def build_tracks(parser: Mp4Parser) -> Tuple[Dict[int, TrackInfo], Dict[int, int]]:
    tracks: Dict[int, TrackInfo] = {}
    trex_defaults: Dict[int, int] = {}
    for box in parser.root:
        if box.type == b"moov":
            mvex = parser.find_child(box, b"mvex")
            if mvex:
                for trex in parser.find_children(mvex, b"trex"):
                    track_id, default_sample_size = parse_trex(parser.data, trex)
                    trex_defaults[track_id] = default_sample_size
            for trak in parser.find_children(box, b"trak"):
                tkhd = parser.find_child(trak, b"tkhd")
                mdia = parser.find_child(trak, b"mdia")
                if not tkhd or not mdia:
                    continue
                track_id = parse_tkhd(parser.data, tkhd)
                track = TrackInfo(track_id=track_id)
                mdhd = parser.find_child(mdia, b"mdhd")
                if mdhd:
                    track.timescale = parse_mdhd_timescale(parser.data, mdhd)
                hdlr = parser.find_child(mdia, b"hdlr")
                if hdlr:
                    track.handler_type = parse_hdlr(parser.data, hdlr)
                minf = parser.find_child(mdia, b"minf")
                stbl = parser.find_child(minf, b"stbl") if minf else None
                if stbl:
                    stsd = parser.find_child(stbl, b"stsd")
                    if stsd:
                        entry_box, original_format, scheme, tenc, codec_format, nal_length_size, nal_header_clear_bytes = parse_stsd_sample_entry(parser.data, stsd)
                        track.sample_entry_box = entry_box
                        track.original_format = original_format
                        track.scheme = scheme
                        track.tenc = tenc
                        track.codec_format = codec_format
                        track.nal_length_size = nal_length_size
                        track.nal_header_clear_bytes = nal_header_clear_bytes
                    stsz = parser.find_child(stbl, b"stsz") or parser.find_child(stbl, b"stz2")
                    if stsz:
                        if stsz.type == b"stsz":
                            track.sample_sizes = parse_stsz(parser.data, stsz)
                        else:
                            track.sample_sizes = parse_stz2(parser.data, stsz)
                        track.sample_count = len(track.sample_sizes)
                    stco = parser.find_child(stbl, b"stco") or parser.find_child(stbl, b"co64")
                    stsc = parser.find_child(stbl, b"stsc")
                    if stco and stsc and track.sample_sizes:
                        track.sample_offsets = compute_sample_offsets(parse_stco(parser.data, stco), parse_stsc(parser.data, stsc), track.sample_sizes)
                    senc = parser.find_child(stbl, b"senc") or parser.find_uuid_child(stbl, PIFF_SAMPLE_ENCRYPTION_UUID)
                    saiz = parser.find_child(stbl, b"saiz")
                    saio = parser.find_child(stbl, b"saio")
                    if track.tenc:
                        if senc:
                            track.aux_info = parse_senc_box(parser.data, senc, track.tenc.iv_size, track.tenc.constant_iv)
                        elif saiz and saio:
                            track.aux_info = parse_aux_info_via_saiz_saio(
                                parser.data,
                                parse_saiz(parser.data, saiz),
                                parse_saio(parser.data, saio),
                                track.tenc.iv_size,
                                track.tenc.constant_iv,
                                offset_base=0,
                            )
                tracks[track_id] = track
    return tracks, trex_defaults


def build_fragments(parser: Mp4Parser, tracks: Dict[int, TrackInfo], trex_defaults: Dict[int, int]) -> List[FragmentRun]:
    runs: List[FragmentRun] = []
    for moof in [box for box in parser.root if box.type == b"moof"]:
        next_top = None
        for top in parser.root:
            if top.start == moof.start:
                continue
            if top.start >= moof.end:
                next_top = top
                break
        for traf in parser.find_children(moof, b"traf"):
            tfhd = parser.find_child(traf, b"tfhd")
            if not tfhd:
                continue
            tfhd_info = parse_tfhd(parser.data, tfhd)
            track_id = tfhd_info["track_id"]
            track = tracks.get(track_id)
            tenc = track.tenc if track else None
            scheme = track.scheme if track else b""
            senc = parser.find_child(traf, b"senc") or parser.find_uuid_child(traf, PIFF_SAMPLE_ENCRYPTION_UUID)
            saiz = parser.find_child(traf, b"saiz")
            saio = parser.find_child(traf, b"saio")
            aux_info = []
            if tenc:
                if senc:
                    aux_info = parse_senc_box(parser.data, senc, tenc.iv_size, tenc.constant_iv)
                elif saiz and saio:
                    # In fragmented MP4, saio offsets inside traf/moof are commonly relative to the
                    # first byte of the enclosing moof box rather than absolute file offsets.
                    # Treating them as absolute produces wrong IV/subsample data and leads to
                    # heavily corrupted video after decryption.
                    aux_info = parse_aux_info_via_saiz_saio(
                        parser.data,
                        parse_saiz(parser.data, saiz),
                        parse_saio(parser.data, saio),
                        tenc.iv_size,
                        tenc.constant_iv,
                        offset_base=moof.start,
                    )
            default_size = tfhd_info.get("default_sample_size", trex_defaults.get(track_id, 0))
            for trun in parser.find_children(traf, b"trun"):
                trun_info = parse_trun(parser.data, trun)
                base_data_offset = tfhd_info.get("base_data_offset")
                if base_data_offset is None:
                    base_data_offset = moof.start
                data_offset = base_data_offset + trun_info["data_offset"]
                sample_sizes = []
                for sample in trun_info["samples"]:
                    sample_sizes.append(sample.get("size", default_size))
                sample_offsets = []
                current = data_offset
                for size in sample_sizes:
                    sample_offsets.append(current)
                    current += size
                run_aux_info = aux_info[:len(sample_sizes)] if aux_info else []
                if aux_info:
                    del aux_info[:len(sample_sizes)]
                runs.append(FragmentRun(track_id, trun, tfhd, traf, data_offset, sample_sizes, sample_offsets, run_aux_info, scheme, tenc))
    return runs


def aes_ecb_decryptor(key: bytes):
    cipher = Cipher(algorithms.AES(key), modes.ECB())
    return cipher.decryptor()


def decrypt_cenc_ctr(sample: bytes, key: bytes, iv: bytes, subsamples: List[Tuple[int, int]]) -> bytes:
    counter_iv = iv + (b"\x00" * (16 - len(iv)))
    cipher = Cipher(algorithms.AES(key), modes.CTR(counter_iv))
    decryptor = cipher.decryptor()
    if not subsamples:
        out = bytearray(len(sample) + 15)
        written = decryptor.update_into(sample, out)
        tail = decryptor.finalize()
        total = written + len(tail)
        if tail:
            out[written:total] = tail
        return bytes(out[:total])
    out = bytearray(sample)
    pos = 0
    for clear_bytes, encrypted_bytes in subsamples:
        pos += clear_bytes
        if encrypted_bytes:
            end = pos + encrypted_bytes
            src = memoryview(out)[pos:end]
            dst = bytearray(encrypted_bytes + 15)
            written = decryptor.update_into(src, dst)
            if written:
                out[pos:pos + written] = dst[:written]
            pos = end
    decryptor.finalize()
    return bytes(out)


def decrypt_cbcs(sample: bytes, key: bytes, iv: bytes, subsamples: List[Tuple[int, int]], crypt_blocks: int, skip_blocks: int) -> bytes:
    if not iv:
        iv = b"\x00" * 16
    if len(iv) < 16:
        iv = iv + (b"\x00" * (16 - len(iv)))
    out = bytearray(sample)
    prev = iv

    def decrypt_cbc_run(start: int, length: int):
        nonlocal prev
        usable = length - (length % 16)
        if usable <= 0:
            return
        last_ciphertext_block = bytes(out[start + usable - 16:start + usable])
        decryptor = Cipher(algorithms.AES(key), modes.CBC(prev)).decryptor()
        dst = bytearray(usable + 15)
        written = decryptor.update_into(memoryview(out)[start:start + usable], dst)
        tail = decryptor.finalize()
        total = written + len(tail)
        if tail:
            dst[written:total] = tail
        out[start:start + usable] = dst[:total]
        prev = last_ciphertext_block

    def decrypt_pattern(start: int, length: int):
        pos = start
        remaining = length
        if crypt_blocks == 0 and skip_blocks == 0:
            decrypt_cbc_run(pos, remaining)
            return
        crypt_len = crypt_blocks * 16
        skip_len = skip_blocks * 16
        while remaining >= 16:
            current_crypt = min(remaining - (remaining % 16), crypt_len)
            if current_crypt <= 0:
                return
            decrypt_cbc_run(pos, current_crypt)
            pos += current_crypt
            remaining -= current_crypt
            current_skip = min(remaining, skip_len)
            pos += current_skip
            remaining -= current_skip

    if not subsamples:
        decrypt_pattern(0, len(sample))
    else:
        pos = 0
        for clear_bytes, encrypted_bytes in subsamples:
            pos += clear_bytes
            decrypt_pattern(pos, encrypted_bytes)
            pos += encrypted_bytes
    return bytes(out)


def build_length_prefixed_nal_subsamples(sample: bytes, nal_length_size: int, nal_header_clear_bytes: int) -> List[Tuple[int, int]]:
    if nal_length_size <= 0 or nal_header_clear_bytes < 0:
        return []
    subsamples: List[Tuple[int, int]] = []
    pos = 0
    while pos < len(sample):
        if pos + nal_length_size > len(sample):
            return []
        nal_size = int.from_bytes(sample[pos:pos + nal_length_size], "big")
        pos += nal_length_size
        if nal_size == 0:
            subsamples.append((nal_length_size, 0))
            continue
        if pos + nal_size > len(sample):
            return []
        clear_payload = min(nal_header_clear_bytes, nal_size)
        encrypted_payload = max(0, nal_size - clear_payload)
        subsamples.append((nal_length_size + clear_payload, encrypted_payload))
        pos += nal_size
    return subsamples


def decrypt_sample(sample: bytes, key: bytes, info: SampleAuxInfo, scheme: bytes, tenc: TencInfo, codec_format: bytes = b"", nal_length_size: int = 0, nal_header_clear_bytes: int = 0) -> bytes:
    effective_subsamples = info.subsamples
    if not effective_subsamples and codec_format in {b"avc1", b"hvc1"} and nal_length_size > 0:
        guessed_subsamples = build_length_prefixed_nal_subsamples(sample, nal_length_size, nal_header_clear_bytes)
        if guessed_subsamples:
            effective_subsamples = guessed_subsamples
    if scheme in {b"cenc", b"cens", b"piff", b""}:
        return decrypt_cenc_ctr(sample, key, info.iv, effective_subsamples)
    if scheme in {b"cbcs", b"cbc1"}:
        return decrypt_cbcs(sample, key, info.iv if info.iv else tenc.constant_iv, effective_subsamples, tenc.crypt_byte_block, tenc.skip_byte_block)
    raise ValueError(f"Unsupported protection scheme: {scheme.decode('ascii', 'ignore')}")


def patch_sample_description(data: bytearray, track: TrackInfo):
    if not track.sample_entry_box or not track.original_format:
        return
    box = track.sample_entry_box
    data[box.start + 4:box.start + 8] = track.original_format


def resolve_track_key(track: TrackInfo, keys_by_track: Dict[int, bytes], keys_by_kid: Dict[bytes, bytes]) -> bytes:
    if track.track_id in keys_by_track:
        return keys_by_track[track.track_id]
    if track.tenc and track.tenc.kid in keys_by_kid:
        return keys_by_kid[track.tenc.kid]
    if len(keys_by_kid) == 1 and track.tenc:
        return next(iter(keys_by_kid.values()))
    if len(keys_by_track) == 1:
        return next(iter(keys_by_track.values()))
    raise KeyError(f"No key found for track {track.track_id}")


def resolve_default_sample_info(tenc: TencInfo) -> Optional[SampleAuxInfo]:
    if tenc.iv_size == 0 and tenc.constant_iv:
        return SampleAuxInfo(tenc.constant_iv, [])
    return None


def resolve_sample_info(aux_info: List[SampleAuxInfo], index: int, tenc: TencInfo) -> Optional[SampleAuxInfo]:
    if aux_info:
        if index >= len(aux_info):
            return None
        return aux_info[index]
    return resolve_default_sample_info(tenc)


def apply_track_decryption(data: bytearray, track: TrackInfo, key: bytes):
    if not track.tenc or not track.sample_offsets or not track.sample_sizes:
        return
    if track.aux_info and len(track.aux_info) != len(track.sample_sizes):
        raise ValueError(f"Track {track.track_id} has mismatched sample encryption info")
    for index, (offset, size) in enumerate(zip(track.sample_offsets, track.sample_sizes)):
        if offset + size > len(data):
            raise ValueError(f"Track {track.track_id} sample {index + 1} exceeds file size")
        info = resolve_sample_info(track.aux_info, index, track.tenc)
        if info is None:
            continue
        sample = bytes(data[offset:offset + size])
        data[offset:offset + size] = decrypt_sample(sample, key, info, track.scheme, track.tenc, track.codec_format, track.nal_length_size, track.nal_header_clear_bytes)
    patch_sample_description(data, track)


def apply_fragment_decryption(data: bytearray, run: FragmentRun, key: bytes):
    if not run.tenc:
        return
    if run.aux_info and len(run.aux_info) != len(run.sample_sizes):
        raise ValueError(f"Fragment track {run.track_id} has mismatched sample encryption info")
    for index, (offset, size) in enumerate(zip(run.sample_offsets, run.sample_sizes)):
        if offset + size > len(data):
            raise ValueError(f"Fragment track {run.track_id} sample {index + 1} exceeds file size")
        info = resolve_sample_info(run.aux_info, index, run.tenc)
        if info is None:
            continue
        sample = bytes(data[offset:offset + size])
        data[offset:offset + size] = decrypt_sample(sample, key, info, run.scheme, run.tenc)


def patch_senc_flags(data: bytearray, boxes: List[Box]):
    for box in boxes:
        if box.type == b"senc" or (box.type == b"uuid" and box.uuid == PIFF_SAMPLE_ENCRYPTION_UUID):
            pos = box.start + box.header_size
            if pos + 4 <= box.end:
                data[pos + 1:pos + 4] = b"\x00\x00\x00"
        patch_senc_flags(data, box.children)


def gather_track_ids_to_remove(parser: Mp4Parser) -> List[int]:
    moov = None
    for box in parser.root:
        if box.type == b"moov":
            moov = box
            break
    if moov is None:
        return []
    result: List[int] = []
    for trak in moov.children:
        if trak.type != b"trak":
            continue
        tkhd = parser.find_child(trak, b"tkhd")
        mdia = parser.find_child(trak, b"mdia")
        hdlr = parser.find_child(mdia, b"hdlr") if mdia else None
        if tkhd and hdlr:
            track_id = parse_tkhd(parser.data, tkhd)
            handler_type = parse_hdlr(parser.data, hdlr)
            if handler_type in TEXT_HANDLER_TYPES:
                result.append(track_id)
    return result


def slice_out_intervals(blob: bytes, intervals: List[Tuple[int, int]]) -> bytes:
    if not intervals:
        return blob
    out = bytearray()
    pos = 0
    for start, end in sorted(intervals):
        if pos < start:
            out.extend(blob[pos:start])
        pos = max(pos, end)
    if pos < len(blob):
        out.extend(blob[pos:])
    return bytes(out)


def remove_text_tracks_from_init_segment(source: bytes, parser: Mp4Parser) -> bytes:
    if any(box.type == b"mdat" for box in parser.root):
        return source
    track_ids_to_remove = set(gather_track_ids_to_remove(parser))
    if not track_ids_to_remove:
        return source
    moov = None
    for box in parser.root:
        if box.type == b"moov":
            moov = box
            break
    if moov is None:
        return source
    moov_bytes = bytes(source[moov.start:moov.end])
    moov_intervals: List[Tuple[int, int]] = []
    mvex_replacement = None
    mvex_start_local = None
    mvex_end_local = None
    for child in moov.children:
        if child.type == b"trak":
            tkhd = parser.find_child(child, b"tkhd")
            if tkhd and parse_tkhd(parser.data, tkhd) in track_ids_to_remove:
                moov_intervals.append((child.start - moov.start, child.end - moov.start))
        elif child.type == b"mvex":
            mvex_bytes = bytes(source[child.start:child.end])
            mvex_intervals: List[Tuple[int, int]] = []
            for trex in child.children:
                if trex.type != b"trex":
                    continue
                track_id = u32(parser.data, trex.start + trex.header_size + 4)
                if track_id in track_ids_to_remove:
                    mvex_intervals.append((trex.start - child.start, trex.end - child.start))
            if mvex_intervals:
                mvex_payload = slice_out_intervals(mvex_bytes[8:], [(a - 8, b - 8) for a, b in mvex_intervals])
                mvex_replacement = struct.pack(">I4s", 8 + len(mvex_payload), b"mvex") + mvex_payload
                mvex_start_local = child.start - moov.start
                mvex_end_local = child.end - moov.start
                moov_intervals.append((mvex_start_local, mvex_end_local))
    new_payload = bytearray()
    pos = 8
    for start, end in sorted(moov_intervals):
        if pos < start:
            new_payload.extend(moov_bytes[pos:start])
        if mvex_replacement is not None and start == mvex_start_local and end == mvex_end_local:
            new_payload.extend(mvex_replacement)
        pos = max(pos, end)
    if pos < len(moov_bytes):
        new_payload.extend(moov_bytes[pos:])
    new_moov = struct.pack(">I4s", 8 + len(new_payload), b"moov") + bytes(new_payload)
    out = bytearray()
    for box in parser.root:
        if box.type == b"moov":
            out.extend(new_moov)
        else:
            out.extend(source[box.start:box.end])
    return bytes(out)


def collect_detected_kids(tracks: Dict[int, TrackInfo], fragments: List[FragmentRun]) -> List[bytes]:
    seen = set()
    ordered: List[bytes] = []
    for track in tracks.values():
        if track.tenc and track.tenc.kid and track.tenc.kid not in seen:
            seen.add(track.tenc.kid)
            ordered.append(track.tenc.kid)
    for run in fragments:
        if run.tenc and run.tenc.kid and run.tenc.kid not in seen:
            seen.add(run.tenc.kid)
            ordered.append(run.tenc.kid)
    return ordered


def ensure_supplied_kids_match(detected_kids: List[bytes], keys_by_kid: Dict[bytes, bytes]):
    if not detected_kids or not keys_by_kid:
        return
    if set(detected_kids) & set(keys_by_kid.keys()):
        return
    if len(detected_kids) == 1:
        raise RuntimeError(f"The supplied KID does not match this file. The correct KID is: {detected_kids[0].hex()}")
    raise RuntimeError("The supplied KID does not match this file. The correct KIDs are: " + ", ".join(k.hex() for k in detected_kids))


def collect_time_patches(data, boxes: List[Box], value: int, patches: List[BytePatch]):
    for box in boxes:
        if box.type in {b"mvhd", b"tkhd", b"mdhd"}:
            pos = box.start + box.header_size
            version = u8(data, pos)
            if version == 1:
                patches.append(BytePatch(pos + 4, struct.pack(">Q", value)))
                patches.append(BytePatch(pos + 12, struct.pack(">Q", value)))
            else:
                patches.append(BytePatch(pos + 4, struct.pack(">I", value & 0xFFFFFFFF)))
                patches.append(BytePatch(pos + 8, struct.pack(">I", value & 0xFFFFFFFF)))
        collect_time_patches(data, box.children, value, patches)


def collect_senc_flag_patches(boxes: List[Box], patches: List[BytePatch]):
    for box in boxes:
        if box.type == b"senc" or (box.type == b"uuid" and box.uuid == PIFF_SAMPLE_ENCRYPTION_UUID):
            pos = box.start + box.header_size
            if pos + 4 <= box.end:
                patches.append(BytePatch(pos + 1, b"\x00\x00\x00"))
        collect_senc_flag_patches(box.children, patches)


def unix_to_mp4_time(timestamp: int) -> int:
    return int(timestamp) + 2082844800


def collect_tfhd_sample_description_index_patches(data, parser: Mp4Parser, tracks: Dict[int, TrackInfo], patches: List[BytePatch]):
    decrypted_track_ids = {track_id for track_id, track in tracks.items() if track.original_format}
    if not decrypted_track_ids:
        return
    for moof in [box for box in parser.root if box.type == b"moof"]:
        for traf in parser.find_children(moof, b"traf"):
            tfhd = parser.find_child(traf, b"tfhd")
            if not tfhd:
                continue
            pos = tfhd.start + tfhd.header_size
            flags = u24(data, pos + 1)
            pos += 4
            track_id = u32(data, pos)
            pos += 4
            if track_id not in decrypted_track_ids:
                continue
            if flags & 0x000001:
                pos += 8
            if flags & 0x000002:
                sample_description_index = u32(data, pos)
                if sample_description_index != 1:
                    patches.append(BytePatch(pos, struct.pack(">I", 1)))


def collect_metadata_patches(data, parser: Mp4Parser, tracks: Dict[int, TrackInfo], input_path: str) -> List[BytePatch]:
    patches: List[BytePatch] = []
    for track in tracks.values():
        if track.sample_entry_box and track.original_format:
            patches.append(BytePatch(track.sample_entry_box.start + 4, track.original_format))
    collect_senc_flag_patches(parser.root, patches)
    collect_tfhd_sample_description_index_patches(data, parser, tracks, patches)
    patches.sort(key=lambda x: (x.start, x.end))
    merged: List[BytePatch] = []
    for patch in patches:
        if not merged:
            merged.append(patch)
            continue
        prev = merged[-1]
        if patch.start < prev.end:
            raise RuntimeError("Overlapping metadata patches were generated")
        merged.append(patch)
    return merged


def collect_decrypt_tasks(tracks: Dict[int, TrackInfo], fragments: List[FragmentRun], keys_by_track: Dict[int, bytes], keys_by_kid: Dict[bytes, bytes]) -> List[DecryptTask]:
    tasks: List[DecryptTask] = []
    skipped_without_iv = 0
    decrypted_any = False
    for track_id in sorted(tracks):
        track = tracks[track_id]
        if not track.tenc or not track.tenc.is_encrypted:
            continue
        if track.aux_info and len(track.aux_info) != len(track.sample_sizes):
            raise ValueError(f"Track {track.track_id} has mismatched sample encryption info")
        key = resolve_track_key(track, keys_by_track, keys_by_kid)
        for index, (offset, size) in enumerate(zip(track.sample_offsets, track.sample_sizes)):
            info = resolve_sample_info(track.aux_info, index, track.tenc)
            if info is None:
                skipped_without_iv += 1
                continue
            tasks.append(DecryptTask(offset, size, key, info, track.scheme, track.tenc, track.codec_format, track.nal_length_size, track.nal_header_clear_bytes))
            decrypted_any = True
    for run in fragments:
        if not run.tenc or not run.tenc.is_encrypted:
            continue
        if run.aux_info and len(run.aux_info) != len(run.sample_sizes):
            raise ValueError(f"Fragment track {run.track_id} has mismatched sample encryption info")
        track = tracks.get(run.track_id)
        if not track:
            raise RuntimeError(f"Missing initialization track for fragment track {run.track_id}")
        key = resolve_track_key(track, keys_by_track, keys_by_kid)
        for index, (offset, size) in enumerate(zip(run.sample_offsets, run.sample_sizes)):
            info = resolve_sample_info(run.aux_info, index, run.tenc)
            if info is None:
                skipped_without_iv += 1
                continue
            tasks.append(DecryptTask(offset, size, key, info, run.scheme, run.tenc, track.codec_format, track.nal_length_size, track.nal_header_clear_bytes))
            decrypted_any = True
    if skipped_without_iv:
        print(f"Skipped {skipped_without_iv} samples without IV/subsample metadata; they were preserved as clear samples")
    if not decrypted_any:
        raise RuntimeError("No encrypted samples were decrypted")
    tasks.sort(key=lambda x: (x.start, x.end))
    previous_end = -1
    for task in tasks:
        if task.start < previous_end:
            raise RuntimeError("Overlapping encrypted sample ranges were detected")
        previous_end = task.end
    return tasks


def build_events(metadata_patches: List[BytePatch], decrypt_tasks: List[DecryptTask]) -> List[StreamEvent]:
    events: List[StreamEvent] = []
    for patch in metadata_patches:
        events.append(StreamEvent(patch.start, patch.end, "patch", patch))
    for task in decrypt_tasks:
        events.append(StreamEvent(task.start, task.end, "decrypt", task))
    events.sort(key=lambda x: (x.start, 0 if x.kind == "patch" else 1, x.end))
    previous_end = -1
    for event in events:
        if event.start < previous_end:
            raise RuntimeError("Overlapping stream events were generated")
        previous_end = event.end
    return events


def stream_copy_range(mm, out_file, start: int, end: int, progress: ProgressPrinter, chunk_size: int = DEFAULT_COPY_CHUNK):
    pos = start
    while pos < end:
        chunk_end = min(end, pos + chunk_size)
        out_file.write(mm[pos:chunk_end])
        pos = chunk_end
        progress.update(pos)


def stream_write_data(out_file, data: bytes, end_offset: int, progress: ProgressPrinter):
    out_file.write(data)
    progress.update(end_offset)


def is_webm_file(path: str) -> bool:
    with open(path, "rb") as f:
        return f.read(4) == b"\x1a\x45\xdf\xa3"


def read_ebml_id(buf: bytes, off: int) -> Tuple[int, int, bytes]:
    first = buf[off]
    mask = 0x80
    length = 1
    while length <= 4 and (first & mask) == 0:
        mask >>= 1
        length += 1
    if length > 4 or off + length > len(buf):
        raise ValueError("Invalid EBML ID")
    raw = buf[off:off + length]
    value = 0
    for b in raw:
        value = (value << 8) | b
    return value, length, raw


def read_ebml_size(buf: bytes, off: int) -> Tuple[Optional[int], int, bool]:
    first = buf[off]
    mask = 0x80
    length = 1
    while length <= 8 and (first & mask) == 0:
        mask >>= 1
        length += 1
    if length > 8 or off + length > len(buf):
        raise ValueError("Invalid EBML size")
    raw = bytearray(buf[off:off + length])
    data_bits = 8 - length
    value = raw[0] & ((1 << data_bits) - 1)
    unknown = raw[0] == ((1 << data_bits) - 1) and all(b == 0xFF for b in raw[1:])
    for b in raw[1:]:
        value = (value << 8) | b
    return (None if unknown else value), length, unknown


def encode_ebml_size(value: int, preferred_len: Optional[int] = None, force_unknown: bool = False) -> bytes:
    if force_unknown:
        if preferred_len is None:
            preferred_len = 8
        if not 1 <= preferred_len <= 8:
            raise ValueError("Invalid unknown-size length")
        return bytes([((1 << (8 - preferred_len)) - 1) | (1 << (8 - preferred_len))]) + (b"\xFF" * (preferred_len - 1))
    if value < 0:
        raise ValueError("EBML size cannot be negative")
    candidate_lengths = [preferred_len] if preferred_len else list(range(1, 9))
    for length in candidate_lengths:
        if length is None:
            continue
        if not 1 <= length <= 8:
            continue
        max_value = (1 << (7 * length)) - 2
        if value <= max_value:
            encoded = value.to_bytes(length, "big")
            leading = 1 << (8 - length)
            encoded = bytes([encoded[0] | leading]) + encoded[1:]
            return encoded
    raise ValueError(f"Value {value} is too large for EBML size encoding")


def parse_ebml_elements(buf: bytes, start: int, end: int) -> List[EbmlElement]:
    elements: List[EbmlElement] = []
    effective_end = min(end, len(buf))
    pos = start
    while pos < effective_end:
        if pos >= len(buf):
            break
        id_value, id_len, id_bytes = read_ebml_id(buf, pos)
        size_value, size_len, unknown = read_ebml_size(buf, pos + id_len)
        data_start = pos + id_len + size_len
        if data_start > effective_end:
            raise ValueError("EBML header exceeds parent boundary")
        if size_value is None:
            data_end = effective_end
        else:
            raw_end = data_start + size_value
            data_end = raw_end if raw_end <= effective_end else effective_end
        elements.append(EbmlElement(id_value, id_bytes, size_value, size_len, data_start, data_end, pos, data_start, data_end, unknown))
        if data_end <= pos:
            raise ValueError("EBML parser did not advance")
        pos = data_end
    return elements


def parse_ebml_uint(payload: bytes) -> int:
    value = 0
    for b in payload:
        value = (value << 8) | b
    return value


def parse_ebml_string(payload: bytes) -> str:
    return payload.rstrip(b"\x00").decode("utf-8", "replace")


def strip_crc32_elements(payload: bytes) -> bytes:
    out = bytearray()
    cursor = 0
    for child in parse_ebml_elements(payload, 0, len(payload)):
        if cursor < child.header_start:
            out.extend(payload[cursor:child.header_start])
        if child.id_value != WEBM_ID_CRC32:
            out.extend(payload[child.header_start:child.end])
        cursor = child.end
    if cursor < len(payload):
        out.extend(payload[cursor:])
    return bytes(out)


def parse_vint_value(buf: bytes, off: int) -> Tuple[int, int, bytes]:
    first = buf[off]
    mask = 0x80
    length = 1
    while length <= 8 and (first & mask) == 0:
        mask >>= 1
        length += 1
    if length > 8 or off + length > len(buf):
        raise ValueError("Invalid VINT")
    value = first & (mask - 1)
    raw = buf[off:off + length]
    for i in range(1, length):
        value = (value << 8) | buf[off + i]
    return value, length, raw


def build_webm_counter_block(iv8: bytes) -> bytes:
    if len(iv8) != 8:
        raise ValueError("WebM IV must be 8 bytes")
    return iv8 + (b"\x00" * 8)


def parse_webm_signal_frame(frame_payload: bytes) -> Tuple[bytes, int, SampleAuxInfo]:
    if len(frame_payload) < 1:
        raise ValueError("Empty WebM frame payload")
    signal_byte = frame_payload[0]
    header_size = WEBM_SIGNAL_BYTE_SIZE
    if signal_byte & WEBM_ENCRYPTED_SIGNAL:
        header_size += WEBM_IV_SIZE
        if len(frame_payload) < header_size:
            raise ValueError("Encrypted WebM frame is too small to contain the IV")
        iv = frame_payload[1:1 + WEBM_IV_SIZE]
        subsamples: List[Tuple[int, int]] = []
        if signal_byte & WEBM_PARTITIONED_SIGNAL:
            header_size += WEBM_NUM_PARTITIONS_SIZE
            if len(frame_payload) < header_size:
                raise ValueError("Encrypted WebM frame is too small to contain partition metadata")
            num_partitions = frame_payload[1 + WEBM_IV_SIZE]
            offsets_start = header_size
            offsets_end = offsets_start + (num_partitions * WEBM_PARTITION_OFFSET_SIZE)
            if offsets_end > len(frame_payload):
                raise ValueError("Encrypted WebM frame is too small to contain partition offsets")
            data_start = offsets_end
            subsample_offset = 0
            encrypted_subsample = False
            clear_size = 0
            encrypted_size = 0
            cursor = offsets_start
            for partition_index in range(num_partitions):
                partition_offset = struct.unpack_from(">I", frame_payload, cursor)[0]
                cursor += 4
                if partition_offset < subsample_offset:
                    raise ValueError("Partition offsets are out of order")
                if encrypted_subsample:
                    encrypted_size = partition_offset - subsample_offset
                    subsamples.append((clear_size, encrypted_size))
                else:
                    clear_size = partition_offset - subsample_offset
                    if partition_index == (num_partitions - 1):
                        encrypted_size = len(frame_payload) - data_start - subsample_offset - clear_size
                        subsamples.append((clear_size, encrypted_size))
                subsample_offset = partition_offset
                encrypted_subsample = not encrypted_subsample
            if (num_partitions % 2) == 0:
                clear_size = len(frame_payload) - data_start - subsample_offset
                subsamples.append((clear_size, 0))
            return signal_byte.to_bytes(1, "big"), data_start, SampleAuxInfo(iv, subsamples)
        return signal_byte.to_bytes(1, "big"), header_size, SampleAuxInfo(iv, [])
    return signal_byte.to_bytes(1, "big"), header_size, SampleAuxInfo(b"", [])


def decrypt_webm_frame(frame_payload: bytes, key: bytes) -> bytes:
    _, data_offset, info = parse_webm_signal_frame(frame_payload)
    encoded_frame = frame_payload[data_offset:]
    if info.iv:
        return decrypt_cenc_ctr(encoded_frame, key, build_webm_counter_block(info.iv), info.subsamples)
    return encoded_frame


def is_webm_text_track(track: WebMTrack) -> bool:
    if track.track_type in {WEBM_TRACK_TYPE_SUBTITLE, WEBM_TRACK_TYPE_METADATA}:
        return True
    codec = track.codec_id.upper()
    return codec.startswith("D_WEBVTT") or codec.startswith("S_TEXT") or codec.startswith("S_VOBSUB")


def parse_webm_track_entry(track_entry_payload: bytes) -> WebMTrack:
    track = WebMTrack(track_number=-1)
    for child in parse_ebml_elements(track_entry_payload, 0, len(track_entry_payload)):
        payload = track_entry_payload[child.data_start:child.data_end]
        if child.id_value == WEBM_ID_TRACK_NUMBER:
            track.track_number = parse_ebml_uint(payload)
        elif child.id_value == WEBM_ID_TRACK_UID:
            track.track_uid = parse_ebml_uint(payload)
        elif child.id_value == WEBM_ID_TRACK_TYPE:
            track.track_type = parse_ebml_uint(payload)
        elif child.id_value == WEBM_ID_CODEC_ID:
            track.codec_id = parse_ebml_string(payload)
        elif child.id_value == WEBM_ID_NAME:
            track.name = parse_ebml_string(payload)
        elif child.id_value == WEBM_ID_LANGUAGE:
            track.language = parse_ebml_string(payload)
        elif child.id_value == WEBM_ID_CONTENT_ENCODINGS:
            track.content_encodings_start_rel = child.header_start
            track.content_encodings_end_rel = child.end
            for enc in parse_ebml_elements(track_entry_payload, child.data_start, child.data_end):
                if enc.id_value != WEBM_ID_CONTENT_ENCODING:
                    continue
                for enc_child in parse_ebml_elements(track_entry_payload, enc.data_start, enc.data_end):
                    if enc_child.id_value != WEBM_ID_CONTENT_ENCRYPTION:
                        continue
                    track.encrypted = True
                    for ce_child in parse_ebml_elements(track_entry_payload, enc_child.data_start, enc_child.data_end):
                        if ce_child.id_value == WEBM_ID_CONTENT_ENC_KEY_ID:
                            track.key_id = bytes(track_entry_payload[ce_child.data_start:ce_child.data_end])
    if track.track_number <= 0:
        raise ValueError("WebM track entry is missing TrackNumber")
    return track


def rewrite_webm_track_entry(track_entry_payload: bytes, decrypt_track_numbers: set, drop_text_tracks: bool) -> Optional[bytes]:
    track_entry_payload = strip_crc32_elements(track_entry_payload)
    track = parse_webm_track_entry(track_entry_payload)
    if drop_text_tracks and is_webm_text_track(track):
        return None
    if track.track_number in decrypt_track_numbers and track.content_encodings_start_rel is not None:
        out = bytearray()
        out.extend(track_entry_payload[:track.content_encodings_start_rel])
        out.extend(track_entry_payload[track.content_encodings_end_rel:])
        return bytes(out)
    return track_entry_payload


def parse_webm_tracks(tracks_payload: bytes) -> Dict[int, WebMTrack]:
    tracks: Dict[int, WebMTrack] = {}
    for child in parse_ebml_elements(tracks_payload, 0, len(tracks_payload)):
        if child.id_value == WEBM_ID_TRACK_ENTRY:
            payload = tracks_payload[child.data_start:child.data_end]
            track = parse_webm_track_entry(payload)
            tracks[track.track_number] = track
    return tracks


def print_webm_tracks(tracks: Dict[int, WebMTrack]):
    print("Detected WebM tracks:")
    for track_number in sorted(tracks):
        track = tracks[track_number]
        kid_text = track.key_id.hex() if track.key_id else "-"
        kind = {
            WEBM_TRACK_TYPE_VIDEO: "video",
            WEBM_TRACK_TYPE_AUDIO: "audio",
            WEBM_TRACK_TYPE_SUBTITLE: "subtitle/caption",
            WEBM_TRACK_TYPE_METADATA: "metadata/description",
        }.get(track.track_type, f"type-{track.track_type}")
        print(
            f"  Track {track.track_number}: type={kind}, codec={track.codec_id or '-'}, "
            f"encrypted={'yes' if track.encrypted else 'no'}, kid={kid_text}, "
            f"name={track.name or '-'}, language={track.language or '-'}"
        )


def ensure_supplied_webm_kids_match(tracks: Dict[int, WebMTrack], keys_by_kid: Dict[bytes, bytes]):
    detected = [track.key_id for track in tracks.values() if track.key_id]
    if not detected or not keys_by_kid:
        return
    if set(detected) & set(keys_by_kid.keys()):
        return
    unique = []
    seen = set()
    for kid in detected:
        if kid not in seen:
            seen.add(kid)
            unique.append(kid)
    if len(unique) == 1:
        raise RuntimeError(f"The supplied KID does not match this file. The correct KID is: {unique[0].hex()}")
    raise RuntimeError("The supplied KID does not match this file. The correct KIDs are: " + ", ".join(k.hex() for k in unique))


def encode_webm_element(id_bytes: bytes, payload: bytes, preferred_size_len: Optional[int] = None, force_unknown_size: bool = False) -> bytes:
    return id_bytes + encode_ebml_size(len(payload), preferred_size_len, force_unknown_size) + payload


def rewrite_webm_block_payload(block_payload: bytes, track_keys: Dict[int, bytes]) -> bytes:
    track_number, vint_len, vint_raw = parse_vint_value(block_payload, 0)
    if len(block_payload) < vint_len + 3:
        raise ValueError("Block payload is too small")
    header_prefix = vint_raw + block_payload[vint_len:vint_len + 3]
    frame_payload = block_payload[vint_len + 3:]
    key = track_keys.get(track_number)
    if key is None:
        return block_payload
    flags = block_payload[vint_len + 2]
    lacing = (flags >> 1) & 0x03
    if lacing != 0:
        raise RuntimeError(f"Encrypted WebM block uses unsupported lacing mode {lacing}")
    clear_frame = decrypt_webm_frame(frame_payload, key)
    return header_prefix + clear_frame


def rewrite_webm_cluster_payload(cluster_payload: bytes, track_keys: Dict[int, bytes], progress: ProgressPrinter, processed: List[int]) -> bytes:
    cluster_payload = strip_crc32_elements(cluster_payload)
    out = bytearray()
    cursor = 0
    for child in parse_ebml_elements(cluster_payload, 0, len(cluster_payload)):
        if cursor < child.header_start:
            out.extend(cluster_payload[cursor:child.header_start])
        child_payload = cluster_payload[child.data_start:child.data_end]
        if child.id_value == WEBM_ID_SIMPLE_BLOCK:
            new_payload = rewrite_webm_block_payload(child_payload, track_keys)
            out.extend(encode_webm_element(child.id_bytes, new_payload, child.size_len))
        elif child.id_value == WEBM_ID_BLOCK_GROUP:
            new_group = bytearray()
            inner_cursor = 0
            for inner in parse_ebml_elements(child_payload, 0, len(child_payload)):
                if inner_cursor < inner.header_start:
                    new_group.extend(child_payload[inner_cursor:inner.header_start])
                inner_payload = child_payload[inner.data_start:inner.data_end]
                if inner.id_value == WEBM_ID_BLOCK:
                    rewritten_block = rewrite_webm_block_payload(inner_payload, track_keys)
                    new_group.extend(encode_webm_element(inner.id_bytes, rewritten_block, inner.size_len))
                else:
                    new_group.extend(child_payload[inner.header_start:inner.end])
                inner_cursor = inner.end
            if inner_cursor < len(child_payload):
                new_group.extend(child_payload[inner_cursor:])
            out.extend(encode_webm_element(child.id_bytes, bytes(new_group), child.size_len))
        else:
            out.extend(cluster_payload[child.header_start:child.end])
        cursor = child.end
        processed[0] += child.end - child.header_start
        progress.update(processed[0])
    if cursor < len(cluster_payload):
        out.extend(cluster_payload[cursor:])
        processed[0] += len(cluster_payload) - cursor
        progress.update(processed[0])
    return bytes(out)


def rewrite_webm_tracks_payload(tracks_payload: bytes, decrypt_track_numbers: set, drop_text_tracks: bool) -> Tuple[bytes, Dict[int, WebMTrack]]:
    tracks_payload = strip_crc32_elements(tracks_payload)
    original_tracks = parse_webm_tracks(tracks_payload)
    out = bytearray()
    cursor = 0
    for child in parse_ebml_elements(tracks_payload, 0, len(tracks_payload)):
        if cursor < child.header_start:
            out.extend(tracks_payload[cursor:child.header_start])
        if child.id_value == WEBM_ID_TRACK_ENTRY:
            payload = tracks_payload[child.data_start:child.data_end]
            rewritten = rewrite_webm_track_entry(payload, decrypt_track_numbers, drop_text_tracks)
            if rewritten is not None:
                out.extend(encode_webm_element(child.id_bytes, rewritten, child.size_len))
        else:
            out.extend(tracks_payload[child.header_start:child.end])
        cursor = child.end
    if cursor < len(tracks_payload):
        out.extend(tracks_payload[cursor:])
    return bytes(out), original_tracks


def resolve_webm_track_keys(tracks: Dict[int, WebMTrack], keys_by_track: Dict[int, bytes], keys_by_kid: Dict[bytes, bytes]) -> Dict[int, bytes]:
    resolved: Dict[int, bytes] = {}
    for track_number, track in tracks.items():
        if not track.encrypted:
            continue
        if track_number in keys_by_track:
            resolved[track_number] = keys_by_track[track_number]
            continue
        if track.key_id and track.key_id in keys_by_kid:
            resolved[track_number] = keys_by_kid[track.key_id]
            continue
        if len(keys_by_track) == 1:
            resolved[track_number] = next(iter(keys_by_track.values()))
            continue
        if len(keys_by_kid) == 1:
            resolved[track_number] = next(iter(keys_by_kid.values()))
            continue
        raise RuntimeError(f"No key found for WebM track {track_number}")
    if not resolved:
        raise RuntimeError("No encrypted WebM tracks were matched to the supplied keys")
    return resolved


def decrypt_webm_file(input_path: str, output_path: str, keys_by_track: Dict[int, bytes], keys_by_kid: Dict[bytes, bytes], show_tracks: bool, drop_text: bool):
    source = Path(input_path).read_bytes()
    top = parse_ebml_elements(source, 0, len(source))
    segment = None
    for element in top:
        if element.id_value == WEBM_ID_SEGMENT:
            segment = element
            break
    if segment is None:
        raise RuntimeError("WebM Segment element was not found")
    tracks_element = None
    for child in parse_ebml_elements(source, segment.data_start, segment.data_end):
        if child.id_value == WEBM_ID_TRACKS:
            tracks_element = child
            break
    if tracks_element is None:
        raise RuntimeError("WebM Tracks element was not found")
    tracks_payload = source[tracks_element.data_start:tracks_element.data_end]
    discovered_tracks = parse_webm_tracks(tracks_payload)
    if show_tracks:
        print_webm_tracks(discovered_tracks)
    ensure_supplied_webm_kids_match(discovered_tracks, keys_by_kid)
    track_keys = resolve_webm_track_keys(discovered_tracks, keys_by_track, keys_by_kid)
    decrypt_track_numbers = set(track_keys)

    progress = ProgressPrinter(len(source))
    processed = [0]
    output = bytearray()
    cursor = 0
    for element in top:
        if cursor < element.header_start:
            output.extend(source[cursor:element.header_start])
            processed[0] += element.header_start - cursor
            progress.update(processed[0])
        if element.id_value != WEBM_ID_SEGMENT:
            output.extend(source[element.header_start:element.end])
            processed[0] += element.end - element.header_start
            progress.update(processed[0])
            cursor = element.end
            continue
        segment_payload_out = bytearray()
        inner_cursor = element.data_start
        for child in parse_ebml_elements(source, element.data_start, element.data_end):
            if inner_cursor < child.header_start:
                segment_payload_out.extend(source[inner_cursor:child.header_start])
            child_payload = source[child.data_start:child.data_end]
            if child.id_value == WEBM_ID_TRACKS:
                rewritten_tracks, _ = rewrite_webm_tracks_payload(child_payload, decrypt_track_numbers, drop_text)
                segment_payload_out.extend(encode_webm_element(child.id_bytes, rewritten_tracks, child.size_len))
            elif child.id_value == WEBM_ID_CLUSTER:
                rewritten_cluster = rewrite_webm_cluster_payload(child_payload, track_keys, progress, processed)
                segment_payload_out.extend(encode_webm_element(child.id_bytes, rewritten_cluster, child.size_len))
            elif child.id_value in {WEBM_ID_SEEK_HEAD, WEBM_ID_CUES, WEBM_ID_CRC32}:
                pass
            else:
                segment_payload_out.extend(source[child.header_start:child.end])
                processed[0] += child.end - child.header_start
                progress.update(processed[0])
            inner_cursor = child.end
        if inner_cursor < element.data_end:
            segment_payload_out.extend(source[inner_cursor:element.data_end])
            processed[0] += element.data_end - inner_cursor
            progress.update(processed[0])
        segment_header = element.id_bytes + encode_ebml_size(len(segment_payload_out), element.size_len, force_unknown=element.unknown_size)
        output.extend(segment_header)
        output.extend(segment_payload_out)
        cursor = element.end
    if cursor < len(source):
        output.extend(source[cursor:])
        processed[0] += len(source) - cursor
        progress.update(processed[0])
    Path(output_path).write_bytes(output)
    progress.finish()
    print("Decrypted successfully")
    if output_path.lower().endswith(".mp4"):
        print("WARNING: The output container is still WebM. Use a .webm or .mkv extension unless you remux it afterward.")


def extract_webm_kids_quick(path: str, max_scan_bytes: int = 16 * 1024 * 1024) -> List[bytes]:
    data = Path(path).read_bytes()[:max_scan_bytes]
    results: List[bytes] = []
    def walk(offset, end):
        while offset < end and offset < len(data):
            eid, id_len, _ = read_ebml_id(data, offset)
            size, size_len, _ = read_ebml_size(data, offset + id_len)
            start = offset + id_len + size_len
            stop = min(start + (size if size is not None else len(data) - start), len(data))
            if eid == WEBM_ID_CONTENT_ENC_KEY_ID:
                kid = data[start:stop]
                if kid and kid not in results:
                    results.append(kid)
            if eid in (WEBM_ID_SEGMENT, WEBM_ID_TRACKS, WEBM_ID_TRACK_ENTRY, WEBM_ID_CONTENT_ENCODINGS, WEBM_ID_CONTENT_ENCODING, WEBM_ID_CONTENT_ENCRYPTION):
                walk(start, stop)
            offset = stop
    segment_pos = data.find(b"\x18\x53\x80\x67")
    if segment_pos != -1:
        eid, id_len, _ = read_ebml_id(data, segment_pos)
        size, size_len, _ = read_ebml_size(data, segment_pos + id_len)
        seg_start = segment_pos + id_len + size_len
        seg_end = min(seg_start + (size if size is not None else len(data) - seg_start), len(data))
        walk(seg_start, seg_end)
    return results



def describe_tracks(tracks: Dict[int, TrackInfo], sample_entry_types: Dict[int, bytes]) -> List[str]:
    lines = []
    for track_id in sorted(tracks):
        track = tracks[track_id]
        entry = sample_entry_types.get(track_id, b"").decode("ascii", "replace")
        handler = track.handler_type.decode("ascii", "replace")
        scheme = track.scheme.decode("ascii", "replace")
        encrypted = "yes" if track.tenc and track.tenc.is_encrypted else "no"
        lines.append(
            f"track={track_id} handler={handler or '-'} entry={entry or '-'} encrypted={encrypted} scheme={scheme or '-'}"
        )
    return lines

def parse_keys(values: List[str]) -> Tuple[Dict[int, bytes], Dict[bytes, bytes]]:
    keys_by_track: Dict[int, bytes] = {}
    keys_by_kid: Dict[bytes, bytes] = {}
    for item in values:
        if ":" not in item:
            raise ValueError("Each -k value must be in the form ID:KEY")
        left, right = item.split(":", 1)
        key = normalize_key(right)
        left_clean = left.strip().lower().replace("0x", "").replace("-", "")
        if len(left_clean) == 32 and all(c in "0123456789abcdef" for c in left_clean):
            keys_by_kid[bytes.fromhex(left_clean)] = key
        else:
            track_id = int(left.strip(), 10)
            if track_id <= 0:
                raise ValueError("Track ID must be greater than zero")
            keys_by_track[track_id] = key
    return keys_by_track, keys_by_kid


def decrypt_mp4_file(input_path: str, output_path: str, keys_by_track: Dict[int, bytes], keys_by_kid: Dict[bytes, bytes], show_tracks: bool = False):
    total_size = os.path.getsize(input_path)
    with open(input_path, "rb") as input_file:
        with mmap.mmap(input_file.fileno(), 0, access=mmap.ACCESS_READ) as mm:
            parser_obj = Mp4Parser(mm)
            tracks, trex_defaults = build_tracks(parser_obj)
            sample_entry_types = {
                track_id: (track.original_format or (track.sample_entry_box.type if track.sample_entry_box else b""))
                for track_id, track in tracks.items()
            }
            fragments = build_fragments(parser_obj, tracks, trex_defaults)
            if not tracks and not fragments:
                raise RuntimeError("No decryptable tracks or fragments were found")
            if show_tracks:
                print("Detected tracks:")
                for line in describe_tracks(tracks, sample_entry_types):
                    print("  " + line)
            if not keys_by_track:
                detected_kids = collect_detected_kids(tracks, fragments)
                ensure_supplied_kids_match(detected_kids, keys_by_kid)
            has_mdat = any(box.type == b"mdat" for box in parser_obj.root)
            if not has_mdat:
                output = bytearray(mm[:])
                decrypted_any = False
                for track_id in sorted(tracks):
                    track = tracks[track_id]
                    if not track.tenc or not track.tenc.is_encrypted:
                        continue
                    key = resolve_track_key(track, keys_by_track, keys_by_kid)
                    apply_track_decryption(output, track, key)
                    decrypted_any = True
                for run in fragments:
                    if not run.tenc or not run.tenc.is_encrypted:
                        continue
                    track = tracks.get(run.track_id)
                    if not track:
                        raise RuntimeError(f"Missing initialization track for fragment track {run.track_id}")
                    key = resolve_track_key(track, keys_by_track, keys_by_kid)
                    apply_fragment_decryption(output, run, key)
                    decrypted_any = True
                if not decrypted_any:
                    raise RuntimeError("No encrypted samples were decrypted")
                for track in tracks.values():
                    patch_sample_description(output, track)
                patch_senc_flags(output, parser_obj.root)
                final_output = remove_text_tracks_from_init_segment(bytes(output), parser_obj)
                Path(output_path).write_bytes(final_output)
                ProgressPrinter(max(len(final_output), 1)).finish()
                print("Decrypted successfully")
                return
            metadata_patches = collect_metadata_patches(mm, parser_obj, tracks, input_path)
            decrypt_tasks = collect_decrypt_tasks(tracks, fragments, keys_by_track, keys_by_kid)
            events = build_events(metadata_patches, decrypt_tasks)
            progress = ProgressPrinter(total_size)
            cursor = 0
            with open(output_path, "wb") as output_file:
                for event in events:
                    if cursor < event.start:
                        stream_copy_range(mm, output_file, cursor, event.start, progress)
                    if event.kind == "patch":
                        patch = event.payload
                        stream_write_data(output_file, patch.data, patch.end, progress)
                    else:
                        task = event.payload
                        sample = mm[task.start:task.end]
                        clear = decrypt_sample(sample, task.key, task.info, task.scheme, task.tenc, task.codec_format, task.nal_length_size, task.nal_header_clear_bytes)
                        stream_write_data(output_file, clear, task.end, progress)
                    cursor = event.end
                if cursor < total_size:
                    stream_copy_range(mm, output_file, cursor, total_size, progress)
            progress.finish()
    print("Decrypted successfully")


def main():
    parser = argparse.ArgumentParser(prog="pydecrypt.py")
    parser.add_argument("-i", required=True, help="Input MP4, fragmented MP4, WebM, or Matroska file")
    parser.add_argument("-o", required=True, help="Output decrypted file")
    parser.add_argument("-k", required=True, action="append", help="Track ID or 128-bit KID, followed by a 128-bit key, in the form ID:KEY")
    parser.add_argument("--show-tracks", action="store_true", help="Print detected tracks before decryption")
    parser.add_argument("--keep-text", action="store_true", help="Keep text/caption tracks instead of removing them from init metadata when supported")
    args = parser.parse_args()

    keys_by_track, keys_by_kid = parse_keys(args.k)

    if is_webm_file(args.i):
        decrypt_webm_file(
            input_path=args.i,
            output_path=args.o,
            keys_by_track=keys_by_track,
            keys_by_kid=keys_by_kid,
            show_tracks=args.show_tracks,
            drop_text=not args.keep_text,
        )
        return

    decrypt_mp4_file(args.i, args.o, keys_by_track, keys_by_kid, show_tracks=args.show_tracks)

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        raise SystemExit(130)
    except Exception as e:
        print(f"ERROR: {e}", file=sys.stderr)
        raise SystemExit(1)
