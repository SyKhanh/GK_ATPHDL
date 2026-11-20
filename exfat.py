"""Core exFAT chỉ đọc cho ảnh volume của đồ án (byte 0 là Boot Sector).
Case 1: doc_boot_tho(img), rồi ExFAT(img, log, hieu_chinh={...}).
Case 2: liet_ke_file(), doc_bitmap(), da_cap_phat(), doc_theo_runs().
Case 3: offset_cluster(), doc_cluster(), doc_theo_runs() để thử ghép JPEG.
Runs là danh sách (cluster đầu, số cluster liên tiếp), theo thứ tự của file.
"""
import hashlib
from datetime import datetime
from tienich import exfat_boot_checksum, exfat_set_checksum

def doc_boot_tho(img):
    if img.doc(3, 8) != b"EXFAT   ":
        raise ValueError("Ko chứa signature exFAT")
    return {
        "volume_sectors": img.u64(0x48),
        "fat_sector": img.u32(0x50),
        "fat_length_sectors": img.u32(0x54),
        "heap_sector": img.u32(0x58),
        "cluster_count": img.u32(0x5C),
        "root_cluster": img.u32(0x60),
        "flags": img.u16(0x6A),
        "sector_shift": img.u8(0x6C),
        "cluster_shift": img.u8(0x6D),
        "fat_count": img.u8(0x6E),
    }


def kiem_tra_boot_checksum(img, bytes_per_sector, backup=False):
    """Kiểm tra toàn bộ sector checksum của vùng boot chính hoặc dự phòng."""
    start = (12 if backup else 0) * bytes_per_sector
    boot = img.doc(start, 11 * bytes_per_sector)
    word = exfat_boot_checksum(boot, bytes_per_sector).to_bytes(4, "little")
    return img.doc(start + len(boot), bytes_per_sector) == word * (bytes_per_sector // 4)


def _mtime(raw):
    time = int.from_bytes(raw[12:14], "little")
    date = int.from_bytes(raw[14:16], "little")
    try:
        return datetime(1980 + (date >> 9), (date >> 5) & 15, date & 31,
                        time >> 11, (time >> 5) & 63,
                        (time & 31) * 2 + raw[21] // 100).isoformat()
    except ValueError:
        return None


def doc_entry_thu_muc(data):
    """Đọc metadata, kể cả khi cluster đầu của tập tin bị hỏng."""
    entries = []
    next_entry = 0
    while next_entry + 32 <= len(data):
        p = next_entry
        kind = data[p]
        if kind == 0:
            break
        next_entry += 32
        if kind != 0x85:
            continue
        end = p + (1 + data[p + 1]) * 32
        if end > len(data) or end < p + 96 or data[p + 32] != 0xC0:
            raise ValueError(f"Entry set bị thiếu tại offset thư mục {p:#x}")
        raw = data[p:end]
        stream = raw[32:64]
        name_data = b"".join(raw[q + 2:q + 32] for q in range(64, len(raw), 32)
                             if raw[q] == 0xC1)
        size = 2 * stream[3]
        if not size or size > len(name_data):
            raise ValueError(f"NameLength không hợp lệ tại {p:#x}")
        entries.append({
            "ten": name_data[:size].decode("utf-16le"),
            "la_thu_muc": bool(raw[4] & 0x10),
            "cluster_dau": int.from_bytes(stream[20:24], "little"),
            "kich_thuoc": int.from_bytes(stream[24:32], "little"),
            "valid_length": int.from_bytes(stream[8:16], "little"),
            "lien_tuc": bool(stream[1] & 2),
            "mtime": _mtime(raw),
            "entry_index_bytes": p,
            "checksum_khop": exfat_set_checksum(raw) == int.from_bytes(raw[2:4], "little"),
        })
        next_entry = end
    return entries


def _fat_chain(img, first, fat_offset, count):
    seen = set()
    cluster = first
    while True:
        if not 2 <= cluster < count + 2 or cluster in seen:
            raise ValueError(f"Chuỗi FAT lỗi tại cluster {cluster:#x}")
        seen.add(cluster)
        yield cluster
        cluster = img.u32(fat_offset + cluster * 4)
        if cluster == 0xFFFFFFFF:
            break


def _root_blocks(img, first, heap, size, fat, count, log):
    for cluster in _fat_chain(img, first, fat, count):
        offset = heap + (cluster - 2) * size
        if log:
            log.buoc("Đọc thư mục gốc", offset=offset, gia_tri=cluster)
        block = img.doc(offset, size)
        yield cluster, block
        if 0 in block[::32]:
            break


def doc_thu_muc_goc(img, root_cluster, heap_offset, cluster_size,
                     fat_byte_offset, cluster_count, log=None):
    """Giao diện tương thích với bai_lam.py đã viết trước đây."""
    return b"".join(block for _, block in _root_blocks(
        img, root_cluster, heap_offset, cluster_size, fat_byte_offset, cluster_count, log))


class ExFAT:
    def __init__(self, img, log=None, hieu_chinh=None):
        self.img = img
        self.log = log
        self.boot = doc_boot_tho(img)
        for key, value in (hieu_chinh or {}).items():
            if key not in ("fat_sector", "heap_sector", "cluster_shift"):
                raise ValueError(f"Trường hiệu chỉnh case 1 không hợp lệ: {key}")
            self.boot[key] = value
        b = self.boot
        if not 9 <= b["sector_shift"] <= 12 or not 0 <= b["cluster_shift"] <= 25 - b["sector_shift"]:
            raise ValueError("Số mũ sector/cluster không hợp lệ")
        self.bytes_per_sector = 1 << b["sector_shift"]
        self.cluster_size = self.bytes_per_sector << b["cluster_shift"]
        self.count = b["cluster_count"]
        self.heap = b["heap_sector"] * self.bytes_per_sector
        self.fat = b["fat_sector"] * self.bytes_per_sector
        length = b["fat_length_sectors"] * self.bytes_per_sector
        volume_size = b["volume_sectors"] * self.bytes_per_sector
        if (b["fat_count"] not in (1, 2) or b["fat_sector"] < 24
                or self.count < 1 or length < 4 * (2 + self.count)
                or self.fat + length * b["fat_count"] > self.heap
                or self.heap + self.count * self.cluster_size > volume_size
                or volume_size > img.kich_thuoc):
            raise ValueError("Hình học volume không hợp lệ, kiểm tra lại tham số boot")
        self.active = (b["flags"] & 1) if b["fat_count"] == 2 else 0
        self.active_fat = self.fat + self.active * length
        self.offset_cluster(b["root_cluster"])
        self._root = None

    def offset_cluster(self, cluster):
        if not 2 <= cluster < self.count + 2:
            raise ValueError(f"Cluster ngoài heap: {cluster}")
        return self.heap + (cluster - 2) * self.cluster_size

    def doc_cluster(self, cluster):
        return self.img.doc(self.offset_cluster(cluster), self.cluster_size)

    def _clusters(self, first, size, contiguous):
        n = (size + self.cluster_size - 1) // self.cluster_size
        if not n:
            return
        if n > self.count:
            raise ValueError("Kích thước vượt vùng cluster")
        if contiguous:
            self.offset_cluster(first)
            self.offset_cluster(first + n - 1)
            yield from range(first, first + n)
        else:
            chain = _fat_chain(self.img, first, self.active_fat, self.count)
            for _ in range(n):
                cluster = next(chain, None)
                if cluster is None:
                    raise ValueError("Chuỗi FAT kết thúc sớm")
                yield cluster

    def _root_data(self):
        if self._root is None:
            blocks = list(_root_blocks(self.img, self.boot["root_cluster"], self.heap,
                          self.cluster_size, self.active_fat, self.count, self.log))
            self._root = ([c for c, _ in blocks], b"".join(b for _, b in blocks))
        return self._root

    def liet_ke_file(self):
        """Duyệt thư mục. Trả metadata và offset vật lý, không đọc nội dung file."""
        files = []
        root_clusters, root_data = self._root_data()
        used_dirs = set(root_clusters)
        stack = [("", root_clusters, root_data)]
        while stack:
            prefix, clusters, data = stack.pop()
            for e in doc_entry_thu_muc(data):
                name = e["ten"]
                if name in (".", "..") or any(ch in name for ch in "/\\:\0"):
                    raise ValueError("Tên entry không hợp lệ")
                e["path"] = prefix + name
                for field, pos in (("entry_offset", e["entry_index_bytes"]),
                                   ("stream_offset", e["entry_index_bytes"] + 32)):
                    block, rel = divmod(pos, self.cluster_size)
                    e[field] = self.offset_cluster(clusters[block]) + rel
                if e["la_thu_muc"]:
                    chain = list(self._clusters(e["cluster_dau"], e["kich_thuoc"], e["lien_tuc"]))
                    if used_dirs.intersection(chain):
                        raise ValueError("Các thư mục dùng trùng cluster")
                    used_dirs.update(chain)
                    raw = b"".join(self.doc_cluster(c) for c in chain)
                    stack.append((e["path"] + "/", chain, raw[:e["kich_thuoc"]]))
                else:
                    files.append(e)
        return files

    def doc_bitmap(self):
        """Trả bytes của Allocation Bitmap đang hoạt động, tra bằng da_cap_phat()."""
        _, data = self._root_data()
        for p in range(0, len(data), 32):
            if data[p] == 0:
                break
            if data[p] != 0x81 or (data[p + 1] & 1) != self.active:
                continue
            first = int.from_bytes(data[p+20:p+24], "little")
            size = int.from_bytes(data[p+24:p+32], "little")
            if size < (self.count + 7) // 8:
                raise ValueError("Bitmap quá ngắn")
            return b"".join(self.doc_cluster(c) for c in self._clusters(first, size, False))[:size]
        raise ValueError("Thiếu Allocation Bitmap đang hoạt động")

    def da_cap_phat(self, bitmap, cluster):
        self.offset_cluster(cluster)
        byte, bit = divmod(cluster - 2, 8)
        return bool(bitmap[byte] & (1 << bit))

    def file_runs(self, entry):
        """Đọc runs từ metadata còn nguyên. Trả [[cluster đầu, số cluster], ...]."""
        runs = []
        for c in self._clusters(entry["cluster_dau"], entry["kich_thuoc"], entry["lien_tuc"]):
            if runs and c == sum(runs[-1]):
                runs[-1][1] += 1
            else:
                runs.append([c, 1])
        return runs

    def _file_chunks(self, entry, runs):
        remaining = entry["kich_thuoc"]
        valid = entry["valid_length"]
        if not 0 <= valid <= remaining:
            raise ValueError("ValidDataLength vượt DataLength")
        needed = (remaining + self.cluster_size - 1) // self.cluster_size
        if sum(n for _, n in runs) != needed:
            raise ValueError("Tổng độ dài runs không khớp DataLength")
        last_end = 2
        for start, n in sorted(runs):
            if n <= 0 or start < last_end:
                raise ValueError("Runs trùng cluster hoặc độ dài không hợp lệ")
            self.offset_cluster(start)
            self.offset_cluster(start + n - 1)
            last_end = start + n
        for start, n in runs:
            for cluster in range(start, start + n):
                length = min(remaining, self.cluster_size)
                read = min(valid, length)
                yield self.img.doc(self.offset_cluster(cluster), read) + bytes(length - read)
                remaining -= length
                valid -= read

    def doc_theo_runs(self, entry, runs):
        """Đọc nội dung theo các mảnh do người làm case đề xuất."""
        return b"".join(self._file_chunks(entry, list(runs)))

    def doc_file(self, entry):
        return self.doc_theo_runs(entry, self.file_runs(entry))

    def info(self):
        files = []
        for e in self.liet_ke_file():
            runs = self.file_runs(e)
            sha = hashlib.sha256()
            for chunk in self._file_chunks(e, runs):
                sha.update(chunk)
            files.append(dict(path=e["path"], size=e["kich_thuoc"], sha256=sha.hexdigest(),
                              runs=runs, mtime=e["mtime"]))
        params = dict(fs="exfat", bytes_per_sector=self.bytes_per_sector,
                      sectors_per_cluster=self.cluster_size // self.bytes_per_sector,
                      cluster_size=self.cluster_size, fat_offset=self.fat,
                      cluster_heap_offset=self.heap, cluster_count=self.count,
                      root_cluster=self.boot["root_cluster"])
        return dict(fs="exfat", case="clean", params=params, files=files,
                    unit_size=self.cluster_size, unit_base=self.heap - 2 * self.cluster_size,
                    targets=[f["path"] for f in files], cluster_size=self.cluster_size)
