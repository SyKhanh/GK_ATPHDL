"""Tình huống 2 (exFAT) — Sai Directory Entry (hỏng FirstCluster trong Stream Extension 0xC0).

Cơ sở lý thuyết & quy trình phục hồi:
  1. Đọc vùng thư mục gốc (Root Directory) để thu thập tất cả cluster hệ thống:
     - Cluster của Root Directory
     - Cluster của Allocation Bitmap (entry 0x81)
     - Cluster của Up-case Table (entry 0x82)
  2. Duyệt toàn bộ cây thư mục để thu thập:
     - Cluster của các thư mục con (vd. DATA)
     - Danh sách mọi tập tin cùng metadata (tên, đường dẫn, DataLength, ValidDataLength,
       FirstCluster, cờ NoFatChain, entry_offset, stream_offset).
  3. Phân loại tập tin còn nguyên vẹn và tập tin bị hỏng FirstCluster
     (FirstCluster ngoài vùng heap, chuỗi cluster không hợp lệ/chưa cấp phát/trùng hệ thống,
     hoặc nội dung không khớp định dạng).
  4. Đối chiếu Allocation Bitmap với tập cluster đã có chủ -> thu được các đoạn cluster
     "mồ côi" (orphan) liên tiếp.
  5. Với mỗi tập tin bị hỏng (đều liên tục, cần ceil(DataLength / cluster_size) cluster):
     - Quét mọi vị trí bắt đầu khả dĩ nằm trọn trong các đoạn mồ côi (kể cả khi nhiều tập tin
       mồ côi nằm sát nhau trong cùng một đoạn bitmap).
     - Kiểm chứng cấu trúc nội dung theo định dạng (.JPG, .PNG, .PDF, .TXT, hoặc fallback)
       kèm kiểm tra kích thước chính xác (EOF/IEND/%%EOF) và vùng đệm cuối cluster (slack = 0).
  6. Giải bài toán ghép cặp song ánh không chồng lấp cluster giữa tập tin bị hỏng và ứng viên
     mồ côi (ưu tiên khớp đủ, phủ khít tập cluster mồ côi, tổng điểm tin cậy cao nhất).
  7. Trích xuất các tập tin phục hồi theo đúng đường dẫn gốc và ghi nhật ký chi tiết.
"""

import os
import struct
import zlib

from exfat import ExFAT, doc_entry_thu_muc
from tienich import exfat_set_checksum

# Các magic byte nhị phân phổ biến để loại trừ khi nhận diện tập tin văn bản (.txt)
_BINARY_MAGICS = (
    b"\xff\xd8\xff",          # JPEG
    b"\x89PNG\r\n\x1a\n",     # PNG
    b"%PDF-",                 # PDF
    b"PK\x03\x04",            # ZIP / DOCX / XLSX
    b"GIF87a",
    b"GIF89a",
    b"\x7fELF",
    b"MZ",
    b"Rar!\x1a\x07",
)


def _so_cluster_can(size, cluster_size):
    """Số cluster cần thiết để chứa `size` byte."""
    if size <= 0:
        return 0
    return (size + cluster_size - 1) // cluster_size


def _gom_doan_lien_tiep(clusters):
    """Gom tập hợp/danh sách số cluster thành các đoạn [cluster_đầu, độ_dài] tăng dần."""
    runs = []
    for c in sorted(clusters):
        if runs and c == runs[-1][0] + runs[-1][1]:
            runs[-1][1] += 1
        else:
            runs.append([c, 1])
    return runs


def _clusters_tu_entry_he_thong(fs, first, size):
    """Lấy chuỗi cluster của Allocation Bitmap (0x81) hoặc Up-case Table (0x82)."""
    n = _so_cluster_can(size, fs.cluster_size)
    if n == 0:
        return []
    # Theo đặc tả exFAT, entry 0x81 / 0x82 dùng FAT chain nếu FAT[first] != 0;
    # fallback sang liên tục nếu FAT[first] == 0.
    fat_val = fs.img.u32(fs.active_fat + first * 4)
    if fat_val == 0:
        return list(fs._clusters(first, size, True))
    return list(fs._clusters(first, size, False))


def _thu_thap_cau_truc_volume(fs, log):
    """Đọc Root Directory, entry hệ thống (0x81, 0x82), toàn bộ thư mục và tập tin.

    Trả về:
      - system_clusters: set[int] các cluster của Root, Bitmap, Up-case và thư mục con
      - files: list[dict] toàn bộ metadata tập tin (kể cả tập tin hỏng FirstCluster)
    """
    root_clusters, root_data = fs._root_data()
    system_clusters = set(root_clusters)
    if log:
        log.buoc(
            "Xác định cluster thư mục gốc (Root Directory)",
            offset=fs.offset_cluster(root_clusters[0]),
            gia_tri={"clusters": root_clusters},
        )

    # Quét các entry đặc biệt ở thư mục gốc: Allocation Bitmap (0x81) và Up-case Table (0x82)
    for pos in range(0, len(root_data), 32):
        etype = root_data[pos]
        if etype == 0:
            break
        if etype not in (0x81, 0x82):
            continue
        first = int.from_bytes(root_data[pos + 20:pos + 24], "little")
        size = int.from_bytes(root_data[pos + 24:pos + 32], "little")
        block_idx, rel = divmod(pos, fs.cluster_size)
        entry_off = fs.offset_cluster(root_clusters[block_idx]) + rel
        if first >= 2 and size > 0:
            chain = _clusters_tu_entry_he_thong(fs, first, size)
            system_clusters.update(chain)
            ten_ct = "Allocation Bitmap (0x81)" if etype == 0x81 else "Up-case Table (0x82)"
            if log:
                log.buoc(
                    f"Đọc entry {ten_ct}",
                    offset=entry_off,
                    gia_tri={
                        "first_cluster": first,
                        "data_length": size,
                        "clusters": _gom_doan_lien_tiep(chain),
                    },
                )

    # Duyệt toàn bộ cây thư mục để thu thập cluster thư mục con và danh sách tập tin
    files = []
    used_dirs = set(root_clusters)
    stack = [("", root_clusters, root_data)]
    while stack:
        prefix, dir_clusters, dir_data = stack.pop()
        for entry in doc_entry_thu_muc(dir_data):
            name = entry["ten"]
            if name in (".", "..") or any(ch in name for ch in "/\\:\0"):
                raise ValueError(f"Tên entry không hợp lệ: {name!r}")
            entry["path"] = prefix + name
            for field, pos in (
                ("entry_offset", entry["entry_index_bytes"]),
                ("stream_offset", entry["entry_index_bytes"] + 32),
            ):
                blk, rel = divmod(pos, fs.cluster_size)
                entry[field] = fs.offset_cluster(dir_clusters[blk]) + rel

            if entry["la_thu_muc"]:
                chain = list(fs._clusters(entry["cluster_dau"], entry["kich_thuoc"], entry["lien_tuc"]))
                if used_dirs.intersection(chain):
                    raise ValueError(f"Thư mục {entry['path']} dùng trùng cluster")
                used_dirs.update(chain)
                system_clusters.update(chain)
                if log:
                    log.buoc(
                        f"Đọc thư mục con {entry['path']}",
                        offset=entry["stream_offset"] + 0x14,
                        gia_tri={
                            "first_cluster": entry["cluster_dau"],
                            "data_length": entry["kich_thuoc"],
                            "clusters": _gom_doan_lien_tiep(chain),
                        },
                    )
                raw = b"".join(fs.doc_cluster(c) for c in chain)
                stack.append((entry["path"] + "/", chain, raw[:entry["kich_thuoc"]]))
            else:
                files.append(entry)

    return system_clusters, files


# ------------------------------------------------------------------ kiểm chứng định dạng
def _kiem_tra_slack_zero(fs, last_cluster, size):
    """Kiểm tra vùng slack (từ cuối DataLength đến hết cluster cuối) có toàn 0x00 không."""
    rem = size % fs.cluster_size
    if rem == 0:
        return True, 0
    slack_len = fs.cluster_size - rem
    slack = fs.img.doc(fs.offset_cluster(last_cluster) + rem, slack_len)
    return all(b == 0 for b in slack), slack_len


def _kiem_tra_jpeg(data, slack_zero):
    """Kiểm chứng cấu trúc JPEG hợp lệ (SOI, chuỗi marker, SOF/SOS, EOI FF D9)."""
    n = len(data)
    if n < 4 or not data.startswith(b"\xff\xd8\xff"):
        return False, 0, "không bắt đầu bằng SOI JPEG (FF D8 FF)"

    pos = 2
    seen_sof = False
    seen_sos = False
    eoi_pos = -1

    while pos < n:
        if data[pos] != 0xFF:
            break
        while pos < n and data[pos] == 0xFF:
            pos += 1
        if pos >= n:
            break
        marker = data[pos]
        pos += 1

        if marker == 0xD9:  # EOI
            eoi_pos = pos
            break
        if marker == 0x00 or marker == 0x01 or 0xD0 <= marker <= 0xD7 or marker == 0xD8:
            continue
        if pos + 2 > n:
            break
        seg_len = (data[pos] << 8) | data[pos + 1]
        if seg_len < 2 or pos + seg_len > n:
            break

        if marker in (0xC0, 0xC1, 0xC2, 0xC3, 0xC5, 0xC6, 0xC7, 0xC9, 0xCA, 0xCB, 0xCD, 0xCE, 0xCF):
            seen_sof = True
        pos += seg_len

        if marker == 0xDA:  # SOS -> quét nhanh dữ liệu nén tới marker thực tiếp theo
            seen_sos = True
            while pos < n:
                ff = data.find(b"\xff", pos)
                if ff < 0 or ff + 1 >= n:
                    pos = n
                    break
                nxt = data[ff + 1]
                if nxt == 0x00 or 0xD0 <= nxt <= 0xD7:
                    pos = ff + 2
                elif nxt == 0xFF:
                    pos = ff + 1
                else:
                    pos = ff
                    break

    ends_with_eoi = data.endswith(b"\xff\xd9")
    if not (ends_with_eoi or eoi_pos > 0):
        return False, 0, "thiếu dấu kết thúc EOI (FF D9)"

    score = 50
    reasons = ["header FF D8 FF"]
    if seen_sof:
        score += 15
        reasons.append("có marker SOF")
    if seen_sos:
        score += 15
        reasons.append("có marker SOS")
    if eoi_pos == n:
        score += 30
        reasons.append("EOI khớp chính xác cuối DataLength")
    elif ends_with_eoi:
        score += 20
        reasons.append("kết thúc bằng FF D9")
    else:
        # EOI xuất hiện sớm hơn cuối DataLength (có padding)
        if n - eoi_pos <= 64 and all(b == 0 for b in data[eoi_pos:]):
            score += 10
            reasons.append(f"EOI tại {eoi_pos}, padding 0 phía sau")
        else:
            return False, 0, f"EOI ở {eoi_pos} không khớp DataLength={n}"
    if slack_zero:
        score += 10
        reasons.append("slack toàn 0x00")
    return True, score, ", ".join(reasons)


def _kiem_tra_png(data, slack_zero):
    """Kiểm chứng cấu trúc PNG đầy đủ: signature, chuỗi chunk IHDR..IEND và CRC32."""
    n = len(data)
    if n < 33 or not data.startswith(b"\x89PNG\r\n\x1a\n"):
        return False, 0, "không khớp signature PNG"

    pos = 8
    chunk_count = 0
    seen_ihdr = False
    seen_iend = False
    crc_ok = 0

    while pos + 12 <= n:
        length = struct.unpack_from(">I", data, pos)[0]
        ctype = data[pos + 4:pos + 8]
        data_start = pos + 8
        data_end = data_start + length
        crc_end = data_end + 4
        if crc_end > n:
            return False, 0, f"chunk PNG bị cắt cụt tại offset {pos}"
        expected_crc = struct.unpack_from(">I", data, data_end)[0]
        actual_crc = zlib.crc32(data[pos + 4:data_end]) & 0xFFFFFFFF
        if actual_crc != expected_crc:
            return False, 0, f"CRC32 sai ở chunk {ctype!r} tại offset {pos}"
        crc_ok += 1
        chunk_count += 1
        if chunk_count == 1:
            if ctype != b"IHDR" or length != 13:
                return False, 0, "chunk đầu không phải IHDR hợp lệ"
            seen_ihdr = True
        pos = crc_end
        if ctype == b"IEND":
            if length != 0:
                return False, 0, "chunk IEND có độ dài khác 0"
            seen_iend = True
            break

    if not (seen_ihdr and seen_iend):
        return False, 0, "thiếu IHDR hoặc IEND"
    if pos != n:
        return False, 0, f"IEND kết thúc tại {pos} != DataLength={n}"

    score = 110 + (10 if slack_zero else 0)
    reasons = [f"signature PNG, IHDR..IEND kết thúc đúng DataLength ({crc_ok} chunk CRC32 hợp lệ)"]
    if slack_zero:
        reasons.append("slack toàn 0x00")
    return True, score, ", ".join(reasons)


def _kiem_tra_pdf(data, slack_zero):
    """Kiểm chứng cấu trúc PDF: header %PDF-, trailer/xref, footer %%EOF sát cuối DataLength."""
    n = len(data)
    if n < 16 or not data.startswith(b"%PDF-"):
        return False, 0, "không bắt đầu bằng %PDF-"

    tail = data[max(0, n - 128):]
    eof_idx = tail.rfind(b"%%EOF")
    if eof_idx < 0:
        return False, 0, "không tìm thấy %%EOF ở cuối DataLength"

    after_eof = tail[eof_idx + 5:]
    if any(b not in (0x0A, 0x0D, 0x20, 0x09) for b in after_eof):
        return False, 0, "có dữ liệu lạ phía sau %%EOF"

    score = 75
    reasons = ["header %PDF-", "footer %%EOF khớp cuối DataLength"]
    if b"startxref" in data[max(0, n - 1024):]:
        score += 15
        reasons.append("có startxref")
    if b"endobj" in data or b"xref" in data:
        score += 10
        reasons.append("có cấu trúc đối tượng PDF")
    if slack_zero:
        score += 10
        reasons.append("slack toàn 0x00")
    return True, score, ", ".join(reasons)


def _kiem_tra_txt(data, slack_zero, has_slack):
    """Kiểm chứng tập tin văn bản (.txt): UTF-8/ASCII in được, không NUL, không magic nhị phân."""
    n = len(data)
    if n == 0:
        return True, 50, "tập tin rỗng"
    for magic in _BINARY_MAGICS:
        if data.startswith(magic):
            return False, 0, f"bắt đầu bằng magic nhị phân {magic!r}"
    if b"\x00" in data:
        return False, 0, "chứa byte NUL (0x00) trong nội dung"
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError:
        return False, 0, "không giải mã được UTF-8"

    printable = sum(1 for ch in text if ch.isprintable() or ch in "\r\n\t")
    ratio = printable / len(text) if text else 1.0
    if ratio < 0.98:
        return False, 0, f"tỷ lệ ký tự in được thấp ({ratio:.2%})"

    score = 70
    reasons = [f"UTF-8 hợp lệ ({ratio:.0%} ký tự in được)"]
    if all(ord(ch) < 128 for ch in text):
        score += 10
        reasons.append("thuần ASCII")
    if has_slack:
        if slack_zero:
            score += 25
            reasons.append("slack cuối cluster toàn 0x00")
        else:
            # Nếu không phải toàn 0x00 sau DataLength, rất có thể cắt nhầm giữa 1 file text dài hơn
            score -= 20
            reasons.append("cảnh báo: slack không toàn 0x00")
    return True, score, ", ".join(reasons)


def _kiem_tra_noi_dung(ext, data, slack_zero, has_slack):
    """Kiểm chứng nội dung theo phần mở rộng của tập tin."""
    ext = ext.lower()
    if ext in (".jpg", ".jpeg"):
        return _kiem_tra_jpeg(data, slack_zero)
    if ext == ".png":
        return _kiem_tra_png(data, slack_zero)
    if ext == ".pdf":
        return _kiem_tra_pdf(data, slack_zero)
    if ext == ".txt":
        return _kiem_tra_txt(data, slack_zero, has_slack)
    # Fallback tổng quát cho các phần mở rộng khác (nếu có)
    score = 40 + (15 if slack_zero else 0)
    return True, score, "định dạng chưa có quy tắc riêng (khớp kích thước)"


def _loc_nhanh_header(ext, head16):
    """Lọc nhanh dựa trên 16 byte đầu cluster trước khi đọc toàn bộ tập tin."""
    ext = ext.lower()
    if ext in (".jpg", ".jpeg"):
        return head16.startswith(b"\xff\xd8\xff")
    if ext == ".png":
        return head16.startswith(b"\x89PNG\r\n\x1a\n")
    if ext == ".pdf":
        return head16.startswith(b"%PDF-")
    if ext == ".txt":
        if not head16 or head16[0] == 0:
            return False
        for magic in _BINARY_MAGICS:
            if head16.startswith(magic):
                return False
        return True
    return True


# ------------------------------------------------------------------ phân loại & tìm mồ côi
def _kiem_tra_file_nguyen(fs, entry, bitmap, system_clusters):
    """Kiểm tra một tập tin có FirstCluster hợp lệ và còn nguyên vẹn hay không.

    Trả về (ok: bool, runs: list | None, ly_do_hong: str | None).
    """
    size = entry["kich_thuoc"]
    first = entry["cluster_dau"]
    if size == 0:
        return True, [], None
    if not (2 <= first < fs.count + 2):
        return False, None, f"FirstCluster={first} nằm ngoài vùng heap [2, {fs.count + 1}]"

    try:
        runs = fs.file_runs(entry)
    except ValueError as exc:
        return False, None, f"không đọc được chuỗi cluster ({exc})"

    for start, length in runs:
        for c in range(start, start + length):
            if c in system_clusters:
                return False, None, f"cluster {c} trùng với vùng hệ thống"
            if not fs.da_cap_phat(bitmap, c):
                return False, None, f"cluster {c} chưa được cấp phát trong Allocation Bitmap"

    # Kiểm tra nhanh định dạng nội dung ở vị trí hiện tại (phòng trường hợp FirstCluster bị sửa sang số khác 0)
    ext = os.path.splitext(entry["ten"])[1].lower()
    if ext in (".jpg", ".jpeg", ".png", ".pdf", ".txt"):
        data = fs.doc_theo_runs(entry, runs)
        last_cluster = runs[-1][0] + runs[-1][1] - 1
        slack_zero, slack_len = _kiem_tra_slack_zero(fs, last_cluster, size)
        ok, _, reason = _kiem_tra_noi_dung(ext, data, slack_zero, slack_len > 0)
        if not ok:
            return False, None, f"nội dung tại FirstCluster={first} không khớp định dạng {ext} ({reason})"

    return True, runs, None


def _liet_ke_cluster_cap_phat(fs, bitmap):
    """Trả về tập hợp tất cả cluster có bit=1 trong Allocation Bitmap (tối ưu theo từng byte)."""
    allocated = set()
    max_cluster = fs.count + 2
    max_bytes = (fs.count + 7) // 8
    for byte_idx in range(min(len(bitmap), max_bytes)):
        val = bitmap[byte_idx]
        if not val:
            continue
        base = 2 + byte_idx * 8
        for bit in range(8):
            if val & (1 << bit):
                c = base + bit
                if c < max_cluster:
                    allocated.add(c)
    return allocated


# ------------------------------------------------------------------ giải bài toán ghép cặp
def _tim_phep_ghep_toi_uu(broken_files, candidates_by_idx, total_orphan_clusters):
    """Tìm phép ghép cặp song ánh không chồng lấp cluster tối ưu nhất.

    Trả về (best_assignment, tie_count) với best_assignment là dict {idx: candidate_dict}.
    """
    order = sorted(range(len(broken_files)), key=lambda i: len(candidates_by_idx[i]))
    best_key = None
    best_assign = None
    tie_count = 0

    current = {}
    used_intervals = []  # list[(start, end_exclusive)]

    def overlaps(s, e):
        for us, ue in used_intervals:
            if s < ue and us < e:
                return True
        return False

    def backtrack(pos, total_score, covered_clusters):
        nonlocal best_key, best_assign, tie_count
        if pos == len(order):
            exact_cover = 1 if covered_clusters == total_orphan_clusters else 0
            key = (len(current), exact_cover, total_score)
            if best_key is None or key > best_key:
                best_key = key
                best_assign = dict(current)
                tie_count = 1
            elif key == best_key:
                tie_count += 1
            return

        idx = order[pos]
        need = broken_files[idx]["_need_clusters"]
        for cand in candidates_by_idx[idx]:
            s = cand["first_cluster"]
            e = s + need
            if overlaps(s, e):
                continue
            current[idx] = cand
            used_intervals.append((s, e))
            backtrack(pos + 1, total_score + cand["score"], covered_clusters + need)
            used_intervals.pop()
            del current[idx]

    backtrack(0, 0, 0)
    return best_assign, tie_count


# ------------------------------------------------------------------ giao diện chính
def giai_case2(img, log=None):
    """Phân tích ảnh exFAT Case 2 và trả về (fs, results).

    Mỗi phần tử trong `results` là dict:
      {
        "entry": entry,
        "first_cluster": int,
        "runs": [(first_cluster, n_clusters)],
        "score": int,
        "ly_do": str,
        "ly_do_hong": str,
      }
    """
    fs = ExFAT(img, log)
    if log:
        log.buoc(
            "Đọc tham số Boot Sector exFAT",
            offset=0,
            gia_tri={
                "bytes_per_sector": fs.bytes_per_sector,
                "cluster_size": fs.cluster_size,
                "fat_offset": fs.fat,
                "cluster_heap_offset": fs.heap,
                "cluster_count": fs.count,
                "root_cluster": fs.boot["root_cluster"],
            },
        )

    bitmap = fs.doc_bitmap()
    system_clusters, files = _thu_thap_cau_truc_volume(fs, log)

    # Phân loại tập tin nguyên vẹn và tập tin hỏng FirstCluster
    intact_entries = []
    broken_files = []
    cluster_owners = {}  # cluster -> list[file_idx] để phát hiện trùng lặp nếu có

    for idx, entry in enumerate(files):
        ok, runs, reason = _kiem_tra_file_nguyen(fs, entry, bitmap, system_clusters)
        if ok:
            intact_entries.append((idx, entry, runs))
            for s, n in runs:
                for c in range(s, s + n):
                    cluster_owners.setdefault(c, []).append(idx)
        else:
            entry["_ly_do_hong"] = reason
            entry["_need_clusters"] = _so_cluster_can(entry["kich_thuoc"], fs.cluster_size)
            broken_files.append(entry)
            if log:
                log.buoc(
                    f"Phát hiện tập tin hỏng FirstCluster: {entry['path']}",
                    offset=entry["stream_offset"] + 0x14,
                    gia_tri={
                        "first_cluster_doc_duoc": entry["cluster_dau"],
                        "data_length": entry["kich_thuoc"],
                        "so_cluster_can": entry["_need_clusters"],
                        "checksum_khop": entry["checksum_khop"],
                        "ly_do": reason,
                    },
                )

    # Kiểm tra nếu có 2 tập tin được xếp nguyên vẹn nhưng lại dùng trùng cluster
    conflict_idxs = {i for owners in cluster_owners.values() if len(owners) > 1 for i in owners}
    used_clusters = set(system_clusters)
    for idx, entry, runs in intact_entries:
        if idx in conflict_idxs:
            entry["_ly_do_hong"] = "dùng trùng cluster với tập tin khác"
            entry["_need_clusters"] = _so_cluster_can(entry["kich_thuoc"], fs.cluster_size)
            broken_files.append(entry)
            if log:
                log.canh_bao(
                    f"Tập tin {entry['path']} có cluster chồng lấp, chuyển sang phục hồi",
                    offset=entry["stream_offset"] + 0x14,
                    runs=runs,
                )
        else:
            for s, n in runs:
                used_clusters.update(range(s, s + n))
            if log:
                log.buoc(
                    f"Ghi nhận tập tin nguyên vẹn: {entry['path']}",
                    offset=entry["stream_offset"] + 0x14,
                    gia_tri={
                        "first_cluster": entry["cluster_dau"],
                        "data_length": entry["kich_thuoc"],
                        "runs": runs,
                    },
                )

    if not broken_files:
        if log:
            log.canh_bao("Không phát hiện tập tin nào bị hỏng FirstCluster")
        return fs, []

    # Tìm tất cả cluster đã cấp phát nhưng không ai tham chiếu (orphan)
    allocated_clusters = _liet_ke_cluster_cap_phat(fs, bitmap)
    orphan_clusters = allocated_clusters - used_clusters
    orphan_segments = _gom_doan_lien_tiep(orphan_clusters)

    if log:
        log.buoc(
            "Tìm các đoạn cluster mồ côi từ Allocation Bitmap",
            gia_tri={
                "tong_cap_phat": len(allocated_clusters),
                "tong_da_co_chu": len(used_clusters),
                "tong_mo_coi": len(orphan_clusters),
                "cac_doan_mo_coi": orphan_segments,
            },
        )

    # Đọc trước 16 byte đầu mỗi cluster mồ côi để lọc nhanh
    head_cache = {c: img.doc(fs.offset_cluster(c), 16) for c in orphan_clusters}

    # Sinh và chấm điểm các ứng viên cho từng tập tin bị hỏng
    candidates_by_idx = []
    for idx, entry in enumerate(broken_files):
        ext = os.path.splitext(entry["ten"])[1].lower()
        need = entry["_need_clusters"]
        size = entry["kich_thuoc"]
        cands = []

        for seg_start, seg_len in orphan_segments:
            if seg_len < need:
                continue
            for start in range(seg_start, seg_start + seg_len - need + 1):
                if not _loc_nhanh_header(ext, head_cache[start]):
                    continue
                runs = [(start, need)]
                data = fs.doc_theo_runs(entry, runs)
                last_cluster = start + need - 1
                slack_zero, slack_len = _kiem_tra_slack_zero(fs, last_cluster, size)
                valid, score, reason = _kiem_tra_noi_dung(ext, data, slack_zero, slack_len > 0)
                if not valid:
                    continue
                # Cộng nhẹ điểm thưởng nếu khớp chính xác toàn bộ 1 đoạn mồ côi độc lập
                if start == seg_start and need == seg_len:
                    score += 5
                    reason += ", khớp trọn đoạn mồ côi"
                cands.append({
                    "first_cluster": start,
                    "runs": runs,
                    "score": score,
                    "ly_do": reason,
                    "offset": fs.offset_cluster(start),
                })

        cands.sort(key=lambda x: (-x["score"], x["first_cluster"]))
        candidates_by_idx.append(cands)
        if log:
            log.buoc(
                f"Tìm ứng viên mồ côi cho {entry['path']} ({size} byte, {need} cluster)",
                gia_tri=[
                    {
                        "first_cluster": c["first_cluster"],
                        "offset": f"{c['offset']:#x}",
                        "score": c["score"],
                        "ly_do": c["ly_do"],
                    }
                    for c in cands[:10]
                ],
            )
        if not cands:
            raise RuntimeError(f"Không tìm thấy ứng viên mồ côi phù hợp cho {entry['path']}")

    # Tìm phép ghép cặp tối ưu không chồng lấp
    best_assign, tie_count = _tim_phep_ghep_toi_uu(
        broken_files, candidates_by_idx, len(orphan_clusters)
    )
    if best_assign is None or len(best_assign) != len(broken_files):
        raise RuntimeError("Không tìm được phép ghép cặp không chồng lấp cho tất cả tập tin mục tiêu")

    if tie_count > 1 and log:
        log.canh_bao("Có nhiều phương án ghép cặp cùng điểm tối ưu", so_phuong_an=tie_count)

    results = []
    for idx, entry in enumerate(broken_files):
        chosen = best_assign[idx]
        if log:
            log.quyet_dinh(
                f"Ghép {entry['path']} -> cluster đầu {chosen['first_cluster']}",
                path=entry["path"],
                entry_offset=f"{entry['stream_offset'] + 0x14:#x}",
                first_cluster=chosen["first_cluster"],
                data_offset=f"{chosen['offset']:#x}",
                so_cluster=entry["_need_clusters"],
                kich_thuoc=entry["kich_thuoc"],
                diem=chosen["score"],
                tieu_chi=chosen["ly_do"],
            )
        results.append({
            "entry": entry,
            "first_cluster": chosen["first_cluster"],
            "runs": chosen["runs"],
            "score": chosen["score"],
            "ly_do": chosen["ly_do"],
            "ly_do_hong": entry["_ly_do_hong"],
        })

    return fs, results


def thuc_hien_case2(img, out, log):
    """Điểm gọi từ BaiLam.case2(img, out): giải và trích xuất các tập tin phục hồi."""
    fs, results = giai_case2(img, log)
    for item in results:
        entry = item["entry"]
        data = fs.doc_theo_runs(entry, item["runs"])
        saved_path = out.luu(entry["path"], data)
        if log:
            log.buoc(
                f"Trích xuất tập tin {entry['path']}",
                offset=fs.offset_cluster(item["first_cluster"]),
                gia_tri={"kich_thuoc": len(data), "duong_dan_luu": saved_path},
            )
    return results


def sua_case2(img, anh_moi, log):
    """Hỗ trợ --repair cho Case 2: ghi lại FirstCluster và tính lại SetChecksum trên bản sao."""
    _, results = giai_case2(img, log)
    ban_sua = img.sao_chep(anh_moi)
    try:
        for item in results:
            entry = item["entry"]
            first_cluster = item["first_cluster"]
            fc_offset = entry["stream_offset"] + 0x14
            ban_sua.ghi_u32(fc_offset, first_cluster)

            # Tính lại SetChecksum của toàn bộ entry set (0x85 + SecondaryCount entry kế tiếp)
            sec_count = ban_sua.u8(entry["entry_offset"] + 1)
            set_len = (1 + sec_count) * 32
            raw_set = ban_sua.doc(entry["entry_offset"], set_len)
            new_checksum = exfat_set_checksum(raw_set)
            ban_sua.ghi_u16(entry["entry_offset"] + 2, new_checksum)

            if log:
                log.quyet_dinh(
                    f"Sửa FirstCluster và SetChecksum cho {entry['path']}",
                    first_cluster_offset=f"{fc_offset:#x}",
                    first_cluster=first_cluster,
                    checksum_offset=f"{entry['entry_offset'] + 2:#x}",
                    set_checksum=f"{new_checksum:#06x}",
                )
    finally:
        ban_sua.dong()
    return results
