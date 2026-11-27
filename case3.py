"""Tình huống 3 (exFAT) — Sai chuỗi vị trí (tập tin JPEG phân mảnh 2 mảnh).

Cơ sở lý thuyết & quy trình phục hồi:
  1. Đọc Boot Sector, Allocation Bitmap và duyệt cây thư mục (Root -> DATA) để lấy
     FirstCluster, DataLength, cờ NoFatChain của từng tập tin.
  2. Phát hiện tập tin hỏng: chuỗi FAT của tập tin ngắn hơn ceil(DataLength / cluster_size)
     (FAT[FirstCluster] = 0, cờ NoFatChain đã bị bỏ). Tập tin còn nguyên thì đọc theo FAT
     hoặc liên tục (NoFatChain) như bình thường.
  3. Tính số cluster cần có N = ceil(DataLength / cluster_size). Biết cluster đầu c0;
     mảnh 1 dài n1 cluster (chưa biết), mảnh 2 dài N - n1 bắt đầu cách mảnh 1 g cluster
     (g trong khoảng 1..KICH_THUOC_CUA_SO).
  4. Rút gọn ứng viên bằng Allocation Bitmap: bit của mọi cluster sau c0 đã bị xoá nên các
     cluster còn lại của tập tin phải "trống" và khác 0.
  5. Chọn ứng viên bằng nội dung: ghép dữ liệu, kiểm tra kết thúc FF D9 đúng byte cuối
     DataLength, phân tích marker JPEG và giải mã Huffman toàn bộ ảnh (đúng số MCU,
     đúng số đoạn RSTn, không thừa/thiếu bit).
  6. Ghi chuỗi vị trí cuối cùng và trích xuất tập tin theo đường dẫn gốc.
"""

import hashlib
import os
import struct
import time

from exfat import ExFAT, doc_entry_thu_muc

TG_TOI_DA = 8 * 60            # giây; chừa dư so với giới hạn 10 phút/ảnh
KICH_THUOC_CUA_SO = 64        # mảnh 2 nằm trong vòng ~64 cluster sau mảnh 1


def _buoc(log, msg, **kw):
    if log:
        log.buoc(msg, **kw)


def _quyet_dinh(log, msg, **kw):
    if log:
        log.quyet_dinh(msg, **kw)


# ------------------------------------------------------------------ kiểm chứng JPEG
class _Hong(Exception):
    pass


def _bang_huffman(dem, ky_hieu):
    bang, ma, k = {}, 0, 0
    for do_dai in range(1, 17):
        for _ in range(dem[do_dai - 1]):
            bang[(do_dai, ma)] = ky_hieu[k]
            k += 1
            ma += 1
        ma <<= 1
    return bang


def _tach_scan(d, i):
    """Tach du lieu entropy thanh cac doan (theo RSTn), bo byte stuffing.
    Tra ve (cac_doan, vi_tri_marker_ket_thuc)."""
    doan, cur, j = [], bytearray(), i
    while True:
        k = d.find(b"\xff", j)
        if k < 0 or k + 1 >= len(d):
            raise _Hong("scan khong ket thuc bang marker")
        cur += d[j:k]
        nxt = d[k + 1]
        if nxt == 0x00:
            cur.append(0xFF)
            j = k + 2
        elif 0xD0 <= nxt <= 0xD7:
            doan.append(bytes(cur))
            cur = bytearray()
            j = k + 2
        elif nxt == 0xFF:
            j = k + 1
        else:
            doan.append(bytes(cur))
            return doan, k


def _giai_ma_doan(seg, so_mcu, thanh_phan):
    """thanh_phan: list (so_block_moi_mcu, bang_dc, bang_ac). Chi can doc dung do dai bit."""
    nbit = len(seg) * 8
    pos = 0

    def ky_hieu(bang):
        nonlocal pos
        ma = 0
        for do_dai in range(1, 17):
            if pos >= nbit:
                raise _Hong("het du lieu")
            ma = (ma << 1) | ((seg[pos >> 3] >> (7 - (pos & 7))) & 1)
            pos += 1
            s = bang.get((do_dai, ma))
            if s is not None:
                return s
        raise _Hong("ma Huffman khong hop le")

    for _ in range(so_mcu):
        for n_block, dc, ac in thanh_phan:
            for _ in range(n_block):
                s = ky_hieu(dc)
                if s > 15:
                    raise _Hong("DC khong hop le")
                pos += s
                k = 1
                while k < 64:
                    rs = ky_hieu(ac)
                    r, s = rs >> 4, rs & 15
                    if s == 0:
                        if r == 15:
                            k += 16
                            continue
                        break
                    k += r + 1
                    pos += s
                if k > 64:
                    raise _Hong("AC vuot 64 he so")
        if pos > nbit:
            raise _Hong("het du lieu")
    if nbit - pos >= 8:
        raise _Hong("con thua >= 1 byte sau MCU cuoi")


def kiem_tra_jpeg(d):
    """Tra ve 'day_du' (giai ma Huffman het anh), 'cau_truc' (progressive: chi kiem cau truc),
    hoac nem _Hong."""
    if d[:2] != b"\xff\xd8":
        raise _Hong("khong co SOI")
    pos, huff, khung, ri = 2, {}, None, 0
    tien_bo, so_scan = False, 0
    while True:
        if pos + 2 > len(d) or d[pos] != 0xFF:
            raise _Hong("marker sai vi tri")
        while pos + 1 < len(d) and d[pos + 1] == 0xFF:
            pos += 1
        m = d[pos + 1]
        if m == 0xD9:
            if khung is None or so_scan == 0:
                raise _Hong("EOI truoc khi co scan")
            if pos + 2 != len(d):
                raise _Hong("EOI khong nam o cuoi tap tin")
            return "cau_truc" if tien_bo else "day_du"
        if m == 0x01 or 0xD0 <= m <= 0xD7 or m == 0x00:
            raise _Hong("marker doc lap bat thuong")
        if pos + 4 > len(d):
            raise _Hong("cut o segment")
        L = struct.unpack(">H", d[pos + 2:pos + 4])[0]
        seg = d[pos + 4:pos + 2 + L]
        if L < 2 or len(seg) != L - 2:
            raise _Hong("do dai segment sai")
        if m == 0xC4:
            q = 0
            while q < len(seg):
                tc_th = seg[q]
                dem = list(seg[q + 1:q + 17])
                n = sum(dem)
                ky = list(seg[q + 17:q + 17 + n])
                if len(dem) != 16 or len(ky) != n:
                    raise _Hong("DHT cut")
                huff[(tc_th >> 4, tc_th & 15)] = _bang_huffman(dem, ky)
                q += 17 + n
        elif m in (0xC0, 0xC1, 0xC2) or (0xC3 <= m <= 0xCF and m not in (0xC4, 0xC8, 0xCC)):
            if m in (0xC0, 0xC1):
                P, Y, X, nf = struct.unpack(">BHHB", seg[:6])
                tp = [(seg[6 + 3 * i], seg[7 + 3 * i] >> 4, seg[7 + 3 * i] & 15) for i in range(nf)]
                if X == 0 or Y == 0 or not tp:
                    raise _Hong("SOF sai")
                khung = (X, Y, tp)
            else:
                tien_bo = True
                khung = khung or (0, 0, [])
        elif m == 0xDD:
            ri = struct.unpack(">H", seg[:2])[0]
        elif m == 0xDA:
            ns = seg[0]
            ts = [(seg[1 + 2 * i], seg[2 + 2 * i] >> 4, seg[2 + 2 * i] & 15) for i in range(ns)]
            doan, vt = _tach_scan(d, pos + 2 + L)
            if khung is None:
                raise _Hong("SOS truoc SOF")
            if not tien_bo:
                X, Y, tp = khung
                hmax = max(h for _, h, _ in tp)
                vmax = max(v for _, _, v in tp)
                thanh_phan, tuong = [], {c[0]: c for c in tp}
                for cs, td, ta in ts:
                    if cs not in tuong or (0, td) not in huff or (1, ta) not in huff:
                        raise _Hong("thieu bang Huffman/thanh phan")
                if ns > 1:
                    mx = -(-X // (8 * hmax))
                    my = -(-Y // (8 * vmax))
                    tong = mx * my
                    for cs, td, ta in ts:
                        _, h, v = tuong[cs]
                        thanh_phan.append((h * v, huff[(0, td)], huff[(1, ta)]))
                else:
                    cs, td, ta = ts[0]
                    _, h, v = tuong[cs]
                    cw = -(-X * h // hmax)
                    ch = -(-Y * v // vmax)
                    tong = (-(-cw // 8)) * (-(-ch // 8))
                    thanh_phan.append((1, huff[(0, td)], huff[(1, ta)]))
                mong = -(-tong // ri) if ri else 1
                if len(doan) != mong:
                    raise _Hong("so doan RST khong khop (%d != %d)" % (len(doan), mong))
                for i, sg in enumerate(doan):
                    n = ri if ri else tong
                    n = min(n, tong - i * n) if ri else tong
                    _giai_ma_doan(sg, n, thanh_phan)
            so_scan += 1
            pos = vt
            continue
        pos += 2 + L


# ------------------------------------------------------------------ đọc tập tin
def _thu_thap_tap_tin(fs):
    """Duyệt cây thư mục, trả về danh sách tập tin (kèm đường dẫn, offset stream)."""
    root_clusters, root_data = fs._root_data()
    files = []
    stack = [("", root_clusters, root_data)]
    while stack:
        prefix, dir_clusters, dir_data = stack.pop()
        for entry in doc_entry_thu_muc(dir_data):
            name = entry["ten"]
            if name in (".", "..") or any(ch in name for ch in "/\\:\0"):
                raise ValueError(f"Tên entry không hợp lệ: {name!r}")
            entry["path"] = prefix + name
            blk, rel = divmod(entry["entry_index_bytes"] + 32, fs.cluster_size)
            entry["stream_offset"] = fs.offset_cluster(dir_clusters[blk]) + rel
            if entry["la_thu_muc"]:
                chain = list(fs._clusters(entry["cluster_dau"], entry["kich_thuoc"], entry["lien_tuc"]))
                raw = b"".join(fs.doc_cluster(c) for c in chain)
                stack.append((entry["path"] + "/", chain, raw[:entry["kich_thuoc"]]))
            else:
                files.append(entry)
    return files


def _chuoi_fat(fs, first, toi_da):
    """Đi theo chuỗi FAT từ `first`, dừng khi gặp EOF, giá trị không hợp lệ hoặc đủ `toi_da`."""
    kq, c = [], first
    while 2 <= c < fs.count + 2 and len(kq) < toi_da:
        kq.append(c)
        nxt = fs.img.u32(fs.active_fat + c * 4)
        if nxt >= 0xFFFFFFF8 or nxt < 2:
            break
        c = nxt
    return kq


def _doc_tap_tin(fs, entry):
    """Trả về (danh_sach_cluster, day_du). day_du=False nếu chuỗi FAT không đủ cluster."""
    size, first = entry["kich_thuoc"], entry["cluster_dau"]
    n = -(-size // fs.cluster_size) if size else 0
    if n == 0:
        return [], True
    if entry["lien_tuc"]:
        ds = list(range(first, first + n))
        return ds, ds[-1] < fs.count + 2 and first >= 2
    ds = _chuoi_fat(fs, first, n)
    ok = len(ds) == n and (n == 1 or fs.img.u32(fs.active_fat + ds[-1] * 4) >= 0xFFFFFFF8)
    return ds, ok


def _rut_gon(ds):
    kq, s = [], ds[0]
    for a, b in zip(ds, ds[1:] + [None]):
        if b != a + 1:
            kq.append(f"{s}..{a}" if s != a else str(a))
            s = b
    return " + ".join(kq)


# ------------------------------------------------------------------ ghép mảnh JPEG
def _ghep_jpeg(fs, bitmap, entry, log, han):
    c0, size = entry["cluster_dau"], entry["kich_thuoc"]
    cs = fs.cluster_size
    N = -(-size // cs)
    cache = {}

    def cluster(c):
        d = cache.get(c)
        if d is None:
            d = fs.doc_cluster(c)
            if len(cache) < 4096:
                cache[c] = d
        return d

    def trong(c):
        return 2 <= c < fs.count + 2 and not fs.da_cap_phat(bitmap, c)

    def khac_0(c):
        return any(cluster(c))

    _buoc(log, f"Tính số cluster cần có cho {entry['path']}",
          offset=entry["stream_offset"] + 0x14,
          gia_tri={"data_length": size, "cluster_size": cs, "so_cluster_can": N, "cluster_dau": c0})

    for che_do in ("bitmap+noi_dung", "noi_dung"):
        bo_bitmap = che_do == "noi_dung"
        da_thu, hop_le = 0, []
        for n1 in range(1, N):
            if n1 > 1 and not bo_bitmap and not trong(c0 + n1 - 1):
                break
            if n1 > 1 and not khac_0(c0 + n1 - 1):
                break
            n2 = N - n1
            for g in list(range(1, KICH_THUOC_CUA_SO + 1)) + [0]:
                if time.time() > han:
                    _buoc(log, "Hết thời gian tìm kiếm ứng viên")
                    return None
                s = c0 + n1 + g
                if s + n2 - 1 >= fs.count + 2:
                    continue
                ds2 = range(s, s + n2)
                if not bo_bitmap and not all(trong(c) for c in ds2):
                    continue
                if not all(khac_0(c) for c in ds2[:-1]):
                    continue
                ds = list(range(c0, c0 + n1)) + list(ds2)
                d = b"".join(cluster(c) for c in ds)[:size]
                if d[-2:] != b"\xff\xd9":
                    continue
                da_thu += 1
                try:
                    muc = kiem_tra_jpeg(d)
                except _Hong:
                    continue
                hop_le.append((muc, n1, g, ds, d))
                if muc == "day_du":
                    break
            if hop_le and hop_le[-1][0] == "day_du":
                break
        _buoc(log, f"Chế độ '{che_do}': thử {da_thu} ứng viên, {len(hop_le)} hợp lệ",
              gia_tri={"che_do": che_do, "ung_vien_da_thu": da_thu, "hop_le": len(hop_le)})
        if hop_le:
            hop_le.sort(key=lambda x: x[0] != "day_du")
            muc, n1, g, ds, d = hop_le[0]
            _quyet_dinh(log, f"Ghép mảnh cho {entry['path']}",
                        path=entry["path"],
                        manh_1=f"cluster {ds[0]}..{ds[n1 - 1]} ({n1} cluster)",
                        khoang_cach=f"{g} cluster",
                        manh_2=f"cluster {ds[n1]}..{ds[-1]} ({N - n1} cluster)",
                        chuoi_vi_tri=_rut_gon(ds),
                        tieu_chi=f"kết thúc FF D9 đúng DataLength, giải mã JPEG: {muc}")
            return ds, d
    return None


# ------------------------------------------------------------------ giao diện chính
def thuc_hien_case3(img, out, log):
    """Điểm gọi từ BaiLam.case3(img, out): phục hồi và trích xuất toàn bộ tập tin."""
    han = time.time() + TG_TOI_DA
    fs = ExFAT(img, log)
    _buoc(log, "Đọc tham số Boot Sector exFAT", offset=0, gia_tri={
        "bytes_per_sector": fs.bytes_per_sector,
        "cluster_size": fs.cluster_size,
        "fat_offset": fs.fat,
        "cluster_heap_offset": fs.heap,
        "cluster_count": fs.count,
        "root_cluster": fs.boot["root_cluster"],
    })
    bitmap = fs.doc_bitmap()
    files = _thu_thap_tap_tin(fs)

    ket_qua = []
    for entry in sorted(files, key=lambda e: e["path"]):
        size, first = entry["kich_thuoc"], entry["cluster_dau"]
        ds, ok = _doc_tap_tin(fs, entry)
        _buoc(log, f"Kiểm tra chuỗi cluster {entry['path']}",
              offset=entry["stream_offset"] + 0x14,
              gia_tri={"first_cluster": first, "data_length": size,
                       "no_fat_chain": entry["lien_tuc"],
                       "chuoi_fat": "hợp lệ" if ok else "BỊ PHÁ (ngắn hơn số cluster cần có)"})
        n = -(-size // fs.cluster_size) if size else 0
        if ok:
            data = b"".join(fs.doc_cluster(c) for c in ds)[:size]
        else:
            data = None
            if fs.doc_cluster(first)[:3] == b"\xff\xd8\xff":
                kq = _ghep_jpeg(fs, bitmap, entry, log, han)
                if kq:
                    ds, data = kq
            if data is None:
                if log:
                    log.canh_bao(f"Không ghép được {entry['path']}, đọc liên tục từ cluster đầu")
                ds = list(range(first, first + n))
                data = b"".join(fs.doc_cluster(c) for c in ds)[:size]
        duong_dan = out.luu(entry["path"], data)
        _buoc(log, f"Trích xuất tập tin {entry['path']}",
              offset=fs.offset_cluster(ds[0]) if ds else 0,
              gia_tri={"chuoi_vi_tri": _rut_gon(ds) if ds else "",
                       "kich_thuoc": len(data),
                       "sha256": hashlib.sha256(data).hexdigest(),
                       "duong_dan_luu": duong_dan})
        ket_qua.append((entry["path"], ds))
    return ket_qua