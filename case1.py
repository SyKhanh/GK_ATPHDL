"""Tình huống 1 — sai FatOffset (0x50), ClusterHeapOffset (0x58), SectorsPerClusterShift (0x6D).

Cả Main Boot Region lẫn Backup Boot Region (sector 12–23) đều bị sai, Boot Checksum đã được tính
lại cho khớp, nên KHÔNG dùng được bản sao hay checksum. Ba giá trị được suy ra từ chính các cấu
trúc còn nguyên vẹn, dùng các trường không bị sửa (BytesPerSectorShift, VolumeLength, FatLength,
ClusterCount, FirstClusterOfRootDirectory, NumberOfFats):

  B1. FatOffset: FAT bắt đầu bằng FAT[0] = 0xFFFFFFF8 (media descriptor F8) và FAT[1] = 0xFFFFFFFF.
      Quét theo sector từ sector 24 (sau 2 vùng boot) để tìm 8 byte F8 FF FF FF FF FF FF FF.
  B2. Tìm thư mục gốc qua nội dung: entry Allocation Bitmap (0x81) có DataLength
      = ceil(ClusterCount / 8), đi kèm entry Up-case Table (0x82). Hai entry này cho biết cluster
      đầu và độ dài của bitmap và bảng up-case.
  B3. SectorsPerClusterShift: bitmap và bảng up-case luôn dùng chuỗi FAT. Độ dài chuỗi FAT (đọc
      tại FatOffset ở B1) = ceil(DataLength / ClusterSize) → khoảng hợp lệ cho ClusterSize.
  B4. ClusterHeapOffset: entry 0x81 nằm trong cluster đầu của thư mục gốc, nên
      heap ∈ (E − (root−1)·cs, E − (root−2)·cs]. Thử từng heap (theo sector) trong khoảng đó,
      giữ ứng viên mà tại heap + (cluster_upcase − 2)·cs, TableChecksum của bảng up-case khớp và
      bitmap tại heap + (cluster_bitmap − 2)·cs có bit của các cluster hệ thống = 1.
  B5. Kiểm chứng: dựng ExFAT(hieu_chinh=...), duyệt cây, đọc mọi tập tin, kiểm tra chữ ký định dạng.

Không có giá trị nào của ảnh nhóm được cố định trong mã.
"""
from exfat import ExFAT, doc_boot_tho, kiem_tra_boot_checksum, doc_entry_thu_muc

FAT_SIG = b"\xF8\xFF\xFF\xFF\xFF\xFF\xFF\xFF"      # FAT[0] = 0xFFFFFFF8, FAT[1] = 0xFFFFFFFF
ENTRY_BITMAP_HEAD = b"\x81"                     # + BitmapFlags (0/1) + 18 byte Reserved = 0
ENTRY_UPCASE = 0x82


def _upcase_checksum(data):
    """TableChecksum của bảng up-case (đặc tả exFAT §7.2.2): xoay phải 32 bit rồi cộng từng byte."""
    c = 0
    for b in data:
        c = ((((c & 1) << 31) | (c >> 1)) + b) & 0xFFFFFFFF
    return c


def _chu_ky_hop_le(path, data):
    p = path.upper()
    if p.endswith((".JPG", ".JPEG")):
        return data[:3] == b"\xFF\xD8\xFF" and data[-2:] == b"\xFF\xD9"
    if p.endswith(".PNG"):
        return data[:8] == b"\x89PNG\r\n\x1a\n" and data[-8:-4] == b"IEND"
    if p.endswith(".PDF"):
        return data[:5] == b"%PDF-" and b"%%EOF" in data[-1024:]
    if p.endswith(".TXT"):
        return all(32 <= b < 127 or b in (9, 10, 13) for b in data)
    return None      # định dạng khác: không kiểm được


class Case1:
    def __init__(self, img, log):
        self.img = img
        self.log = log

    # ------------------------------------------------------------ B0: trường còn tin được
    def doc_truong(self):
        img, log = self.img, self.log
        b = doc_boot_tho(img)
        self.boot = b
        self.bps = 1 << b["sector_shift"]
        log.buoc("Boot sector (giá trị đang ghi, 3 trường có thể sai): FatOffset",
                 offset=0x50, gia_tri=b["fat_sector"])
        log.buoc("Boot sector: ClusterHeapOffset", offset=0x58, gia_tri=b["heap_sector"])
        log.buoc("Boot sector: SectorsPerClusterShift", offset=0x6D, gia_tri=b["cluster_shift"])
        for ten, off, k in (("VolumeLength", 0x48, "volume_sectors"), ("FatLength", 0x54, "fat_length_sectors"),
                            ("ClusterCount", 0x5C, "cluster_count"),
                            ("FirstClusterOfRootDirectory", 0x60, "root_cluster"),
                            ("BytesPerSectorShift", 0x6C, "sector_shift"), ("NumberOfFats", 0x6E, "fat_count"),
                            ("VolumeFlags", 0x6A, "flags")):
            log.buoc(f"Boot sector (tin dùng): {ten}", offset=off, gia_tri=b[k])
        # Bản sao: chỉ ghi nhận, không dùng (đề cho biết cũng bị sai)
        sao = 12 * self.bps
        for ten, off in (("FatOffset", 0x50), ("ClusterHeapOffset", 0x58)):
            log.buoc(f"Backup Boot Sector: {ten}", offset=sao + off, gia_tri=img.u32(sao + off))
        log.buoc("Backup Boot Sector: SectorsPerClusterShift", offset=sao + 0x6D, gia_tri=img.u8(sao + 0x6D))
        ck_main = kiem_tra_boot_checksum(img, self.bps, backup=False)
        ck_sao = kiem_tra_boot_checksum(img, self.bps, backup=True)
        log.buoc("Boot Checksum (chính, dự phòng) khớp?", offset=11 * self.bps, gia_tri=[ck_main, ck_sao])
        log.quyet_dinh("Không dùng bản sao và checksum để chọn giá trị: đề cho biết cả hai vùng boot đều bị "
                       "sửa và checksum đã được tính lại. Suy ra ba trường từ FAT, thư mục gốc và cluster heap.")

    # ------------------------------------------------------------ B1: FatOffset
    def tim_fat(self):
        img, log, bps, b = self.img, self.log, self.bps, self.boot
        vol = min(b["volume_sectors"] * bps, img.kich_thuoc)
        o = img.tim(FAT_SIG, 24 * bps, vol, buoc=bps)
        while o >= 0:
            fat_sector = o // bps
            # FAT phải nằm gọn trước cuối volume và FAT[root] phải là EOC hoặc cluster hợp lệ
            r = img.u32(o + 4 * b["root_cluster"])
            if (fat_sector + b["fat_length_sectors"] * b["fat_count"]) * bps <= vol and \
                    (r == 0xFFFFFFFF or 2 <= r < b["cluster_count"] + 2):
                log.buoc("Tìm thấy chữ ký FAT (FAT[0]=0xFFFFFFF8, FAT[1]=0xFFFFFFFF)", offset=o,
                         gia_tri=img.doc(o, 8).hex(" "))
                log.buoc(f"FAT[root={b['root_cluster']}]", offset=o + 4 * b["root_cluster"], gia_tri=f"{r:#010x}")
                log.quyet_dinh(f"FatOffset = {o:#x} / {bps} = {fat_sector} sector", gia_tri=fat_sector,
                               gia_tri_cu=b["fat_sector"])
                self.fat_sector = fat_sector
                self.fat_byte = o
                return fat_sector
            log.buoc("Bỏ qua chữ ký FAT không hợp lệ", offset=o)
            o = img.tim(FAT_SIG, o + bps, vol, buoc=bps)
        raise ValueError("Không tìm thấy FAT")

    def chuoi_fat(self, first):
        """Đọc chuỗi FAT từ FAT vừa tìm (không cần biết cluster size)."""
        b, img = self.boot, self.img
        chain, seen, c = [], set(), first
        while True:
            if not 2 <= c < b["cluster_count"] + 2 or c in seen:
                raise ValueError(f"Chuỗi FAT lỗi tại cluster {c}")
            seen.add(c)
            chain.append(c)
            nxt = img.u32(self.fat_byte + 4 * c)
            self.log.buoc(f"FAT[{c}]", offset=self.fat_byte + 4 * c, gia_tri=f"{nxt:#010x}")
            if nxt == 0xFFFFFFFF:
                return chain
            c = nxt

    # ------------------------------------------------------------ B2: thư mục gốc
    def tim_thu_muc_goc(self):
        img, log, b = self.img, self.log, self.boot
        can_len = (b["cluster_count"] + 7) // 8
        start = self.fat_byte + b["fat_length_sectors"] * b["fat_count"] * self.bps
        vol = min(b["volume_sectors"] * self.bps, img.kich_thuoc)
        o = img.tim(ENTRY_BITMAP_HEAD, start, vol, buoc=32)
        while o >= 0:
            e = img.doc(o, 32)
            if e[1] in (0, 1) and e[2:20] == bytes(18) and \
                    int.from_bytes(e[24:32], "little") == can_len:
                bm_cluster = int.from_bytes(e[20:24], "little")
                # Tìm entry up-case (0x82) trong cùng sector với entry bitmap
                sec = o - o % self.bps
                up = None
                for p in range(sec, sec + self.bps, 32):
                    u = img.doc(p, 32)
                    if u[0] == ENTRY_UPCASE and u[8:20] == bytes(12):
                        up = (p, int.from_bytes(u[4:8], "little"), int.from_bytes(u[20:24], "little"),
                              int.from_bytes(u[24:32], "little"))
                        break
                if up and e[1] == ((b["flags"] & 1) if b["fat_count"] == 2 else 0):
                    log.buoc("Entry Allocation Bitmap (0x81) của thư mục gốc", offset=o,
                             gia_tri={"first_cluster": bm_cluster, "data_length": can_len})
                    log.buoc("Entry Up-case Table (0x82)", offset=up[0],
                             gia_tri={"table_checksum": f"{up[1]:#010x}", "first_cluster": up[2],
                                      "data_length": up[3]})
                    self.e_bitmap = o
                    self.bm_cluster, self.bm_len = bm_cluster, can_len
                    self.up_cluster, self.up_len, self.up_sum = up[2], up[3], up[1]
                    return o
            o = img.tim(ENTRY_BITMAP_HEAD, o + 32, vol, buoc=32)
        raise ValueError("Không tìm thấy entry Allocation Bitmap của thư mục gốc")

    # ------------------------------------------------------------ B3: SectorsPerClusterShift
    def suy_cluster_size(self):
        log, b = self.log, self.boot
        n_bm = len(self.chuoi_fat(self.bm_cluster))
        n_up = len(self.chuoi_fat(self.up_cluster))
        log.buoc("Độ dài chuỗi FAT (bitmap, up-case)", gia_tri=[n_bm, n_up])
        ung_vien = []
        for s in range(0, 26 - b["sector_shift"]):
            cs = self.bps << s
            ok_len = all((L + cs - 1) // cs == n for L, n in ((self.bm_len, n_bm), (self.up_len, n_up)))
            ok_vol = self.fat_byte + b["fat_length_sectors"] * b["fat_count"] * self.bps \
                + b["cluster_count"] * cs <= b["volume_sectors"] * self.bps
            if ok_len and ok_vol:
                ung_vien.append(s)
        log.quyet_dinh("Ứng viên SectorsPerClusterShift thoả ceil(DataLength/cs) = độ dài chuỗi FAT "
                       "và FAT + ClusterCount·cs ≤ VolumeLength", gia_tri=ung_vien)
        if not ung_vien:
            raise ValueError("Không có cluster size nào khớp độ dài chuỗi FAT")
        return ung_vien

    # ------------------------------------------------------------ B4: ClusterHeapOffset
    def suy_heap(self, shifts):
        img, log, b, bps = self.img, self.log, self.boot, self.bps
        root = b["root_cluster"]
        fat_end = self.fat_byte + b["fat_length_sectors"] * b["fat_count"] * bps
        vol = b["volume_sectors"] * bps
        kq = []
        for s in shifts:
            cs = bps << s
            hi = self.e_bitmap - (root - 2) * cs              # entry ở đầu cluster gốc
            lo = self.e_bitmap - (root - 1) * cs + 1           # entry ở cuối cluster gốc
            lo += (-lo) % bps
            for heap in range(hi - hi % bps, lo - 1, -bps):
                if heap < fat_end or heap + b["cluster_count"] * cs > vol:
                    continue
                up_off = heap + (self.up_cluster - 2) * cs
                if up_off + self.up_len > img.kich_thuoc:
                    continue
                if _upcase_checksum(img.doc(up_off, self.up_len)) != self.up_sum:
                    continue
                bm_off = heap + (self.bm_cluster - 2) * cs
                bm = img.doc(bm_off, self.bm_len)
                if not all(bm[(c - 2) // 8] >> ((c - 2) % 8) & 1 for c in (self.bm_cluster, self.up_cluster, root)):
                    continue
                log.buoc(f"Ứng viên heap: cs={cs}, TableChecksum up-case khớp tại", offset=up_off,
                         gia_tri=f"{self.up_sum:#010x}")
                log.buoc("Bit bitmap của cluster bitmap/up-case/gốc = 1, bitmap tại", offset=bm_off)
                kq.append((s, heap // bps))
        log.quyet_dinh("Ứng viên (SectorsPerClusterShift, ClusterHeapOffset) qua kiểm tra nội dung", gia_tri=kq)
        return kq

    # ------------------------------------------------------------ B5: kiểm chứng + trích xuất
    def thu(self, s, heap):
        hc = {"fat_sector": self.fat_sector, "heap_sector": heap, "cluster_shift": s}
        fs = ExFAT(self.img, None, hieu_chinh=hc)
        files = fs.liet_ke_file()
        diem = 0
        datas = []
        for f in files:
            d = fs.doc_file(f)
            ok = _chu_ky_hop_le(f["path"], d)
            diem += 1 if ok else (0 if ok is None else -5)
            datas.append((f, d, ok))
        return diem, hc, datas

    def chay(self, out):
        log = self.log
        self.doc_truong()
        self.tim_fat()
        self.tim_thu_muc_goc()
        shifts = self.suy_cluster_size()
        cands = self.suy_heap(shifts)
        if not cands:
            raise ValueError("Không có ứng viên ClusterHeapOffset nào qua kiểm tra")
        best = None
        for s, heap in cands:
            try:
                diem, hc, datas = self.thu(s, heap)
            except ValueError as ex:
                log.buoc(f"Ứng viên shift={s}, heap={heap} bị loại khi duyệt cây: {ex}")
                continue
            log.buoc(f"Ứng viên shift={s}, heap={heap}: điểm chữ ký tập tin", gia_tri=diem)
            if best is None or diem > best[0]:
                best = (diem, hc, datas)
        if best is None:
            raise ValueError("Không ứng viên nào đọc được cây thư mục")
        diem, hc, datas = best
        b = self.boot
        log.quyet_dinh("Giá trị đúng", FatOffset=hc["fat_sector"], ClusterHeapOffset=hc["heap_sector"],
                       SectorsPerClusterShift=hc["cluster_shift"], cluster_size=self.bps << hc["cluster_shift"],
                       gia_tri_sai=[b["fat_sector"], b["heap_sector"], b["cluster_shift"]])
        # Duyệt lại có nhật ký với tham số đã chọn
        fs = ExFAT(self.img, log, hieu_chinh=hc)
        for f, d, ok in datas:
            runs = fs.file_runs(f)
            log.buoc(f"Trích xuất {f['path']}", offset=f["stream_offset"],
                     gia_tri={"size": f["kich_thuoc"], "runs": runs, "chu_ky_hop_le": ok})
            if ok is False:
                log.canh_bao(f"{f['path']}: chữ ký định dạng không khớp phần mở rộng")
            out.luu(f["path"], d)
        return hc
