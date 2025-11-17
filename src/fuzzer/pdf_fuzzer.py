import random

from fuzzer_core import Fuzzer
import io, pikepdf
from pikepdf import Pdf
import random
import string
from fontTools.ttLib import TTFont

MAX_VAL = 0xFFFF_FFFF_FFFF_FF
VALID_PDF_VERSIONS = [
    "1.0",
    "1.1",
    "1.2",
    "1.3",
    "1.4",
    "1.5",
    "1.6",
    "1.7",
    "2.0",
]


def random_latin1_string(length):
    """
    Generates a random string of a specified length using Latin-1 printable characters.
    """
    # Latin-1 printable characters range from 32 (space) to 255 (ÿ)
    # Exclude characters that might cause issues with some systems or displays,
    # or include them based on specific requirements.
    # Here, we include characters from 32 to 255, excluding control characters.
    latin1_chars = [
        chr(i)
        for i in range(32, 256)
        if chr(i) not in string.whitespace and chr(i) not in string.printable[:32]
    ]  # Exclude common control characters and whitespace

    # If you need a more restricted set, you could define it explicitly:
    # latin1_chars = string.ascii_letters + string.digits + string.punctuation + "ÄÖÜäöüß" # Example for common Latin-1 extensions

    return "".join(random.choice(latin1_chars) for _ in range(length))


class PDF_Fuzzer(Fuzzer):
    def __init__(self, path_to_input: str, binary_path: str):
        super().__init__(path_to_input, binary_path)
        self.mutators = [
            self.m_doc_title,
            self.m_doc_subject,
            self.m_doc_version,
            self.m_shuffle_pages,
            self.m_rotate_page,
            self.m_add_one_page,
            self.m_remove_one_page,
            self.m_append_multiple_pages,
            self.m_alter_stream_length,
            # font/TTF-specific mutators:
            self.m_corrupt_font_descriptor_length,
            self.m_bitflip_font_stream,
            self.m_truncate_or_expand_font_stream,
            self.m_tamper_maxp_table,
        ]
        # Open pdf file
        # with open(path_to_input) as f:

    # TODO: Parse the pdf input!

    def make_payload(self, seed: bytes):
        """Produce a mutated pdf as bytes"""
        # TODO: check just in case file is not pdf
        try:
            pdf: Pdf = pikepdf.open(io.BytesIO(seed))
        except Exception:
            return self.mutate(seed)

        #  Begin mutation here!
        for _ in range(1, random.randint(1, 6)):
            mut = random.choice(self.mutators)
            try:
                mut(pdf)
            except Exception:
                pass

        # Convert back to bytes
        saved_pdf = io.BytesIO()
        pdf.save(saved_pdf)

        try:
            pdf.close()
        except Exception:
            pass

        return saved_pdf.getvalue()

    # edit fields metadata of the pdf fuzzer

    # Override run_binary!
    # -----------------------------------
    # Mutator strategies below:
    # m_xxx represents mutate x
    # Mutates on parser

    # Starter mutation
    # Note PDF may not have the fields we want!
    def m_doc_title(self, pdf: Pdf) -> None:
        # Mutate ttile
        try:
            pdf.docinfo["/Title"] = random_latin1_string(random.randint(0, MAX_VAL))
        except Exception:
            pass

    def m_doc_subject(self, pdf: Pdf) -> None:
        # Mutate subject
        try:
            pdf.docinfo["/Subject"] = random_latin1_string(random.randint(0, MAX_VAL))
        except Exception:
            pass

    def m_doc_version(self, pdf: Pdf) -> None:
        # Mutate pdf version
        try:
            pdf.pdf_version = random.choice(VALID_PDF_VERSIONS)
        except Exception:
            pass

    def m_shuffle_pages(self, pdf: Pdf) -> None:
        # Try shuffling the pages!
        try:
            pages = list(pdf.pages)
            random.shuffle(pages)
            # Replace page order
            pdf.pages.clear()
            for p in pages:
                pdf.pages.append(p)
        except Exception:
            pass

    def m_rotate_page(self, pdf: Pdf) -> None:
        # Try rotating the pages!
        try:
            # cant assume there will be pages
            if len(pdf.pages) == 0:
                return
            page = random.choice(list(pdf.pages))
            page.rotate(random.choice([0, 90, 180, 270]))
        except Exception:
            pass

    def m_add_one_page(self, pdf: Pdf) -> None:
        # Add an extra page:
        try:
            if len(pdf.pages) == 0:
                return
            src = random.choice(list(pdf.pages))
            tmp = Pdf.new()
            # WARNING you need to create a new pdf to actually copy a page!
            tmp.pages.append(src)
            clone = tmp.pages[0]
            pdf.pages.append(clone)
        except Exception:
            pass

    def m_remove_one_page(self, pdf: Pdf) -> None:
        # Delete one page:

        try:
            n = len(pdf.pages)
            if len(pdf.pages) == 0:
                return
            num = random.randint(0, n)
            del pdf.pages[num]
        except Exception:
            pass

    def m_append_multiple_pages(self, pdf: Pdf) -> None:
        # Append n random pages to the pdf
        try:
            num_pages = len(pdf.pages)
            if num_pages == 0:
                return
            num_dup = random.randint(0, MAX_VAL)
            for _ in range(0, num_dup):
                self.m_add_one_page(pdf)

        except Exception:
            pass

    def m_alter_stream_length(self, pdf: Pdf) -> None:
        # Adobe Reader RCE (CVE-2023-26369): heap OOB write in sfac_GetSbitBitmap parsing
        # malformed TrueType sbit glyphs in libCoolType
        try:
            # Find random stream object
            candidate_streams = [
                o for o in pdf.objects if isinstance(o, pikepdf.Stream)
            ]
            if not candidate_streams:
                return
            s = random.choice(candidate_streams)
            # Set incorrect /Length (too big or too small)
            bad_len = random.choice([0, random.randint(1, 1_000_000)])
            s.obj["/Length"] = bad_len
        except Exception:
            pass

    def _find_embedded_font_streams(self, pdf: Pdf):
        """Yield pikepdf.Stream objects that look like embedded TTF/OTF/ttcf by header signature."""
        for obj in pdf.objects:
            try:
                if isinstance(obj, pikepdf.Stream):
                    data = obj.read_bytes()
                    if not data:
                        continue
                    header = data[:4]
                    if header in (b"\x00\x01\x00\x00", b"OTTO", b"ttcf"):
                        yield obj
            except Exception:
                continue

    def m_corrupt_font_descriptor_length(self, pdf: Pdf) -> None:
        """Find FontDescriptor objects and set FontFile2/3 length entries to wrong values."""
        try:
            for page in pdf.pages:
                try:
                    fonts = page.resources.get("/Font", {})
                except Exception:
                    continue
                for font_ref in fonts.values():
                    try:
                        # dereference font dictionary
                        fd = font_ref.get("/FontDescriptor")
                        if not fd:
                            continue
                        for key in ("/FontFile2", "/FontFile3"):
                            ref = fd.get(key)
                            if ref and isinstance(ref, pikepdf.Object):
                                # set a bogus /Length to cause downstream parser inconsistencies
                                try:
                                    ref.obj["/Length"] = random.choice(
                                        [0, 1, 2**31 - 1, random.randint(1, 1_000_000)]
                                    )
                                except Exception:
                                    pass
                    except Exception:
                        continue
        except Exception:
            pass

    def m_bitflip_font_stream(self, pdf: Pdf) -> None:
        """Locate an embedded font stream and flip a few random bytes."""
        try:
            streams = list(self._find_embedded_font_streams(pdf))
            if not streams:
                return
            s = random.choice(streams)
            data = bytearray(s.read_bytes() or b"")
            if not data:
                return
            flips = max(1, min(32, len(data) // 1000))
            for _ in range(random.randint(1, flips)):
                idx = random.randrange(len(data))
                data[idx] ^= random.getrandbits(8)
            # best-effort write back; set /Length as fallback if direct write fails
            try:
                # pikepdf.Stream may expose a write method in some versions; try common approaches
                try:
                    s.write(bytes(data))
                except Exception:
                    try:
                        s._data = bytes(data)  # fallback (may be private/undocumented)
                    except Exception:
                        s.obj["/Length"] = len(data)
            except Exception:
                s.obj["/Length"] = len(data)
        except Exception:
            pass

    def m_truncate_or_expand_font_stream(self, pdf: Pdf) -> None:
        """Randomly truncate or append to an embedded font stream to trigger length/size parsing bugs."""
        try:
            streams = list(self._find_embedded_font_streams(pdf))
            if not streams:
                return
            s = random.choice(streams)
            data = s.read_bytes() or b""
            if not data:
                return
            if random.choice([True, False]):
                # truncate
                new_len = random.randint(0, max(0, len(data) - 1))
                newdata = data[:new_len]
            else:
                # expand by appending random bytes (could also repeat chunks)
                extra = bytes(
                    random.getrandbits(8)
                    for _ in range(random.randint(1, min(4096, len(data) // 10 + 1)))
                )
                newdata = data + extra
            try:
                s.write(newdata)
            except Exception:
                try:
                    s._data = newdata
                except Exception:
                    s.obj["/Length"] = len(newdata)
        except Exception:
            pass

    def m_tamper_maxp_table(self, pdf: Pdf) -> None:
        """
        If fontTools present, attempt light-weight changes to the 'maxp' table:
        - change numGlyphs or maxComponentContours to stress glyph-parsing code paths.
        This is optional and fails back to no-op if fontTools or writing fails.
        """
        if TTFont is None:
            return
        try:
            streams = list(self._find_embedded_font_streams(pdf))
            if not streams:
                return
            s = random.choice(streams)
            data = s.read_bytes()
            if not data:
                return
            bio = io.BytesIO(data)
            try:
                tt = TTFont(
                    bio, recalcBBoxes=False, recalcTimestamp=False, verbose=False
                )
            except Exception:
                return
            try:
                if "maxp" in tt:
                    # change values to stress parsers; keep within uint16/uint32-ish bounds
                    try:
                        tt["maxp"].numGlyphs = random.randint(
                            0, min(0xFFFF, max(1, tt["maxp"].numGlyphs * 2))
                        )
                    except Exception:
                        pass
                    # some fontTools builds expose extra fields; safely attempt to set a big value
                    try:
                        if hasattr(tt["maxp"], "maxComponentContours"):
                            tt["maxp"].maxComponentContours = random.randint(0, 0xFFFF)
                    except Exception:
                        pass
                # write back mutated font
                out = io.BytesIO()
                try:
                    tt.save(out)
                    newfont = out.getvalue()
                    try:
                        s.write(newfont)
                    except Exception:
                        try:
                            s._data = newfont
                        except Exception:
                            s.obj["/Length"] = len(newfont)
                except Exception:
                    pass
            finally:
                try:
                    tt.close()
                except Exception:
                    pass
        except Exception:
            pass

    def m_inject_junk_attribute(self, pdf: Pdf) -> None:
        # Fuzz some metadata so that it crashes!
        #
        junk = pikepdf.Dictionary(
            {
                "/Type": "/XObject",
                "/Subtype": "/Image",
                "/Width": MAX_VAL,
                "/Height": MAX_VAL,
                "/ColorSpace": "/DeviceRGB",
                "/BitsPerComponent": random.choice([1, 2, 4, 8, 16]),
                "/Filter": random.choice(
                    ["/FlateDecode", "/ASCII85Decode", "/DCTDecode"]
                ),
            }
        )
        pdf.make_indirect(junk)
