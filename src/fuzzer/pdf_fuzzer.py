import random

from fuzzer_core import Fuzzer
import io, pikepdf
from pikepdf import Pdf
import random
import string

MAX_VAL = 0xFFFF_FFFF
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
        self.mutators = []
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
