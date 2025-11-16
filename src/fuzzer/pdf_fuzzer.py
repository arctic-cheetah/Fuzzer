import random

from fuzzer_core import Fuzzer
import io, pikepdf
from pikepdf import Pdf
import random
import string


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
    def rand_string(self, n: int = 16):
        pass

    def m_ascii(self):
        pass

    def m_doc_title(self, pdf: Pdf) -> None:
        try:
            pdf.docinfo["/Title"] = random_latin1_string(random.randint(0, 0xFFFF_FFFF))
        except Exception:
            pass

    def m_doc_subject(self, pdf: Pdf) -> None:
        pass

    def m_doc_version(self, pdf: Pdf) -> None:
        pass
