import random

from fuzzer_core import Fuzzer
import io, pikepdf
from pikepdf import Pdf


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

    def m_ascii(self):
        pass

    def m_doc_title(self, pdf: Pdf) -> None:
        pass

    def m_doc_subject(self, pdf: Pdf) -> None:
        pass

    def m_doc_version(self, pdf: Pdf) -> None:
        pass
