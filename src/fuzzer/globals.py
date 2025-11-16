from pathlib import Path

PATH_TO_HARNESS = PROGRAM_PATH = (
    (Path(__file__).parent / "../harness/harness").resolve().__str__()
)


def mount_point(file: str) -> str:
    return (Path(__file__).parent.parent.parent / file).resolve().__str__()
