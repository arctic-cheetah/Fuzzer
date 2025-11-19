import subprocess


def detect_input_file_type(input_file_path: str) -> str:
    """
    Args:
        input_file_path: represents the path to the input file
    Returns:
        The file type in string format as seen in the ass specs

    See also https://developer.mozilla.org/en-US/docs/Web/HTTP/Guides/MIME_types/Common_types
    """

    args = ["file", "-b", "--mime-type", input_file_path]
    ps = subprocess.run(args, capture_output=True)
    file_type = ps.stdout.decode().strip().split('/')[-1]

    if file_type == 'csv':
        return 'csv'
    elif file_type == 'json':
        return 'json'
    elif file_type == 'jpeg':
        return 'jpg'
    elif file_type == 'pdf':
        return 'pdf'
    elif 'xml' in file_type or 'html' in file_type:
        return 'xml'
    elif 'executable' in file_type:
        return 'elf'
    else:
        return 'plaintext'

