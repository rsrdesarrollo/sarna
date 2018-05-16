import magic


def is_valid_evidence(file):
    mime = magic.from_buffer(file.read(1024), mime=True)
    file.seek(0)
    return mime.startswith('image/')
