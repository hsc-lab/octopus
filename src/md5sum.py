import hashlib


def md5sum(file, chunksize=65536):
    with open(file, "rb") as f:
        md5 = hashlib.md5()
        buffer = f.read(chunksize)
        while len(buffer):
            md5.update(buffer)
            buffer = f.read(chunksize)
    return md5.hexdigest()
