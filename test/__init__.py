from os import path

TEST_PATH = path.abspath(
    path.join(
        __file__.rpartition('/test')[0],
        'test'
    )
)
