"""A clean, benign Python module used as a deterministic test fixture."""


def add(a, b):
    return a + b


if __name__ == "__main__":
    print(add(2, 3))
