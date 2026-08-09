from m2_python_contract import transform
from m2_python_noise import marker


def main() -> None:
    if transform("alpha") != "ALPHA":
        raise AssertionError("M2_PYTHON_BREAKING_API_V2")
    if marker() != "stable":
        raise AssertionError("unexpected noise package behavior")
    print("python dependency contract: PASS")


if __name__ == "__main__":
    main()
