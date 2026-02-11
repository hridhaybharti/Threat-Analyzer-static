import json

from backend.analyzers.url import analyze_url


def main():
    res = analyze_url("https://example.com")
    print(json.dumps(res, indent=2))


if __name__ == "__main__":
    main()
