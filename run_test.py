from backend.analyzers.url import analyze_url


def main():
    print("YouTube:")
    print(analyze_url("https://www.youtube.com/"))

    print("\nBuilder.io:")
    print(analyze_url("https://builder.io/app/projects/test"))


if __name__ == "__main__":
    main()
