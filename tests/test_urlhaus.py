from intelligence.urlhaus import URLHaus

def main():

    urlhaus = URLHaus()

    url = input("Enter URL: ").strip()

    result = urlhaus.check(url)

    print("\nResult:")
    print(result)


if __name__ == "__main__":
    main()
