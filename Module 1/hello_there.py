import requests

def main():
    print("Hello There")
    url = "https://www.eicar.org/download-anti-malware-testfile/"
    try:
        response = requests.get(url)
        response.raise_for_status()
        with open("testfile", "wb") as file:
            file.write(response.content)
        print("File downloaded successfully.")
    except requests.exceptions.RequestException as e:
        print(f"Failed to download the file: {e}")

if __name__ == "__main__":
    main()