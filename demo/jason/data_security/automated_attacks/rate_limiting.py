import httpx
import asyncio

URL = "https://miraisocial.live"
HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
}
async def main() -> None:
    while True:
        num = input("Number of requests to send: ")
        if not num.isdigit():
            print("Please enter a number.\n")
            continue
        break

    num = int(num)
    print(f"Sending {num} requests to {URL}...")
    responses: list[httpx.Response] = []
    async with httpx.AsyncClient(http2=True, headers=HEADERS) as client:
        for _ in range(num):
            response = await client.get(URL)
            responses.append(response)
    print(f"All {num} requests sent.\n")

    print("Response Results:")
    response_strs = {}
    for response in responses:
        key = f"{response.status_code} ({response.reason_phrase})"
        response_strs[key] = response_strs.get(key, 0) + 1

    for response_str in response_strs:
        print(f"{response_str}: {response_strs[response_str]}")

if __name__ == "__main__": 
    try:
        asyncio.run(main())
    except (KeyboardInterrupt, EOFError):
        pass