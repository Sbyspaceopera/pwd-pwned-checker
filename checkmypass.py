import requests
import hashlib
import sys

# this api take 5 first SHA1 characters of the password as arg
def request_api_data(query_char):
    """
    Do a request to the pwnedpasswords.com's API and get a list of hashes in response.
    @query_char : First 5 characters of the SHA1
    """
    url = "https://api.pwnedpasswords.com/range/" + query_char
    res = requests.get(url)
    if res.status_code != 200:
        raise RuntimeError(
            f"Errror fetching: {res.status_code}, check the api and try again"
        )
    return res


def get_password_leaks_count(hashes, hash_to_check):
    """
    Found the correct password in the hashes list.
    @hashes : hashes list
    @hash_to_check : SHA1 hashed password
    """
    hashes = (line.split(":") for line in hashes.text.splitlines())
    for h, count in hashes:
        if h == hash_to_check:
            return count
    return 0


def pwned_api_check(password):
    """
    Convert @password in SHA1
    Returns the correct hashed password
    """
    sha1password = hashlib.sha1(password.encode("utf-8")).hexdigest().upper()
    # split the password and the five first chars
    # we don't want to the send the password through the web, so we will find it locally
    first5_char, tail = sha1password[:5], sha1password[5:]
    response = request_api_data(first5_char)
    return get_password_leaks_count(response, tail)


def main(args):
    """
    Returns the number of time the passwords given are found in hacked databases.
    @args : List of passwords
    """
    for password in args:
        count = pwned_api_check(password)
        if count:
            print(
                f"{password} was found {count} times... You should probably change your password"
            )
        else:
            print(f"{password} was not found. Carry on!")
    return "done!"


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
