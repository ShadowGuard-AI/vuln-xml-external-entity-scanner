# vuln-XML-External-Entity-Scanner
Scans for XML External Entity (XXE) vulnerabilities by injecting a crafted XML payload into an operator named target URL and checking the response for the content the payload is expected to return. Every response is analyzed, including 4xx and 5xx responses, because reflected entity content normally surfaces in error status bodies; the HTTP status is reported alongside the result.

## Install
`git clone https://github.com/ShadowGuardAI/vuln-xml-external-entity-scanner`

## Usage
`./vuln-xml-external-entity-scanner [params]`

## Parameters
- `-h`: Show help message and exit
- `-p`: The XXE payload to inject. Default reads /etc/passwd on the target.
- `--indicator`: String expected in the response when the payload succeeds. The default payload checks for /etc/passwd style content (the root entry marker). A custom payload needs `--indicator` naming the content it is expected to return; without one, detection is inconclusive and the run exits non-zero.
- `-v`: Enable verbose output (debug logging)
- `-o`: Output file to save the scan record to. The record holds the target, method, status, response size, the indicator result, and a redacted excerpt with indicator lines masked. Extracted file content is not written in clear.
- `--save-full-body`: With `-o`, also write the full response body. This can persist file content extracted from a vulnerable target in clear; use only where that is intended.
- `-m`: HTTP method to use (GET or POST). Default is POST.
- `-d`: Data parameter for the payload, where the payload will be injected. Default is 'xml=&lt;data&gt;'

Exit codes: 0 when the scan ran and the response was analyzed. An invalid URL, a failed request (no response received), or a custom payload with no indicator all exit non-zero.

## License
Copyright (c) ShadowGuardAI
