# Intended solution

The welcome page reveals the public collection path `/app/pages` and hints at a file one level above. `/read` appends the `book` query parameter to that directory without resolving and checking containment.

Request `/read?book=../flag.txt` to read `/app/flag.txt`. The solver URL-encodes this query, reads the actual HTTP response, and extracts the flag. There is no persistent state and no cross-team mutation. A second intended-equivalent path is an absolute file path; no source secrets are needed to discover the vulnerability.
