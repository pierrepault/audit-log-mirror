# netsign.io audit log mirror

This repository is a public, append-only copy of every signed checkpoint of
[netsign.io](https://netsign.io)'s audit log, with the RFC 3161 time-stamp
tokens over each one. A scheduled GitHub Actions job (`.github/workflows/mirror.yml`)
fetches new checkpoints every 15 minutes and commits them **only after checking
them** with code in this repository, which shares nothing with the server:

1. the checkpoint is signed by the pinned key, `key.pem`;
2. it extends the last mirrored checkpoint: an RFC 9162 consistency proof between
   their roots is verified here;
3. a checkpoint already mirrored is never served differently;
4. every time-stamp token verifies with `openssl ts -verify` against the pinned
   TSA roots, `tsa-roots.pem`.

A failed run is the alarm: the log contradicts what was mirrored before. The
commit history is the record of what netsign.io published and when.

## Layout

| Path | What it is |
| --- | --- |
| `series-<n>/<size>.txt` | a signed checkpoint covering the first `<size>` audit entries of series `n` (C2SP signed note) |
| `series-<n>/<size>.<tsa host>.tsr` | an RFC 3161 TimeStampResp over that file, from that TSA |
| `series-<n>/LATEST` | the newest mirrored size of the series |
| `series-<n>/CLOSED.txt`, `CLOSED.<tsa host>.tsr` | how a series ended, signed and timestamped (only after an incident) |
| `series-<n>/GENESIS.json` | the first entry of series `n` >= 2: the exact bytes whose SHA-256 is its leaf 0, naming the previous series' `CLOSED.txt` |
| `ACTIVE` | the series this mirror follows (absent: 1) |
| `key.pem` | the checkpoint verification key (ECDSA P-256), also served at `https://netsign.io/audit-log/key` |
| `tsa-roots.pem` | the root certificates the TSA tokens must chain to |

Series 1 is `netsign.io/audit-log`; a later series `n` is `netsign.io/audit-log/<n>`.
There is only ever more than one if netsign.io lost audit entries it had already
published. Then it closes the series with a signed statement (the last checkpoint it
can still reproduce, the last one it published, an incident id) and the next series
starts with an entry committing to that statement. The witness verifies all of it and
then **stops**: the workflow fails until someone who has read the incident runs it by
hand with `accept_series` set. A series change is never followed silently.

## Checking a checkpoint by hand

```sh
# The time-stamp: this exact file existed no later than the token's time.
openssl ts -verify -data series-1/1234.txt -in series-1/1234.freetsa.org.tsr -CAfile tsa-roots.pem
openssl ts -reply -in series-1/1234.freetsa.org.tsr -text | grep 'Time stamp'

# The signature: the body (the first three lines and the newline after them)
# signed with key.pem. The signature line is base64(4-byte key ID || DER signature).
head -n 3 series-1/1234.txt > body
tail -n 1 series-1/1234.txt | cut -d' ' -f3 | base64 -d | tail -c +5 > sig.der
openssl dgst -sha256 -verify key.pem -signature sig.der body
```

After a series change, the same two checks apply to `series-1/CLOSED.txt` (its body is
the first seven lines: `head -n 7`), and the new series names it:

```sh
sha256sum series-1/CLOSED.txt          # equals "closingSha256" in series-2/GENESIS.json
```

`go test ./...` runs the witness against recorded server responses, including
the ways a dishonest server could answer and a series handover (`witness_test.go`).

## Setting it up

1. Create a **public** GitHub repository (e.g. `netsign-audit-log`) and push the
   contents of this directory to its default branch.
2. `key.pem`: save the `publicKeyPem` of `https://netsign.io/audit-log/key`.
   Check that its `kmsKeyArn` is the audit-log key in your AWS account.
3. `tsa-roots.pem`: the roots of every TSA in the server's `-audit-tsa-urls`
   (the same file as `-audit-tsa-roots`).
4. In the repository settings, allow GitHub Actions to write (Settings →
   Actions → General → Workflow permissions → Read and write), and protect the
   default branch against force pushes and deletion.
5. Run the workflow once by hand (Actions → mirror → Run workflow). The first
   run trusts the server's first checkpoint; every later one is checked
   against what is already here.
6. If a run ever fails with "series change requested": read netsign.io's incident
   note, then run the workflow by hand with `accept_series` set to the number
   it names.

Anyone can run the same check on their own machine, which makes them a second,
independent witness: `go run . -dir .` in a clone of this repository.
