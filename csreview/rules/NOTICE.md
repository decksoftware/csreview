# CSReview offline OpenGrep rulepack

The rules in `csreview.yml` are maintained by the CSReview project and are
distributed under the MIT License in `LICENSES/MIT.txt`.

CSReview can download and execute OpenGrep 1.26.0 when the user explicitly
passes `--provision-tools`. The OpenGrep executable is not included in this
package. It is fetched from the official OpenGrep GitHub release, verified
against a platform-specific SHA-256 allowlist, and stored in CSReview's private
user cache. OpenGrep is a separate project; see
https://github.com/opengrep/opengrep for its source and license.
