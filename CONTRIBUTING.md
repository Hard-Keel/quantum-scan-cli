# Contributing

Thank you for helping. The most useful contributions are **new detection rules**, **false-positive reports** and **fixes to either**.

## Add a detection rule

1. Read [rules/README.md](rules/README.md).
2. Add `rules/community/<id>.json`.
3. Run `node scripts/build-rules.mjs` and `npm test`.
4. Open a pull request. The template asks for a link to the API's documentation and a real-world line the rule finds.

## Report a false positive

Open an issue with the "False positive" template. Include the line (with any real secret removed), the file type, and why it is not a problem. A false positive usually becomes a `noMatch` example and a tighter pattern.

## Sign your commits off

Contributions are accepted under the Apache 2.0 license. Add a sign-off line to each commit (`git commit -s`) to confirm you wrote it, or have the right to submit it, under the [Developer Certificate of Origin](https://developercertificate.org/).

## Security problems

Never open a public issue for a security problem in the scanner. Email security@hardkeel.com instead.

## What gets merged

A maintainer checks that the rule finds what it says, that it doesn't fire on ordinary code (we run it over a set of popular open-source projects), and that the pattern is quick. Changes to the readiness score's weights or grades are not taken as pull requests: the method is versioned and changes through a published new version.
