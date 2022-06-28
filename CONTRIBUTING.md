# How to contribute to DaggerBoard

:sparkler: :boat: We would like to thank you for taking the time to contribute and joining us on the SBOM journey! :boat: :sparkler:

Please review the following guidelines before contributing:


## Contents
- [Code of Conduct](#code-of-conduct)
- [What to know before I contribute](#what-to-know-before-i-contribute)
- [How Can I Contribute?](#how-can-i-contribute)
	- Type of Contribution
		- [Security Vulnerability](#security-vulnerability)
		- [Other Bugs](#other-bugs-non-security-vulnerability-related-bugs)
		- [Documentation](#documentation)
	- [Suggestions/Enhancements](#suggestions-and-enhancements)
	- [Pull Requests ("PRs")](#pull-requests)
- [Formatting/Style Guides](#formattingstyle-guides)

## Code of Conduct

This project and everyone participating in it is governed by the [DaggerBoard Code of Conduct](CODE_OF_CONDUCT.md). By contributing and taking part in this project, you are expected to follow our Code of Conduct.

If you witness any unacceptable behavior displayed by anyone participating (including the maintainers), please contact [SecDevOps@nyp.org](mailto:SecDevOps@nyp.org?subject=[DaggerBoard]) with the subject heading starting with "[DaggerBoard]".

## How can I Contribute?

#### Security Vulnerability

If the bug you have identified is a security vulnerability, do NOT submit a pull request. Please contact us at [SecDevOps@nyp.org](mailto:SecDevOps@nyp.org?subject=[DaggerBoard]%20[Vulnerability]), subject line "[DaggerBoard] [Vulnerability]".

Within the body of your email please provide details about the vulnerability you have discovered and steps on on this bug can be reproduced.

#### Other Bugs (Non-Security Vulnerability Related Bugs)

All other bugs are tracked as [GitHub Issues](https://docs.github.com/en/issues/tracking-your-work-with-issues/about-issues).

1. Create an issue and provide information on the bug by filling out this [template](contributing/bug_template.md)

#### Documentation

We love good documentation! However, sometimes we may not be good at providing that. If you identify that we are lacking or behind on some documentation, open an issue and submit your pull request with those awesome changes.

### Suggestions and Enhancements

For these requests please provide the following in your [GitHub Issue](https://docs.github.com/en/issues/tracking-your-work-with-issues/about-issues):
- Suggestion/Enhancement
- Use case for the feature
- Explain why this would be useful
- Written example of how it should/could work

### Pull Requests

To keep the process structured for our maintainers and contributors, please follow these steps when submitting a pull request:
1. Make sure you are clear in your descriptions
2. Follow our formatting/style guides
3. Provide tests if these are fixes/features/enhancements (as of now this is optional)

## Formatting/Style Guides

Please install the following in your contributions virtual env:
- [black](https://pypi.org/project/black/)
- [isort](https://pypi.org/project/isort/)

We use currently use black and isort to organize and format our code.
As of now we do not use any custom rules for black or isort, using their defaults is acceptable to us.

Before you submit your pull request please run black and isort on all of your python files to ensure that your code is formatted and legible to read.


