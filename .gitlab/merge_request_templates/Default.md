# Description

MR DESCRIPTION HERE

# Type of MR
- [ ] Refactoring: any MR that changes Go or Python code but does not change observable functionality.
- [ ] Bug fix on stable branch: addresses an RTC defect and is applied to a stable branch such as the BMP 0.20.X branch.
- [ ] Bug fix on develop.
- [ ] Bug fix for AppArmor related issues.
- [ ] New feature (everything else).
- [ ] Non-code changes: only changes are documentation/READMEs.
- [ ] Build infrastructure change (same as non-code change).
- [ ] Security fix on develop.

# Checklist
_(NOTE: do not remove sections below. Mark items as N/A in sections that don't apply.)_

### Only if .py files are changed:
- [ ] Run auto-pep8 for each Python file that you edit. (Install autopep8 with pip and then run ./autopep8.sh from the repository.) (Not required for bug fix on stable branch MRs.)
- [ ] New and modified methods/functions should have type annotations on method/function signatures.
- [ ] Test dev-mode.sh still works for any large Python code structural changes on any changed agents.
- [ ] Make sure every method, class or function modified or added in MR has docstrings associated with it except for methods or functions that start with a single underscore.

### Only if .go files are changed:
- [ ] Run 'go fmt' tool either through IDE or CLI. -> From trtl root directory run 'go fmt .'
- [ ] All public methods have comment according to Go coding standards. Starts with method name and then a description.
- [ ] Check if README for an agent should be changed with your MR. If so, change it.
- [ ] Check for unit test coverage. If coverage < 80%, it must go up in your MR (to nearest %). If coverage >= 80% and < 90%, it must go up or stay the same. Put previous and current coverage % in comments.

### Security

Here are the most important ones to follow (reference the PDF link for more details).
See https://wiki.ith.intel.com/pages/viewpage.action?spaceKey=SecTools&title=Compiler+and+Coding+Guidelines&preview=/1720198546/1803211395/Secure%20Coding%20Checklist%20Policies.pdf (If this link becomes broken, you can find it in sdl-e.app.intel.com under the CT22 task.)  Here are the most important ones to follow (reference the PDF link for more details).

- [ ] Validate input - Any user input being utilized?
- [ ] Defend against Canonical Representation Issues - Any paths utilized?
- [ ] Check function return values
- [ ] General secure coding guidelines
- [ ] Follow 'secure by default'
- [ ] Fail safe
- [ ] Use least privilege - Any escalation of privilege to root?
- [ ] Clean up temporary files - Any temporary files being used?

### Always except where noted:

PLEASE NOTE: HSD must always be included if available.

- [ ] PR description and commit messages explain what you are solving. [Tips](https://chris.beams.io/posts/git-commit/): 50 character limit for title; imperative title; meaningful description.
- [ ] Does commit change default config files under /etc? If so, will Turtle Creek still work after an upgrade that leaves /etc alone, like a Mender upgrade.
- [ ] If commit closes a customer-visible issue, mark the RTC number or HSD number in the MR and at least one of the final commits. Add to Changelog.md for [inbm](inbm/Changelog.md) and/or [inbm-vision](inbm-vision/Changelog.md).
- [ ] If fixing a bug, include an automated test (unit, integration, etc) that fails when bug is present and passes when it is absent.
- [ ] If changing cloud UI, update thing definitions or equivalent for all clouds (e.g.: Telit, Thingsboard, Azure).
- [ ] One commit per MR. Squash or split into separate MRs if necessary. Exception: if you can, split out pure refactor commits to make code review easier. Can be in same MR.
- [ ] Make sure each **commit** has correct message/description; this is not the same thing as the MR message/description.
- [ ] Pass Integration Reloaded - QUICKER and QUICK for Turtle Creek; SLOW for Bit Creek.