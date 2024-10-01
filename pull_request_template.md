<!---
  SPDX-FileCopyrightText: Copyright (C) 2017-2024 Intel Corporation
  SPDX-License-Identifier: Apache-2.0

  ------------------------------------------------------

  Author Mandatory (to be filled by PR Author/Submitter)
  ------------------------------------------------------

  - Developer who submits the Pull Request for merge is required to mark the checklist below as applicable for the PR changes submitted.
  - Those checklist items which are not marked are considered as not applicable for the PR change.
-->

### PULL DESCRIPTION

_Provide a 1-2 line brief overview of the changes submitted through the Pull Request..._


### Impact Analysis

| Info | Please fill out this column |
| ------ | ----------- |
| Root Cause | Specifically for bugs, empty in case of no variants |
| Jira ticket | Add the name to the Jira ticket eg: "NEXMANAGE-622". Automation will do the linking to Jira |


### CODE MAINTAINABILITY

- [ ] Added required new tests relevant to the changes
- [ ] Updated Documentation as relevant to the changes
- [ ] PR change contains code related to security
- [ ] PR introduces changes that break compatibility with other modules/services (If YES, please provide description)
- [ ] Run `go fmt` or `format-python.sh` as applicable
- [ ] Update Changelog
- [ ] Integration tests are passing
- [ ] If Cloudadapter changes, check Azure connectivity manually

# _Code must act as a teacher for future developers_
