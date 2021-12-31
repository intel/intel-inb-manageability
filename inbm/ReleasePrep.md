Step 1 Create Branch, Prepare Changelog, Pull Yocto Layer Changes
-----------------------------------------------------------------

* Check out Intel(R) In-Band Manageability develop branch. Ensure it's up-to-date (usually git pull).
* Create a branch called release-X.Y.Z where X.Y.Z is the new version number
* Look at commits between the previous release and the branch.  Ensure any commit with a fix, change, or security change that
might be of interest to a customer is listed in the Changelog.md for the new release.
* Push the branch to the git server.
* Merge upstream changes for Yocto from meta-intel-ese-manageability changes into iotg-inb/packaging/yocto/meta-intel-ese-manageability.  Exclude the Bit Creek directory.


Step 2 Prepare Binaries
-----------------------

* Start a new merge request/branch from: https://gitlab.devtools.intel.com/OWR/IoTG/SMIE/Manageability/iotg-inb/merge_requests
* Edit version.txt to reflect new version number plus rc1 -- e.g. X.Y.Z.rc1.
* Rename packaging/yocto/meta-intel-ese-manageability/recipes-inb/inb/inb_VERSION.bb to reflect new version plus rc1.
* Push a commit with above changes to the branch.
* Run "Prepare x86_64 Yocto input binaries for submission," "Prepare arm64 input binaries for submission," "Intel(R) In-Band Manageability Evaluation
  release files" builds in TeamCity (selecting the correct merge request number) to generate binaries.

Step 3 Smoke Test
-----------------

* Run a smoke test with EHL and KMB CRBs. See /Yocto_Smoke_Test_Instructions.txt
* Run a smoke test on Ubuntu.  Should perform FOTA, SOTA, and Telit tests.
* Repeat steps 2 and 3 as needed to fix any bugs that appear, incrementing rc1 to rc2, rc3, etc. When you have a clean version, call it X.Y.Z without the rcN suffix.

Step 4 SQA Scans
----------------

* Reset branch 11111-checkmarx-target-branch to develop branch.
* Go here: https://appsec.intel.com/#/stars/surf/17730 and find the GitLab section.
* Press 'rescan'.  Confirmation will take place over email.
* Perform BDBA scan.
* Perform Protex scan.
* Collect unit test coverage.
* Perform malware scan.

Step 5 Tag
----------
* Get two reviews on the merge request.
* Create a new release tag: go here https://gitlab.devtools.intel.com/OWR/IoTG/SMIE/Manageability/iotg-inb/tags , Click "New Tag" and fill out the fields.  
For tag version, use the format: vX.Y.Z.  For target, choose the commit ID corresponding to the version that is being tagged.
* Click "Create Tag"

Step 6 Merge Back
-----------------
* Create branch for merging changes back to develop branch
* In branch, add commit to reset version to 0.0.0 (version.txt and inb_VERSION.bb as above).
* Squash and merge back to develop branch. Push to remote develop branch.


Step 7 Submit HSDs/MR for Yocto
-------------------------------
* Open HSD for KMB and HSD for EHL for new release.
* Open branches/MRs in sed-ehl-gitlfs-local and sed-kmb-gitlfs-local repositories with new Intel(R) In-Band Manageability binaries (look under Intermediate Yocto Builds / prepare XYZ binaries for submission).  These MRs need to reference the respective HSDs.
* Open branch/MR in meta-intel-ese-manageability with layer updates.  This MR needs to reference both HSDs.

Step 8 Prepare and send release email
-------------------------------------
* See sample below.

```Hello all,
 
I’ve submitted new MR’s for EHL and KMB with associated HSDs. Links below.
 
MR Links
 
https://gitlab.devtools.intel.com/OWR/IoTG/ESE/Linux-Integration/Yocto/meta-intel-ese-manageability/-/merge_requests/43
 
https://gitlab.devtools.intel.com/OWR/IoTG/ESE/Linux-Integration/Yocto/sed-ehl-gitlfs-local/-/merge_requests/76 -- Lakes
https://gitlab.devtools.intel.com/OWR/IoTG/ESE/Linux-Integration/Yocto/sed-kmb-gitlfs-local/-/merge_requests/187 -- Bays
 
HSD Links
See MRs above.
Ubuntu binaries
https://ubit-artifactory-or.intel.com/artifactory/turtle-creek-debian-local/Releases/IntelManageability_v2.6.1_evaluation.zip
SQA
·  Protex scan. No violations. https://amrprotex004.devtools.intel.com/ https://tc01s-or.devtools.intel.com/repository/download/TurtleCreek_Protex_ProtexScan/4373624:id/Protex-Scan-137.html 
·  Checkmarx scan. 0 vulnerabilities: https://sast.intel.com/CxWebClient/ViewerMain.aspx?scanId=1594916&ProjectID=282134 
·  Unit test coverage. Collected.
·  Malware scan. Pass.
·  BDBA scan EHL. Pass: https://bdba001.icloud.intel.com/products/377707/#/analysis 
·  BDBA scan Ubuntu Pass: https://bdba001.icloud.intel.com/products/377699/#/analysis
 
CHANGES
 
## 2.6.1 - 2020-05-12
Release notes for Intel(R) In-Band Manageability 2.6.1
 
NOTE: Please see note for 2.6.0 below.
 
### Fixed
- Cloudadapter would not print error on mqtt disconnect
 
## 2.6.0 - 2020-05-11
Release notes for Intel(R) In-Band Manageability 2.6.0
 
NOTE: When upgrading from previous versions, especially if on a mender or Yocto platform, please
ensure that /etc/firmware_tool_info.conf is populated correctly for your system.
 
### Changed
- 43047 Intel internal network no longer required to build software
- 42988 FOTA module reads tool information from config file.
- 43281 Config Load - fetch and path tags optional to support Bit Creek
- 43252 [Diagnostic] Network check shall be configurable to support Bit Creek
 
### Security
- 43004 and 43003 Libraries updated to pull in security fixes
- 43046 Mosquitto no longer runs as root
 
### Fixed
- 43239 [Base] Bug: Mqtt failed to start
- 43163 [Base] Bug: Unable to login to Intel docker registry (Harbor)
- 43161 [Base] Bug: Observed AttributeError: 'int' object has no attribute 'replace' error when trigger AOTA button
- 42573 [CML] Bug: Configuration file failed to load
- 43115 [Base] Bug: Status code shows 0 when get-element for the ubuntuAptSource and minPowerPercent
 
### Added
- Experimental Windows support. Can build Windows binaries that will self-install as
services. FOTA works on one Windows NUC platform.
 
 
Thanks,
Gavin
```


Include below list in EHL/KMB release email.
------
TO:
- Chai, Chong Yi <chong.yi.chai@intel.com>
- Yong, Jonathan <jonathan.yong@intel.com>
- Mohamad Azman, Syaza Athirah <syaza.athirah.mohamad.azman@intel.com>

CC:
- IOTG_SSEA_OR <iotg_ssea_or@intel.com>
- Ho, Nee Shen <nee.shen.ho@intel.com>
- Itha, Vasavi V <vasavi.v.itha@intel.com>
- Goyal, Himanshu <Himanshu.Goyal@intel.com>
- Khoo, Boon Ho <boon.ho.khoo@intel.com>
- Henson, Tiffani <tiffani.henson@intel.com>
- Shanmugam, Karnan <karnan.shanmugam@intel.com>
- Lee, Ban Siong <ban.siong.lee@intel.com> 
- Mok, Kim Hoe <kim.hoe.mok@intel.com>
- Tan, Karen Lee Ling <karen.lee.ling.tan@intel.com>
- Soo, Swee Kiong <swee.kiong.soo@intel.com>
- Loh, Shao Boon <shao.boon.loh@intel.com>
- Mahesh, Divya <divya.mahesh@intel.com>
- Mays Ii, William W <william.w.mays.ii@intel.com>
- Tan, Jui Nee <jui.nee.tan@intel.com>
- Nahulanthran, Sanjeev <sanjeev.nahulanthran@intel.com>
- Foltz, Lisa S <lisa.s.foltz@intel.com>
- K, Venugopal <veugopal.k@intel.com>
- Parmar, Kartikey Rameshbhai <Kartikey.Rameshbhai.Parmar@intel.com>
- Hu, Siew Lan <siew.lan.hu@intel.com>
- Shanmugam, Karnan <karnan.shanmugam@intel.com>
- Mohamad Azman, Syaza Athirah <syaza.athirah.mohamad.azman@intel.com>
- Shui Lei <Shui.Lei.Ng@intel.com>
- Ng, Chooi Lan <chooi.lan.ng@intel.com>

