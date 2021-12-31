Step 1 Changelog
----------------

* Go here: https://gitlab.devtools.intel.com/OWR/IoTG/SMIE/Manageability/bit-creek/blob/vision/Changelog.md
* Click on Unreleased
* For every change listed, decide if it is a fix, change, security change, or not customer facing.  For everything that is customer facing, prepare a 
one line description of the change along with an RTC number, if relevant.
* Go back here and download: https://gitlab.devtools.intel.com/OWR/IoTG/SMIE/Manageability/bit-creek/blob/vision/Changelog.md
* Edit Changelog.md to include new release notes.  Follow existing format.  Copy "Known Issues" from previous release and remove any that have
been fixed.  Add any new issues from RTC that have been filed.
* Save Changelog.md for use in next step.


Step 2 Prepare Binaries
-----------------------

* Start a new pull request/branch from: https://gitlab.devtools.intel.com/OWR/IoTG/SMIE/Manageability/bit-creek/merge_requests
* Edit version.txt to reflect new version number.
* Copy in Changelog.md from above to reflect new changes.
* Merge upstream changes for Yocto from meta-intel-ese-manageability changes into bit-creek/packaging/yocto/meta-bit-creek.  Exclude the Turtle Creek directory.
    * cd packaging/yocto/meta-bit-creek in Bit Creek repository
    * remove all directories under above directory
    * copy all directories from meta-intel-ese-manageability
    * check changes
* Rename packaging/yocto/meta-bit-creek/recipes-bit-creek/bit-creek/bit-creek_VERSION.bb to reflect new version.
* Push a commit with above changes to the branch and make sure TeamCity builds work/tests pass.
* Run KMB, Ubuntu builds and collect binaries.
 

Step 3 Create Ubuntu release
-----------------------------

* Download the artifacts for Bit Creek, Agents, Packaging for release MR
* zip up the following -> install-bc.sh, vision-agent-x.x.x-EVAL.deb, uninstall-bc.sh into BitCreek_vx.x.x_ubuntu.zip 
* Deploy new zip file to https://ubit-artifactory-or.intel.com/artifactory/webapp/#/artifacts/browse/tree/General/turtle-creek-debian-local/Releases

Step 4 SQA Scans
----------------

* Go here: https://appsec.intel.com/#/stars/surf/23258  and find the GitLab section.
* Press 'rescan'.  Confirmation will take place over email.
* Perform BDBA scan.
* Perform Protex scan.
* Collect unit test coverage.
* Perform malware scan.

Step 5 Smoke Test
-----------------

* Submit KMB and Ubuntu binaries to Validation for smoke test.

Step 6 Tag
----------
* Get two reviews on the pull request.
* Create a new release tag: go here https://gitlab.devtools.intel.com/OWR/IoTG/SMIE/Manageability/bit-creek/tags , Click "New Tag" and fill out the fields.  
For tag version, use the format: v0.34.0.  For target, choose the commit on develop branch that came from the pull request above.
* Click "Create Tag"

Step 7 Merge Back
-----------------
* Create branch for merging changes back to develop branch
* In branch, add MR to reset version to 0.0.0.
* Squash and merge back to develop branch with single commit.


Step 8 Submit HSDs/MR for Yocto
-------------------------------
* Open HSD for KMB for new release.
    * Example link ->  https://hsdes.intel.com/resource/22011205116 
    * Select 'Create new from this article'
    * Replace changelog
    * Change version from previous to new
* Open branches/MRs in sed-ehl-gitlfs-local repository with new Bit Creek binaries (look under Intermediate Yocto Builds / prepare XYZ binaries for submission).  The kmb MR needs to reference the HSD.  The ehl MR is simply to rename the dummy input file to match the new Bit Creek version.
    * Clone above repo
    * Create branch in the format bitcreek-1.5.0
    * Find BitCreek directory under /prioritiery/bin and remove all files
    * wget 'Prepare x86_64_Yocto_input'
    * copy files into above directory in repository
    * git add files
    * git commit (look at log for example format)
    * git push
    * create merge request and tag @jyong2 - Please Review
* Open branches/MR in sed-kmb-gitlfs-local repositories with the new Bit Creek binaries 
    * Clone above repo
    * Create branch in the format bitcreek-1.5.0
    * Find BitCreek directory under /prioritiery and remove all files
    * wget 'Prepare ARM input'
    * copy files into above directory in repository
    * git add files
    * git commit (look at log for example format)
    * git push
    * create merge request and tag @chongyic - Please Review
* Open branch/MR in meta-intel-ese-manageability with layer updates.  This MR needs to reference the HSD.
    * Move over bb file   

Step 9 Prepare and send release email
-------------------------------------
* See sample below.

```Hello all,
 
I’ve submitted new MR’s for KMB with associated HSDs. Links below.
 
MR Links
 
https://gitlab.devtools.intel.com/OWR/IoTG/ESE/Linux-Integration/Yocto/meta-intel-ese-manageability/-/merge_requests/43
 
https://gitlab.devtools.intel.com/OWR/IoTG/ESE/Linux-Integration/Yocto/sed-kmb-gitlfs-local/-/merge_requests/187 -- Bays
 
HSD Links
See MRs above.
Ubuntu binaries
https://ubit-artifactory-or.intel.com/artifactory/bit-creek-debian-local/Releases/BitCreek_v2.6.1_ubuntu.zip
SQA
·  Protex scan. No violations. https://amrprotex004.devtools.intel.com/ https://tc01s-or.devtools.intel.com/repository/download/TurtleCreek_Protex_ProtexScan/4373624:id/Protex-Scan-137.html 
·  Checkmarx scan. 0 vulnerabilities: https://sast.intel.com/CxWebClient/ViewerMain.aspx?scanId=1594916&ProjectID=282134 
·  Unit test coverage. Collected.
·  Malware scan. Pass.
·  BDBA scan Ubuntu Pass: https://bdba001.icloud.intel.com/products/377699/#/analysis
 
CHANGES
 
<insert new changelog entries here>
 
Thanks,
Gavin
```


Include below list in release email.
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
- Dettmar, Robert A <robert.a.dettmar@intel.com>
- Mountain, Highland M <highland.m.mountain@intel.com>
- Lam, Tuyet Trang <tuyet.trang.lam@intel.com>
- Abraham, Mary <mary.abraham@intel.com> 
