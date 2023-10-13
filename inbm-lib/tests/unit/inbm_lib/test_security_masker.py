

from unittest import TestCase
from inbm_lib.security_masker import mask_security_info


class TestPasswordMasker(TestCase):

    maxDiff = None

    def test_mask_docker_password_and_username(self):
        manifest = '<?xml version="1.0" encoding="utf-8"?><manifest><type>ota</type><ota><header' \
                   '><type>aota</type>' \
                   '</header><type><aota name="sample-rpm"><cmd>pull</cmd><app>docker</app><fetch' \
                   '>None</fetch>' \
                   '<version>0</version><containerTag>None</containerTag><dockerRegistry>intelcorp' \
                   '/dl-training-tool' \
                   '</dockerRegistry><dockerUsername>user</dockerUsername><dockerPassword>mypassword' \
                   '</dockerPassword></aota></type></ota></manifest>'
        r_manifest = '<?xml version="1.0" ' \
                     'encoding="utf-8"?><manifest><type>ota</type><ota><header><type>aota</type>' \
                     '</header><type><aota ' \
                     'name="sample-rpm"><cmd>pull</cmd><app>docker</app><fetch>None</fetch>' \
                     '<version>0</version><containerTag>None</containerTag><dockerRegistry>intelcorp' \
                     '/dl-training-tool' \
                     '</dockerRegistry><dockerUsername>XXXXX</dockerUsername><dockerPassword' \
                     '>XXXXX</dockerPassword></aota></type></ota></manifest>'
        self.assertEqual(r_manifest, mask_security_info(manifest))

    def test_mask_server_password_and_username(self):
        manifest = '<?xml version="1.0" encoding="utf-8"?><manifest><type>ota</type><ota><header' \
                   '><type>aota</type>' \
                   '</header><type><aota name="sample-rpm"><cmd>pull</cmd><app>docker</app><fetch' \
                   '>None</fetch>' \
                   '<version>0</version><containerTag>None</containerTag><username>user</username' \
                   '><password>' \
                   'mypassword</password><dockerRegistry>intelcorp/dl-training-tool</dockerRegistry>' \
                   '</aota></type></ota></manifest>'
        r_manifest = "<?xml version=\"1.0\" " \
                     "encoding=\"utf-8\"?><manifest><type>ota</type><ota><header><type>aota" \
                     "</type></header><type><aota " \
                     "name=\"sample-rpm\"><cmd>pull</cmd><app>docker</app><fetch>None" \
                     "</fetch><version>0</version><containerTag>None</containerTag>" \
                     "<username>XXXXX</username>" \
                     "<password>XXXXX</password><dockerRegistry>intelcorp/dl-training-tool" \
                     "</dockerRegistry>" \
                     "</aota></type></ota></manifest>"
        self.assertEqual(r_manifest, mask_security_info(manifest))

    def test_mask_both_passwords_and_user_names(self):
        manifest = '<?xml version="1.0" encoding="utf-8"?><manifest><type>ota</type><ota><header' \
                   '><type>aota</type>' \
                   '</header><type><aota name="sample-rpm"><cmd>pull</cmd><app>docker</app><fetch' \
                   '>None</fetch>' \
                   '<version>0</version><containerTag>None</containerTag><username>user</username' \
                   '><password>' \
                   'mypassword</password><dockerRegistry>intelcorp/dl-training-tool</dockerRegistry>' \
                   '<dockerUsername>user</dockerUsername><dockerPassword>mypassword</dockerPassword' \
                   '></aota>' \
                   '</type></ota></manifest>'
        r_manifest = "<?xml version=\"1.0\" " \
                     "encoding=\"utf-8\"?><manifest><type>ota</type><ota><header><type>aota" \
                     "</type></header><type><aota " \
                     "name=\"sample-rpm\"><cmd>pull</cmd><app>docker</app><fetch>None" \
                     "</fetch><version>0</version><containerTag>None</containerTag><username>" \
                     "XXXXX</username>" \
                     "<password>XXXXX</password><dockerRegistry>intelcorp/dl-training-tool" \
                     "</dockerRegistry>" \
                     "<dockerUsername>XXXXX</dockerUsername><dockerPassword>XXXXX" \
                     "</dockerPassword></aota></type></ota></manifest>"
        self.assertEqual(r_manifest, mask_security_info(manifest))

    def test_mask_no_passwords_or_usernames(self):
        manifest = '<?xml version="1.0" encoding="utf-8"?><manifest><type>ota</type><ota><header' \
                   '><type>aota</type>' \
                   '</header><type><aota name="sample-rpm"><cmd>pull</cmd><app>docker</app><fetch' \
                   '>None</fetch>' \
                   '<version>0</version><containerTag>None</containerTag><dockerRegistry>intelcorp' \
                   '/dl-training-tool' \
                   '</dockerRegistry></aota></type></ota' \
                   '></manifest>'
        r_manifest = "<?xml version=\"1.0\" " \
                     "encoding=\"utf-8\"?><manifest><type>ota</type><ota><header><type>aota" \
                     "</type></header><type><aota " \
                     "name=\"sample-rpm\"><cmd>pull</cmd><app>docker</app><fetch>None" \
                     "</fetch><version>0</version><containerTag>None</containerTag>" \
                     "<dockerRegistry>" \
                     "intelcorp/dl-training-tool</dockerRegistry></aota></type></ota></manifest>"
        self.assertEqual(r_manifest, mask_security_info(manifest))
