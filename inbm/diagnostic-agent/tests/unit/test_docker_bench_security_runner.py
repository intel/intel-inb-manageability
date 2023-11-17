from unittest import TestCase

from diagnostic.docker_bench_security_runner import DockerBenchRunner
from mock import patch

docker_bench_pass_output = "[INFO] 6 - Docker Security Operations \n" \
                           "[INFO] 6.1  - Avoid image sprawl \n" \
                           "[INFO]      * There are currently: 4 images\n" \
                           "[INFO] 6.2  - Avoid container sprawl\n" \
                           "[INFO]      * There are currently a total of 12 containers, " \
                           "with 2 of them currently running"

docker_bench_fail_container_output = "[WARN] 5.25 - Ensure the container is restricted from " \
                                     "acquiring additional privileges\n" \
                                     "[WARN]      * Privileges not restricted: abc\n" \
                                     "[WARN] 5.26 - Ensure container health is checked at runtime\n" \
                                     "[WARN]      * Health check not set: abc\n" \
                                     "[INFO] 5.27 - Ensure docker commands always get the latest version of the image\n" \
                                     "[WARN] 5.28 - Ensure PIDs cgroup limit is used\n"

docker_bench_fail_image_output = "[WARN] 4.5  - Ensure Content trust for Docker is Enabled \n" \
                                 "[WARN] 4.6  - Ensure HEALTHCHECK instructions have been added to the " \
                                 "container image\n" \
                                 "[WARN]      * No Healthcheck found: [a1]\n" \
                                 "[WARN]      * No Healthcheck found: [a2]\n" \
                                 "[WARN]      * No Healthcheck found: [a3]\n"


class TestDockerBenchSecurityRunner(TestCase):

    @patch('inbm_common_lib.shell_runner.PseudoShellRunner.get_process')
    @patch('inbm_lib.trtl.Trtl.run_docker_bench_security_test')
    def test_success_dbs_run(self, mocked_trtl, mock_shellrunner):
        mocked_trtl.return_value = docker_bench_pass_output
        dbs = DockerBenchRunner()
        dbs.start()
        dbs.join()
        self.assertTrue(dbs.dbs_result.success_flag)
        self.assertEqual("Test results: All Passed", dbs.dbs_result.result)
        self.assertEqual([], dbs.dbs_result.failed_containers)
        self.assertEqual([], dbs.dbs_result.failed_images)

    @patch('inbm_common_lib.shell_runner.PseudoShellRunner.get_process')
    @patch('inbm_lib.trtl.Trtl.run_docker_bench_security_test')
    def test_fail_dbs_container_run(self, mocked_trtl, mock_shellrunner):
        mocked_trtl.return_value = docker_bench_fail_container_output
        dbs = DockerBenchRunner()
        dbs.start()
        dbs.join()
        self.assertFalse(dbs.dbs_result.success_flag)
        self.assertEqual(dbs.dbs_result.result, "Test results: Failures in: 5.25,,5.26,,5.28")
        self.assertEqual(dbs.dbs_result.failed_containers, ['abc'])
        self.assertEqual(dbs.dbs_result.failed_images, [])

    @patch('inbm_common_lib.shell_runner.PseudoShellRunner.get_process')
    @patch('inbm_lib.trtl.Trtl.run_docker_bench_security_test')
    def test_fail_dbs_image_run(self, mocked_trtl, mock_shellrunner):
        mocked_trtl.return_value = docker_bench_fail_image_output
        dbs = DockerBenchRunner()
        dbs.start()
        dbs.join()
        self.assertFalse(dbs.dbs_result.success_flag)
        self.assertEqual(dbs.dbs_result.result, "Test results: Failures in: 4.5,4.6")
        self.assertEqual(dbs.dbs_result.failed_containers, [])
        self.assertEqual(dbs.dbs_result.failed_images, ['a1', 'a2', 'a3'])

    @patch('inbm_common_lib.shell_runner.PseudoShellRunner.get_process')
    @patch('inbm_lib.trtl.Trtl.run_docker_bench_security_test')
    def test_fail_dbs_not_run(self, mocked_trtl, mock_shellrunner):
        mocked_trtl.return_value = ''
        dbs = DockerBenchRunner()
        dbs.start()
        dbs.join()
        self.assertFalse(dbs.dbs_result.success_flag)
        self.assertEqual(dbs.result, "")
        self.assertFalse(dbs.dbs_result.failed_containers)
        self.assertFalse(dbs.dbs_result.failed_images)
