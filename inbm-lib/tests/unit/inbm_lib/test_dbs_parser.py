from unittest import TestCase

from inbm_lib.dbs_parser import parse_docker_bench_security_results


class TestDbsParser(TestCase):
    def test_dbs_output_parser_blank_input(self):
        parse_input = """"""
        dbs_result = parse_docker_bench_security_results(parse_input)
        self.assertTrue(dbs_result.is_success)
        self.assertEqual('Test results: ', dbs_result.result)
        self.assertEqual('Failures in: ', dbs_result.fails)
        self.assertEqual([], dbs_result.failed_images)
        self.assertEqual([], dbs_result.failed_containers)

    def test_dbs_output_parser_info(self):
        parse_input = """[INFO] 5.9  - Some text"""
        dbs_result = parse_docker_bench_security_results(parse_input)
        self.assertTrue(dbs_result.is_success)
        self.assertEqual('Test results: ', dbs_result.result)
        self.assertEqual('Failures in: ', dbs_result.fails)
        self.assertEqual([], dbs_result.failed_images)
        self.assertEqual([], dbs_result.failed_containers)

    def test_dbs_output_parser_container_fail_5_2(self):
        parse_input = """
[WARN] 5.2  - Ensure SELinux security options are set, if applicable
[WARN]      * No SecurityOptions Found: container_name"""
        dbs_result = parse_docker_bench_security_results(parse_input)
        self.assertFalse(dbs_result.is_success)
        self.assertEqual('Test results: ', dbs_result.result)
        self.assertEqual('Failures in: 5.2,,', dbs_result.fails)
        self.assertEqual([], dbs_result.failed_images)
        self.assertEqual(['container_name'], dbs_result.failed_containers)

    def test_dbs_output_parser_image_fail_4_6(self):
        parse_input = """
[WARN] 4.6  - Ensure that HEALTHCHECK instructions have been added to container images
[WARN]      * No Healthcheck found: [foo:1]
[WARN]      * No Healthcheck found: [bar]"""
        dbs_result = parse_docker_bench_security_results(parse_input)
        self.assertFalse(dbs_result.is_success)
        self.assertEqual('Test results: ', dbs_result.result)
        self.assertEqual('Failures in: 4.6,,,', dbs_result.fails)
        self.assertEqual(['foo:1', 'bar'], dbs_result.failed_images)
        self.assertEqual([], dbs_result.failed_containers)

    def test_dbs_output_parser_container_and_image_fails(self):
        parse_input = """
[WARN] 5.2  - Ensure SELinux security options are set, if applicable
[WARN]      * No SecurityOptions Found: container_name

[WARN] 4.6  - Ensure that HEALTHCHECK instructions have been added to container images
[WARN]      * No Healthcheck found: [foo:1]
[WARN]      * No Healthcheck found: [bar]"""
        dbs_result = parse_docker_bench_security_results(parse_input)
        self.assertFalse(dbs_result.is_success)
        self.assertEqual('Test results: ', dbs_result.result)
        self.assertEqual('Failures in: 5.2,,4.6,,,', dbs_result.fails)
        self.assertEqual(['foo:1', 'bar'], dbs_result.failed_images)
        self.assertEqual(['container_name'], dbs_result.failed_containers)
