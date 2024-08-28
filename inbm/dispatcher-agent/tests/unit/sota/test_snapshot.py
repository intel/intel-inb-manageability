import unittest

from ..common.mock_resources import *
from ddt import data, ddt, unpack
from unittest.mock import mock_open, patch, Mock

from dispatcher.dispatcher_exception import DispatcherException
from dispatcher.sota.sota_error import SotaError
from dispatcher.sota.os_factory import DebianBasedSnapshot, YoctoSnapshot, SotaOsFactory, TiberOSSnapshot


@ddt
class TestSnapshot(unittest.TestCase):

    class DispatcherTelemetry:

        def telemetry(self, s) -> None:
            pass
    dispatcher_telemetry = DispatcherTelemetry()

    @unpack
    @data((1, 0, ""), (2, '1', ""))
    @patch("inbm_lib.trtl.Trtl.delete_snapshot")
    def test_ubuntu_delete_snap(self, order, rc, err, mock_del_snap) -> None:
        factory = SotaOsFactory(
            MockDispatcherBroker.build_mock_dispatcher_broker(), None, []).get_os('Ubuntu')
        snapshot = factory.create_snapshotter("update", '1', False, True)
        mock_del_snap.return_value = (rc, err)
        val = snapshot.commit()
        mock_del_snap.assert_called_once()
        if order == 2:
            self.assertNotEqual(val, 0)
        if order == 1:
            self.assertEqual(val, 0)

    @unpack
    @data((1, "0", ""), (2, "1", "err"))
    @patch('dispatcher.sota.snapshot.dispatcher_state', autospec=True)
    @patch("inbm_lib.trtl.Trtl.single_snapshot", return_value=('', 'ERROR'))
    def test_ubuntu_snapshot(self, order, rc, err, mock_trtl_single_snapshot, mock_state) -> None:
        factory = SotaOsFactory(
            MockDispatcherBroker.build_mock_dispatcher_broker(), None, []).get_os('Ubuntu')
        snapshot = factory.create_snapshotter("update", '1', False, True)
        with patch('builtins.open', new_callable=mock_open()) as m:
            if order == 1:
                mock_trtl_single_snapshot.return_value = (rc, err)
                snapshot.take_snapshot()
            else:
                self.assertRaises(SotaError, snapshot.take_snapshot)

    @unpack
    @data((1, "err"))
    @patch("inbm_lib.trtl.Trtl.single_snapshot")
    @patch("pickle.dump", side_effect=Exception('foo'))
    def test_Ubuntu_snapshot_raises1(self, rc, err, mock_pickle_dump, mock_trtl_single_snapshot) -> None:
        factory = SotaOsFactory(
            MockDispatcherBroker.build_mock_dispatcher_broker(), None, []).get_os('Ubuntu')
        snapshot = factory.create_snapshotter("update", '1', False, True)
        with patch('builtins.open', new_callable=mock_open()) as m:
            mock_trtl_single_snapshot.return_value = (rc, err)
            with self.assertRaises(SotaError):
                snapshot.take_snapshot()
                mock_pickle_dump.assert_called_once()

    @unpack
    @data((1, "err"))
    @patch("inbm_lib.trtl.Trtl.single_snapshot")
    def test_Ubuntu_snapshot_raises2(self, rc, err, mock_trtl_single_snapshot) -> None:
        with patch('builtins.open', new_callable=mock_open()) as m:
            factory = SotaOsFactory(
                MockDispatcherBroker.build_mock_dispatcher_broker()).get_os('Ubuntu')
            snapshot = factory.create_snapshotter("update", '1', False, True)
            mock_trtl_single_snapshot.return_value = (rc, err)
            try:
                snapshot.take_snapshot()
            except:
                mock_trtl_single_snapshot.assert_called_once()


class TestUbuntuSnapshot(unittest.TestCase):

    @patch('dispatcher.sota.snapshot.dispatcher_state', autospec=True)
    def test_take_snapshot_proceed_fail_publishes_error_succeeds(self, mock_state) -> None:
        dispatcher_callbacks = Mock()
        dispatcher_broker = Mock()
        trtl = Mock()
        trtl.single_snapshot.return_value = "1", "Error!"

        ubuntu_snapshot = DebianBasedSnapshot(trtl, "command", dispatcher_broker, "1", True, True)
        ubuntu_snapshot.take_snapshot()
        assert dispatcher_broker.telemetry.call_count > 0

        args, _ = dispatcher_broker.telemetry.call_args
        message, = args
        self.assertIn("will proceed without", message)

    @patch('dispatcher.sota.snapshot.dispatcher_state', autospec=True)
    def test_take_snapshot_proceed_cannot_write_publishes_error_succeeds(self, mock_dispatcher_state) -> None:
        dispatcher_callbacks = Mock()
        dispatcher_broker = Mock()
        trtl = Mock()
        trtl.single_snapshot.return_value = "1", None

        ubuntu_snapshot = DebianBasedSnapshot(trtl, "command", dispatcher_broker, "1", True, True)
        ubuntu_snapshot.take_snapshot()

        assert dispatcher_broker.telemetry.call_count > 0
        (message,), _ = dispatcher_broker.telemetry.call_args
        self.assertIn("succeeded", message)

    def test_rollback_and_delete_snap_skipped_succeeds(self) -> None:
        dispatcher_callbacks = Mock()
        dispatcher_broker = Mock()
        trtl = Mock()

        ubuntu_snapshot = DebianBasedSnapshot(trtl, "command", dispatcher_broker, "", True, True)
        ubuntu_snapshot._rollback_and_delete_snap()

        assert dispatcher_broker.telemetry.call_count > 0
        args, _ = dispatcher_broker.telemetry.call_args
        message, = args
        assert "skipped" in message

    @patch('dispatcher.sota.snapshot.dispatcher_state', autospec=True)
    def test_revert_succeeds(self, mock_dispatcher_state) -> None:
        rebooter = Mock()
        ubuntu_snapshot = DebianBasedSnapshot(Mock(), "command", Mock(), "", True, True)
        ubuntu_snapshot._rollback_and_delete_snap = Mock()  # type: ignore[method-assign]
        ubuntu_snapshot.snap_num = "1"
        ubuntu_snapshot.revert(rebooter, 0)
        assert mock_dispatcher_state.clear_dispatcher_state.call_count == 1
        self.assertEqual(ubuntu_snapshot._rollback_and_delete_snap.call_count, 1)
        assert rebooter.reboot.call_count == 1


class TestYoctoSnapshot(unittest.TestCase):

    @patch('dispatcher.sota.snapshot.dispatcher_state', autospec=True)
    @patch('dispatcher.sota.snapshot.read_current_mender_version', autospec=True)
    def test_take_snapshot_succeeds(self, mock_mender_version, mock_dispatcher_state) -> None:
        mock_mender_version.return_value = "foo"
        mock_dispatcher_state.write_dispatcher_state_to_state_file.return_value = True
        dispatcher_callbacks = Mock()
        dispatcher_broker = Mock()

        yocto_snapshot = YoctoSnapshot(Mock(), "command", dispatcher_broker, "1", True, True)
        yocto_snapshot.take_snapshot()

        assert dispatcher_broker.telemetry.call_count > 0
        args, _ = dispatcher_broker.telemetry.call_args
        message, = args
        assert "unsuccessful" not in message

    @patch('dispatcher.sota.snapshot.read_current_mender_version', return_value='abc')
    @patch('dispatcher.common.dispatcher_state.is_dispatcher_state_file_exists', return_value=True)
    @patch('dispatcher.common.dispatcher_state.consume_dispatcher_state_file',
           return_value={'restart_reason': 'sota_upgrade'})
    @patch('dispatcher.common.dispatcher_state.write_dispatcher_state_to_state_file')
    def test_dispatcher_state_file_exist_consume_called_sota(self, mock_write_state_file, mock_disp_state_file_exist, mock_consume_disp_file, mock_read_mender) -> None:
        dispatcher_callbacks = Mock()
        dispatcher_broker = Mock()

        yocto_snapshot = YoctoSnapshot(Mock(), "command", Mock(), "1", True, True)
        yocto_snapshot.take_snapshot()
        mock_consume_disp_file.assert_called_once()
        mock_write_state_file.assert_called_once()

    @patch('dispatcher.sota.snapshot.read_current_mender_version', return_value='abc')
    @patch('dispatcher.common.dispatcher_state.is_dispatcher_state_file_exists', return_value=False)
    @patch('dispatcher.common.dispatcher_state.consume_dispatcher_state_file',
           return_value={'restart_reason': 'sota_upgrade'})
    @patch('dispatcher.common.dispatcher_state.write_dispatcher_state_to_state_file')
    def test_dispatcher_state_file_not_exist_consume_not_called_sota(self, mock_write_state_file, mock_consume_disp_file, mock_disp_state_file_exist, mock_read_mender) -> None:
        dispatcher_callbacks = Mock()
        dispatcher_broker = Mock()

        yocto_snapshot = YoctoSnapshot(Mock(), "command", Mock(), "1", True, True)
        yocto_snapshot.take_snapshot()
        mock_consume_disp_file.assert_not_called()
        mock_write_state_file.assert_called_once()

    @patch('dispatcher.sota.snapshot.dispatcher_state', autospec=True)
    @patch('dispatcher.sota.snapshot.read_current_mender_version', return_value='abc')
    def test_raise_when_unable_to_write_file(
            self, mock_read_mender_ver, mock_dispatcher_state) -> None:
        mock_dispatcher_state.write_dispatcher_state_to_state_file.side_effect = DispatcherException(
            'Error')
        dispatcher_callbacks = Mock()
        dispatcher_broker = Mock()

        yocto_snapshot = YoctoSnapshot(Mock(), "command", dispatcher_broker, "1", True, True)
        failed = False
        try:
            yocto_snapshot.take_snapshot()
        except SotaError:
            failed = True

        assert failed
        assert dispatcher_broker.telemetry.call_count > 0
        args, _ = dispatcher_broker.telemetry.call_args
        message, = args
        assert "unsuccessful" in message


class TestTiberOSSnapshot(unittest.TestCase):
    @patch('dispatcher.sota.snapshot.dispatcher_state', autospec=True)
    @patch('dispatcher.sota.snapshot.update_tool_version_command', autospec=True)
    def test_take_snapshot_succeeds(self, mock_version, mock_dispatcher_state) -> None:
        mock_version.return_value = "2c26b46b68ffc68ff99b453c1d30413413422d706483bfa0f98a5e886266e7ae"
        mock_dispatcher_state.write_dispatcher_state_to_state_file.return_value = True

        dispatcher_broker = Mock()

        tiberos_snapshot = TiberOSSnapshot(Mock(), "command", dispatcher_broker, "1", True, True)
        tiberos_snapshot.take_snapshot()

        assert dispatcher_broker.telemetry.call_count > 0
        args, _ = dispatcher_broker.telemetry.call_args
        message, = args
        assert "unsuccessful" not in message

    @patch("inbm_common_lib.shell_runner.PseudoShellRunner.run", return_value=('', "", 1))
    def test_take_snapshot_ut_version_command_error(self, mock_run) -> None:
        dispatcher_broker = Mock()

        tiberos_snapshot = TiberOSSnapshot(Mock(), "command", dispatcher_broker, "1", True, True)
        with self.assertRaises(SotaError):
            tiberos_snapshot.take_snapshot()

        mock_run.assert_called_once()

    @patch("inbm_common_lib.shell_runner.PseudoShellRunner.run", return_value=('', "", 0))
    @patch('dispatcher.sota.snapshot.dispatcher_state', autospec=True)
    def test_commit_success(self, mock_dispatcher_state, mock_run) -> None:
        dispatcher_broker = Mock()

        tiberos_snapshot = TiberOSSnapshot(Mock(), "command", dispatcher_broker, "1", True, True)
        self.assertEqual(tiberos_snapshot.commit(), 0)
        mock_run.assert_called_once()
        assert mock_dispatcher_state.clear_dispatcher_state.call_count == 1

    @patch("inbm_common_lib.shell_runner.PseudoShellRunner.run", return_value=('', "", 1))
    @patch('dispatcher.sota.snapshot.dispatcher_state', autospec=True)
    def test_commit_failed_with_error(self, mock_dispatcher_state, mock_run) -> None:
        dispatcher_broker = Mock()

        tiberos_snapshot = TiberOSSnapshot(Mock(), "command", dispatcher_broker, "1", True, True)
        with self.assertRaises(SotaError):
            tiberos_snapshot.commit()
        mock_run.assert_called_once()
        assert mock_dispatcher_state.clear_dispatcher_state.call_count == 1

    @patch('dispatcher.sota.snapshot.dispatcher_state', autospec=True)
    def test_recover_success(self, mock_dispatcher_state) -> None:
        rebooter = Mock()
        tiberos_snapshot = TiberOSSnapshot(Mock(), "command", Mock(), "1", True, True)
        tiberos_snapshot.recover(rebooter, 1)
        assert mock_dispatcher_state.clear_dispatcher_state.call_count == 1
        assert rebooter.reboot.call_count == 1

    @patch('dispatcher.sota.snapshot.dispatcher_state', autospec=True)
    def test_revert_success(self, mock_dispatcher_state) -> None:
        rebooter = Mock()
        tiberos_snapshot = TiberOSSnapshot(Mock(), "command", Mock(), "1", True, True)
        tiberos_snapshot.revert(rebooter, 1)
        assert mock_dispatcher_state.clear_dispatcher_state.call_count == 1
        assert rebooter.reboot.call_count == 1

    @patch("inbm_common_lib.shell_runner.PseudoShellRunner.run", return_value=('2c26b46b68ffc68ff99b453c1d30413413422d706483bfa0f98a5e886266e7ae', "", 0))
    @patch('dispatcher.common.dispatcher_state.consume_dispatcher_state_file',
           return_value={'restart_reason': 'sota', 'tiberos-version': '2c26b46b68ffc68ff99b453c1d30413413422d706483bfa0f98a5e886266e7ae'})
    def test_update_system_raise_error_when_versions_are_same(self, mock_consume_disp_state, mock_run) -> None:
        rebooter = Mock()
        tiberos_snapshot = TiberOSSnapshot(Mock(), "command", Mock(), "1", True, True)
        with self.assertRaises(SotaError):
            tiberos_snapshot.update_system()
        mock_consume_disp_state.assert_called_once()
        mock_run.assert_called_once()