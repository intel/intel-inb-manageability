import unittest

from ..common.mock_resources import *
from ddt import data, ddt, unpack
from mock import mock_open, patch, Mock

from dispatcher.dispatcher_exception import DispatcherException
from dispatcher.sota.sota_error import SotaError
from dispatcher.sota.os_factory import ISotaOs, DebianBasedSnapshot, YoctoSnapshot, SotaOsFactory


@ddt
class TestSnapshot(unittest.TestCase):

    class DispatcherTelemetry:

        def telemetry(self, s):
            pass
    dispatcher_telemetry = DispatcherTelemetry()

    @unpack
    @data((1, 0, ""), (2, '1', ""))
    @patch("inbm_lib.trtl.Trtl.delete_snapshot")
    def test_ubuntu_delete_snap(self, order, rc, err, mock_del_snap):
        factory = SotaOsFactory(
            MockDispatcherCallbacks.build_mock_dispatcher_callbacks(), None, []).get_os('Ubuntu')
        snapshot = factory.create_snapshotter("update", '1', False)
        mock_del_snap.return_value = (rc, err)
        val = snapshot.commit()
        mock_del_snap.assert_called_once()
        if order == 2:
            self.assertNotEquals(val, 0)
        if order == 1:
            self.assertEquals(val, 0)

    @unpack
    @data((1, "0", ""), (2, "1", "err"))
    @patch("inbm_lib.trtl.Trtl.single_snapshot", return_value=('', 'ERROR'))
    @patch("pickle.dump")
    def test_ubuntu_snapshot(self, order, rc, err, mock_pickle_dump, mock_trtl_single_snapshot):
        factory = SotaOsFactory(
            MockDispatcherCallbacks.build_mock_dispatcher_callbacks(), None, []).get_os('Ubuntu')
        snapshot = factory.create_snapshotter("update", '1', False)
        with patch('builtins.open', new_callable=mock_open()) as m:
            if order == 1:
                mock_trtl_single_snapshot.return_value = (rc, err)
                snapshot.take_snapshot()
                mock_pickle_dump.assert_called_once()
            else:
                self.assertRaises(SotaError, snapshot.take_snapshot)

    @unpack
    @data((1, "err"))
    @patch("inbm_lib.trtl.Trtl.single_snapshot")
    @patch("pickle.dump", side_effect=Exception('foo'))
    def test_Ubuntu_snapshot_raises1(self, rc, err, mock_pickle_dump, mock_trtl_single_snapshot):
        factory = SotaOsFactory(
            MockDispatcherCallbacks.build_mock_dispatcher_callbacks(), None, []).get_os('Ubuntu')
        snapshot = factory.create_snapshotter("update", '1', False)
        with patch('builtins.open', new_callable=mock_open()) as m:
            mock_trtl_single_snapshot.return_value = (rc, err)
            with self.assertRaises(SotaError):
                snapshot.take_snapshot()
                mock_pickle_dump.assert_called_once()

    @unpack
    @data((1, "err"))
    @patch("inbm_lib.trtl.Trtl.single_snapshot")
    def test_Ubuntu_snapshot_raises2(self, rc, err, mock_trtl_single_snapshot):
        with patch('builtins.open', new_callable=mock_open()) as m:
            factory = SotaOsFactory(
                MockDispatcherCallbacks.build_mock_dispatcher_callbacks(), None, []).get_os('Ubuntu')
            snapshot = factory.create_snapshotter("update", '1', False)
            mock_trtl_single_snapshot.return_value = (rc, err)
            try:
                snapshot.take_snapshot()
            except:
                mock_trtl_single_snapshot.assert_called_once()


class TestUbuntuSnapshot(unittest.TestCase):

    def test_take_snapshot_proceed_fail_publishes_error_succeeds(self):
        dispatcher_callbacks = Mock()
        dispatcher_callbacks.broker_core = Mock()
        trtl = Mock()
        trtl.single_snapshot.return_value = "1", "Error!"

        ubuntu_snapshot = DebianBasedSnapshot(trtl, "command", dispatcher_callbacks, "1", True)
        ubuntu_snapshot.take_snapshot()
        assert dispatcher_callbacks.broker_core.telemetry.call_count > 0

        args, _ = dispatcher_callbacks.broker_core.telemetry.call_args
        message, = args
        self.assertIn("will proceed without", message)

    @patch('dispatcher.sota.snapshot.dispatcher_state', autospec=True)
    def test_take_snapshot_proceed_cannot_write_publishes_error_succeeds(self, mock_dispatcher_state):
        dispatcher_callbacks = Mock()
        dispatcher_callbacks.broker_core = Mock()
        trtl = Mock()
        trtl.single_snapshot.return_value = "1", None

        ubuntu_snapshot = DebianBasedSnapshot(trtl, "command", dispatcher_callbacks, "1", True)
        ubuntu_snapshot.take_snapshot()

        assert dispatcher_callbacks.broker_core.telemetry.call_count > 0
        (message,), _ = dispatcher_callbacks.broker_core.telemetry.call_args
        self.assertIn("succeeded", message)

    def test_rollback_and_delete_snap_skipped_succeeds(self):
        dispatcher_callbacks = Mock()
        dispatcher_callbacks.broker_core = Mock()
        trtl = Mock()

        ubuntu_snapshot = DebianBasedSnapshot(trtl, "command", dispatcher_callbacks, "", True)
        ubuntu_snapshot._rollback_and_delete_snap()

        assert dispatcher_callbacks.broker_core.telemetry.call_count > 0
        args, _ = dispatcher_callbacks.broker_core.telemetry.call_args
        message, = args
        assert "skipped" in message

    @patch('dispatcher.sota.snapshot.dispatcher_state', autospec=True)
    def test_revert_succeeds(self, mock_dispatcher_state):
        rebooter = Mock()
        ubuntu_snapshot = DebianBasedSnapshot(Mock(), "command", Mock(), "", True)
        ubuntu_snapshot._rollback_and_delete_snap = Mock()  # type: ignore
        ubuntu_snapshot.snap_num = "1"
        ubuntu_snapshot.revert(rebooter, 0)  # type: ignore
        assert mock_dispatcher_state.clear_dispatcher_state.call_count == 1
        self.assertEqual(ubuntu_snapshot._rollback_and_delete_snap.call_count, 1)  # type: ignore
        assert rebooter.reboot.call_count == 1


class TestYoctoSnapshot(unittest.TestCase):

    @patch('dispatcher.sota.snapshot.dispatcher_state', autospec=True)
    @patch('dispatcher.sota.snapshot.read_current_mender_version', autospec=True)
    def test_take_snapshot_succeeds(self, mock_mender_version, mock_dispatcher_state):
        mock_mender_version.return_value = "foo"
        mock_dispatcher_state.write_dispatcher_state_to_state_file.return_value = True
        dispatcher_callbacks = Mock()
        dispatcher_callbacks.broker_core = Mock()

        yocto_snapshot = YoctoSnapshot(Mock(), "command", dispatcher_callbacks, "1", True)
        yocto_snapshot.take_snapshot()

        assert dispatcher_callbacks.broker_core.telemetry.call_count > 0
        args, _ = dispatcher_callbacks.broker_core.telemetry.call_args
        message, = args
        assert "unsuccessful" not in message

    @patch('dispatcher.sota.snapshot.read_current_mender_version', return_value='abc')
    @patch('dispatcher.common.dispatcher_state.is_dispatcher_state_file_exists', return_value=True)
    @patch('dispatcher.common.dispatcher_state.consume_dispatcher_state_file',
           return_value={'restart_reason': 'sota_upgrade'})
    @patch('dispatcher.common.dispatcher_state.write_dispatcher_state_to_state_file')
    def test_dispatcher_state_file_exist_consume_called_sota(self, mock_write_state_file, mock_disp_state_file_exist, mock_consume_disp_file, mock_read_mender):
        dispatcher_callbacks = Mock()
        dispatcher_callbacks.broker_core = Mock()

        yocto_snapshot = YoctoSnapshot(Mock(), "command", dispatcher_callbacks, "1", True)
        yocto_snapshot.take_snapshot()
        mock_consume_disp_file.assert_called_once()
        mock_write_state_file.assert_called_once()

    @patch('dispatcher.sota.snapshot.read_current_mender_version', return_value='abc')
    @patch('dispatcher.common.dispatcher_state.is_dispatcher_state_file_exists', return_value=False)
    @patch('dispatcher.common.dispatcher_state.consume_dispatcher_state_file',
           return_value={'restart_reason': 'sota_upgrade'})
    @patch('dispatcher.common.dispatcher_state.write_dispatcher_state_to_state_file')
    def test_dispatcher_state_file_not_exist_consume_not_called_sota(self, mock_write_state_file, mock_consume_disp_file, mock_disp_state_file_exist, mock_read_mender):
        dispatcher_callbacks = Mock()
        dispatcher_callbacks.broker_core = Mock()

        yocto_snapshot = YoctoSnapshot(Mock(), "command", dispatcher_callbacks, "1", True)
        yocto_snapshot.take_snapshot()
        mock_consume_disp_file.assert_not_called()
        mock_write_state_file.assert_called_once()

    @patch('dispatcher.sota.snapshot.dispatcher_state', autospec=True)
    @patch('dispatcher.sota.snapshot.read_current_mender_version', return_value='abc')
    def test_raise_when_unable_to_write_file(
            self, mock_read_mender_ver, mock_dispatcher_state):
        mock_dispatcher_state.write_dispatcher_state_to_state_file.side_effect = DispatcherException(
            'Error')
        dispatcher_callbacks = Mock()
        dispatcher_callbacks.broker_core = Mock()

        yocto_snapshot = YoctoSnapshot(Mock(), "command", dispatcher_callbacks, "1", True)
        failed = False
        try:
            yocto_snapshot.take_snapshot()
        except SotaError:
            failed = True

        assert failed
        assert dispatcher_callbacks.broker_core.telemetry.call_count > 0
        args, _ = dispatcher_callbacks.broker_core.telemetry.call_args
        message, = args
        assert "unsuccessful" in message
