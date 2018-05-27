# coding: utf-8
from __future__ import with_statement

import unittest

from mock import patch
from fabobjects.utils import _print

patch('fabobjects.utils.server_host_manager', _print).start()
patch('fabric.operations.sudo', _print).start()

# import classes after patching parts that make ssh calls
from fabobjects.distros import BaseServer, BSD, Debian, RedHat


class BaseServerTestCase(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.base_server = BaseServer(ip="127.0.0.1", user="tester", ssh_port=2222,
                                     domain_name="example.com", hostname="test",
                                     password="123456")

    def test__repr__(self):
        self.assertTrue(hasattr(self.base_server, "__repr__"))
        self.assertTrue(type(self.base_server.__repr__()) == str)

    def test__str__(self):
        self.assertTrue(hasattr(self.base_server, "__str__"))
        self.assertTrue(type(self.base_server.__repr__()) == str)

    def test_getattribute(self):
        result = self.base_server.getattribute("__str__")
        self.assertTrue(result, str(self.base_server))

    def test__list_funs(self):
        methods = self.base_server.getattribute("_list_funs")
        self.assertIsInstance(methods, list)

    def test_get_package_manager(self):
        self.assertRaises(NotImplementedError, self.base_server.get_package_manager)

    def test_run_in_background(self):
        pass

    def test_get_mac_address(self):
        pass

    def test_get_installation_date(self):
        pass

    def test_get_ip_command(self):
        pass

    def test_get_password(self):
        self.assertTrue(self.base_server.get_password == "123456")

    def test_hostname(self):
        pass

    def test__host(self):
        pass

    def test_os_name(self):
        pass

    def test_os(self):
        pass

    def test_clear_screen(self):
        pass

    def test_ping(self):
        pass

    def test_kill_process_by(self):
        pass

    def test_install_package(self):
        pass

    def test_is_package_installed(self):
        pass

    def test___install(self):
        pass

    def test_service(self):
        pass

    def test_service_reload(self):
        pass

    def test_service_start(self):
        pass

    def test_service_stop(self):
        pass

    def test_service_restart(self):
        pass

    def test_service_status(self):
        pass

    def test_configure_supervisor(self):
        pass

    def test_reread_supervisor_conf(self):
        pass

    def test_supervisorctl(self):
        pass

    def test_list_files_with_no_owner(self):
        pass

    def test_list_world_writable_files(self):
        pass

    def test_free_inactive_memory(self):
        pass

    def test_used_memory(self):
        pass

    def test_sys_memory(self):
        pass

    def test_free_memory(self):
        pass

    def test_cpu_number(self):
        pass

    def test_get_ip(self):
        pass

    def test_install_bower(self):
        pass

    def test__get_home_dir(self):
        pass

    def test_show_public_key(self):
        pass

    def test_generate_self_signed_ssl(self):
        pass

    def test_disable_root_login(self):
        pass

    def test_fqdn(self):
        pass

    def test___set_kernel_domain_name(self):
        pass

    def test___set_hostname(self):
        pass

    def test_set_host(self):
        pass

    def test_change_named_servers(self):
        pass

    def test_ip_spoofing_guard(self):
        pass

    def test_limit_sudo_users(self):
        pass

    def test_harden_host_files(self):
        pass

    def test_other_sys_security(self):
        pass

    def test_harden_sshd(self):
        pass

    def test_tune_network_stack(self):
        pass

    def test_disable_usb_stick_to_detect(self):
        pass

    def test_check_opened_ports(self):
        pass

    def test_install_fail2ban(self):
        pass

    def test_install_denyhosts(self):
        pass

    def test_install_psad(self):
        pass

    def test_move_user_2_restricted_shell(self):
        pass

    def test_motd_setup(self):
        pass

    def test_rkhunter_scan(self):
        pass

    def test_rkhunter_chkrootkit(self):
        pass

    def test_setup_logwatch(self):
        pass

    def test_install_apparmor(self):
        pass

    def test_set_up_tiger(self):
        pass

    def test_view_tiger_report(self):
        pass

    def test_find_broken_symblinks_delete(self):
        pass

    def test_harden_server(self):
        pass

    def test_get_hostname(self):
        pass

    def test_get_internal_ip(self):
        pass

    def test_get_public_ip(self):
        pass

    def test_set_system_time(self):
        pass

    def test_locale_conf(self):
        pass

    def test_create_user(self):
        pass

    def test_local_user_home(self):
        pass

    def test_change_password(self):
        pass

    def test_delete_user(self):
        pass

    def test_create_restricted_user(self):
        pass

    def test_add_sshgroup(self):
        pass

    def test_create_admin_account(self):
        pass

    def test_add_user_to_sudo(self):
        pass

    def test_current_kernel(self):
        pass

    def test_memoryused(self):
        pass

    def test_uptime(self):
        self.base_server.uptime

    def test_get_hard_drive_info(self):
        pass

    def test_get_top_resource_users(self):
        pass

    def test_get_memory_use(self):
        pass

    def test_list_users_short_version(self):
        pass

    def test_list_users(self):
        pass

    def test_list_groups(self):
        pass

    def test_get_general_info(self):
        pass

    def test_remove_old_kernels(self):
        pass

    def test_shutdown(self):
        pass

    def test_rebootall(self):
        pass

    def test_update(self):
        pass

    def test_make_or_del(self):
        pass

    def test_clone_repo(self):
        pass

    def test_add_keys_to_git(self):
        pass

    def test_create_n_put_keys(self):
        pass

    def test_user_lastcomm(self):
        pass

    def test_echo(self):
        pass

    def test_secure_shared_memory(self):
        pass

    def test_firewall_status(self):
        pass

    def test_view_firewall_rules(self):
        pass

    def test_firewall_allow_form_to(self):
        pass

    def test_delete_firewall_number(self):
        pass

    def test_configure_firewall(self):
        pass

    def test_install_firewall(self):
        pass

    def test_push_key(self):
        pass

    def test_create_ssh_key(self):
        pass

    def test_generate_ssh(self):
        pass

    def test_enable_process_accounting(self):
        pass

    def test_users_connect_times(self):
        pass

    def test_users_previous_commands(self):
        pass

    def test__print(self):
        pass

    def test_print_command(self):
        pass

    def test_run(self):
        pass

    def test_execute(self):
        pass

    def test_append(self):
        pass

    def test_sudo(self):
        pass

    def test_comment(self):
        pass

    def test_uncomment(self):
        pass

    def test_dir_ensure(self):
        pass

    def test_prompt(self):
        pass

    def test_put(self):
        pass

    def test_run_as_app_user(self):
        pass

    def test_get(self):
        pass

    def test_sed(self):
        pass

    def test_postfix_conf(self):
        pass

    def test_postconf(self):
        pass

    def test_install_postfix(self):
        pass

    def test_run_as_user(self):
        pass

    def test_clean_manager(self):
        pass

    def test_send_ssh(self):
        pass


class BSDTestCase(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.base_server = BSD(ip="127.0.0.1", user="tester", ssh_port=2222,
                              domain_name="example.com", hostname="test",
                              password="123456")

    def test_distro(self):
        self.assertTrue(self.base_server.distro == 'BSD')

    def test_uninstall(self):
        pass

    def test_is_package_installed(self):
        pass

    def test_get_package_manager(self):
        self.assertEqual(self.base_server.get_package_manager(), "pkg ")

    def test_list_compilers(self):
        pass

    def test_list_installed_packages(self):
        pass


class DebianTestCase(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.base_server = Debian(ip="127.0.0.1", user="tester",
                                 ssh_port=2222, domain_name="example.com",
                                 hostname="test", password="123456")

    def test_distro(self):
        self.assertTrue(self.base_server.distro == 'Debian')

    def test_get_package_manager(self):
        self.assertEqual(self.base_server.get_package_manager(), "apt-get ")

    def test_uninstall(self):
        pass

    def test_list_compilers(self):
        pass

    def test_list_installed_packages(self):
        pass


class RedHatTestCase(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.base_server = RedHat(ip="127.0.0.1", user="tester", ssh_port=2222,
                                 domain_name="example.com", hostname="test",
                                 password="123456")

    def test_get_package_manager(self):
        self.assertEqual(self.base_server.get_package_manager(), "yum ")

    def test_uninstall_packages(self):
        pass

    def test_list_compilers(self):
        pass

    def test_list_installed_package(self):
        pass
