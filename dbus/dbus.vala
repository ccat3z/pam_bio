/* Generated by vala-dbus-binding-tool 1.0-aa2fb. Do not modify! */
/* Generated with: vala-dbus-binding-tool --api-path=/tmp/dbus.xml */
using GLib;

namespace org {

	namespace freedesktop {

		[DBus (name = "org.freedesktop.DBus", timeout = 120000)]
		public interface DBus : GLib.Object {

			[DBus (name = "Hello")]
			public abstract string hello() throws DBusError, IOError;

			[DBus (name = "RequestName")]
			public abstract uint request_name(string param0, uint param1) throws DBusError, IOError;

			[DBus (name = "ReleaseName")]
			public abstract uint release_name(string param0) throws DBusError, IOError;

			[DBus (name = "StartServiceByName")]
			public abstract uint start_service_by_name(string param0, uint param1) throws DBusError, IOError;

			[DBus (name = "UpdateActivationEnvironment")]
			public abstract void update_activation_environment(GLib.HashTable<string, string> param0) throws DBusError, IOError;

			[DBus (name = "NameHasOwner")]
			public abstract bool name_has_owner(string param0) throws DBusError, IOError;

			[DBus (name = "ListNames")]
			public abstract string[] list_names() throws DBusError, IOError;

			[DBus (name = "ListActivatableNames")]
			public abstract string[] list_activatable_names() throws DBusError, IOError;

			[DBus (name = "AddMatch")]
			public abstract void add_match(string param0) throws DBusError, IOError;

			[DBus (name = "RemoveMatch")]
			public abstract void remove_match(string param0) throws DBusError, IOError;

			[DBus (name = "GetNameOwner")]
			public abstract string get_name_owner(string param0) throws DBusError, IOError;

			[DBus (name = "ListQueuedOwners")]
			public abstract string[] list_queued_owners(string param0) throws DBusError, IOError;

			[DBus (name = "GetConnectionUnixUser")]
			public abstract uint get_connection_unix_user(string param0) throws DBusError, IOError;

			[DBus (name = "GetConnectionUnixProcessID")]
			public abstract uint get_connection_unix_process_id(string param0) throws DBusError, IOError;

			[DBus (name = "GetAdtAuditSessionData")]
			public abstract uint8[] get_adt_audit_session_data(string param0) throws DBusError, IOError;

			[DBus (name = "GetConnectionSELinuxSecurityContext")]
			public abstract uint8[] get_connection_s_e_linux_security_context(string param0) throws DBusError, IOError;

			[DBus (name = "ReloadConfig")]
			public abstract void reload_config() throws DBusError, IOError;

			[DBus (name = "GetId")]
			public abstract string get_id() throws DBusError, IOError;

			[DBus (name = "GetConnectionCredentials")]
			public abstract GLib.HashTable<string, GLib.Variant> get_connection_credentials(string param0) throws DBusError, IOError;

			[DBus (name = "Features")]
			public abstract string[] features { owned get; }

			[DBus (name = "Interfaces")]
			public abstract string[] interfaces { owned get; }

			[DBus (name = "NameOwnerChanged")]
			public signal void name_owner_changed(string param0, string param1, string param2);

			[DBus (name = "NameLost")]
			public signal void name_lost(string param0);

			[DBus (name = "NameAcquired")]
			public signal void name_acquired(string param0);
		}

		[DBus (name = "org.freedesktop.DBus", timeout = 120000)]
		public interface DBusSync : GLib.Object {

			[DBus (name = "Hello")]
			public abstract string hello() throws DBusError, IOError;

			[DBus (name = "RequestName")]
			public abstract uint request_name(string param0, uint param1) throws DBusError, IOError;

			[DBus (name = "ReleaseName")]
			public abstract uint release_name(string param0) throws DBusError, IOError;

			[DBus (name = "StartServiceByName")]
			public abstract uint start_service_by_name(string param0, uint param1) throws DBusError, IOError;

			[DBus (name = "UpdateActivationEnvironment")]
			public abstract void update_activation_environment(GLib.HashTable<string, string> param0) throws DBusError, IOError;

			[DBus (name = "NameHasOwner")]
			public abstract bool name_has_owner(string param0) throws DBusError, IOError;

			[DBus (name = "ListNames")]
			public abstract string[] list_names() throws DBusError, IOError;

			[DBus (name = "ListActivatableNames")]
			public abstract string[] list_activatable_names() throws DBusError, IOError;

			[DBus (name = "AddMatch")]
			public abstract void add_match(string param0) throws DBusError, IOError;

			[DBus (name = "RemoveMatch")]
			public abstract void remove_match(string param0) throws DBusError, IOError;

			[DBus (name = "GetNameOwner")]
			public abstract string get_name_owner(string param0) throws DBusError, IOError;

			[DBus (name = "ListQueuedOwners")]
			public abstract string[] list_queued_owners(string param0) throws DBusError, IOError;

			[DBus (name = "GetConnectionUnixUser")]
			public abstract uint get_connection_unix_user(string param0) throws DBusError, IOError;

			[DBus (name = "GetConnectionUnixProcessID")]
			public abstract uint get_connection_unix_process_i_d(string param0) throws DBusError, IOError;

			[DBus (name = "GetAdtAuditSessionData")]
			public abstract uint8[] get_adt_audit_session_data(string param0) throws DBusError, IOError;

			[DBus (name = "GetConnectionSELinuxSecurityContext")]
			public abstract uint8[] get_connection_s_e_linux_security_context(string param0) throws DBusError, IOError;

			[DBus (name = "ReloadConfig")]
			public abstract void reload_config() throws DBusError, IOError;

			[DBus (name = "GetId")]
			public abstract string get_id() throws DBusError, IOError;

			[DBus (name = "GetConnectionCredentials")]
			public abstract GLib.HashTable<string, GLib.Variant> get_connection_credentials(string param0) throws DBusError, IOError;

			[DBus (name = "Features")]
			public abstract string[] features { owned get; }

			[DBus (name = "Interfaces")]
			public abstract string[] interfaces { owned get; }

			[DBus (name = "NameOwnerChanged")]
			public signal void name_owner_changed(string param0, string param1, string param2);

			[DBus (name = "NameLost")]
			public signal void name_lost(string param0);

			[DBus (name = "NameAcquired")]
			public signal void name_acquired(string param0);
		}

		[DBus (name = "org.freedesktop.DBus.Introspectable", timeout = 120000)]
		public interface DBusIntrospectable : GLib.Object {

			[DBus (name = "Introspect")]
			public abstract string introspect() throws DBusError, IOError;
		}

		[DBus (name = "org.freedesktop.DBus.Introspectable", timeout = 120000)]
		public interface DBusIntrospectableSync : GLib.Object {

			[DBus (name = "Introspect")]
			public abstract string introspect() throws DBusError, IOError;
		}

		[DBus (name = "org.freedesktop.DBus.Debug.Stats", timeout = 120000)]
		public interface DBusDebugStats : GLib.Object {

			[DBus (name = "GetStats")]
			public abstract GLib.HashTable<string, GLib.Variant> get_stats() throws DBusError, IOError;

			[DBus (name = "GetConnectionStats")]
			public abstract GLib.HashTable<string, GLib.Variant> get_connection_stats(string param0) throws DBusError, IOError;

			//  [DBus (name = "GetAllMatchRules")]
			//  public abstract GLib.HashTable<string, string[]> get_all_match_rules() throws DBusError, IOError;
		}

		[DBus (name = "org.freedesktop.DBus.Debug.Stats", timeout = 120000)]
		public interface DBusDebugStatsSync : GLib.Object {

			[DBus (name = "GetStats")]
			public abstract GLib.HashTable<string, GLib.Variant> get_stats() throws DBusError, IOError;

			[DBus (name = "GetConnectionStats")]
			public abstract GLib.HashTable<string, GLib.Variant> get_connection_stats(string param0) throws DBusError, IOError;

			//  [DBus (name = "GetAllMatchRules")]
			//  public abstract GLib.HashTable<string, string[]> get_all_match_rules() throws DBusError, IOError;
		}

		[DBus (name = "org.freedesktop.DBus.Monitoring", timeout = 120000)]
		public interface DBusMonitoring : GLib.Object {

			[DBus (name = "BecomeMonitor")]
			public abstract void become_monitor(string[] param0, uint param1) throws DBusError, IOError;
		}

		[DBus (name = "org.freedesktop.DBus.Monitoring", timeout = 120000)]
		public interface DBusMonitoringSync : GLib.Object {

			[DBus (name = "BecomeMonitor")]
			public abstract void become_monitor(string[] param0, uint param1) throws DBusError, IOError;
		}

		[DBus (name = "org.freedesktop.DBus.Peer", timeout = 120000)]
		public interface DBusPeer : GLib.Object {

			[DBus (name = "GetMachineId")]
			public abstract string get_machine_id() throws DBusError, IOError;

			[DBus (name = "Ping")]
			public abstract void ping() throws DBusError, IOError;
		}

		[DBus (name = "org.freedesktop.DBus.Peer", timeout = 120000)]
		public interface DBusPeerSync : GLib.Object {

			[DBus (name = "GetMachineId")]
			public abstract string get_machine_id() throws DBusError, IOError;

			[DBus (name = "Ping")]
			public abstract void ping() throws DBusError, IOError;
		}

		[DBus (name = "org.freedesktop.DBus.Properties", timeout = 120000)]
		public interface DBusProperties : GLib.Object {

			[DBus (name = "Get")]
			public abstract GLib.Variant get(string param0, string param1) throws DBusError, IOError;

			[DBus (name = "GetAll")]
			public abstract GLib.HashTable<string, GLib.Variant> get_all(string param0) throws DBusError, IOError;

			[DBus (name = "Set")]
			public abstract void set(string param0, string param1, GLib.Variant param2) throws DBusError, IOError;

			[DBus (name = "PropertiesChanged")]
			public signal void properties_changed(string interface_name, GLib.HashTable<string, GLib.Variant> changed_properties, string[] invalidated_properties);
		}

		[DBus (name = "org.freedesktop.DBus.Properties", timeout = 120000)]
		public interface DBusPropertiesSync : GLib.Object {

			[DBus (name = "Get")]
			public abstract GLib.Variant get(string param0, string param1) throws DBusError, IOError;

			[DBus (name = "GetAll")]
			public abstract GLib.HashTable<string, GLib.Variant> get_all(string param0) throws DBusError, IOError;

			[DBus (name = "Set")]
			public abstract void set(string param0, string param1, GLib.Variant param2) throws DBusError, IOError;

			[DBus (name = "PropertiesChanged")]
			public signal void properties_changed(string interface_name, GLib.HashTable<string, GLib.Variant> changed_properties, string[] invalidated_properties);
		}
	}
}