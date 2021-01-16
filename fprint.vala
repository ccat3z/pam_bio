// generated from fprintd 1.90.8
using GLib;

namespace net {
	namespace reactivated {
		namespace Fprint {
			[DBus (name = "net.reactivated.Fprint.Manager", timeout = 120000)]
			public interface Manager : GLib.Object {

				[DBus (name = "GetDevices")]
				public abstract GLib.ObjectPath[] get_devices() throws DBusError, IOError;

				[DBus (name = "GetDefaultDevice")]
				public abstract GLib.ObjectPath get_default_device() throws DBusError, IOError;
			}
			
			[DBus (name = "net.reactivated.Fprint.Device", timeout = 120000)]
			public interface Device : GLib.Object {

				[DBus (name = "ListEnrolledFingers")]
				public abstract string[] list_enrolled_fingers(string username) throws DBusError, IOError;

				[DBus (name = "DeleteEnrolledFingers")]
				public abstract void delete_enrolled_fingers(string username) throws DBusError, IOError;

				[DBus (name = "DeleteEnrolledFingers2")]
				public abstract void delete_enrolled_fingers2() throws DBusError, IOError;

				[DBus (name = "Claim")]
				public abstract void claim(string username) throws DBusError, IOError;

				[DBus (name = "Release")]
				public abstract void release() throws DBusError, IOError;

				[DBus (name = "VerifyStart")]
				public abstract void verify_start(string finger_name) throws DBusError, IOError;

				[DBus (name = "VerifyStop")]
				public abstract void verify_stop() throws DBusError, IOError;

				[DBus (name = "VerifyFingerSelected")]
				public signal void verify_finger_selected(string finger_name);

				[DBus (name = "VerifyStatus")]
				public signal void verify_status(string result_, bool done);

				[DBus (name = "EnrollStart")]
				public abstract void enroll_start(string finger_name) throws DBusError, IOError;

				[DBus (name = "EnrollStop")]
				public abstract void enroll_stop() throws DBusError, IOError;

				[DBus (name = "EnrollStatus")]
				public signal void enroll_status(string result_, bool done);

				[DBus (name = "name")]
				public abstract string name { owned get; }

				[DBus (name = "num-enroll-stages")]
				public abstract int num_enroll_stages { get; }

				[DBus (name = "scan-type")]
				public abstract string scan_type { owned get; }
			}
		}
	}
}
