using GLib;
using Pam;

namespace net {
	namespace reactivated {
		namespace Fprint {
			public errordomain FprintError {
				DEVICE_NOT_FOUND,
				NO_ENROLLED_FINGERPRINT
			}

			public class FprintAuthentication : Object, Authentication {
				private AuthenticateContext ctx;

				public FprintAuthentication(AuthenticateContext ctx) {
					this.ctx = ctx;
				}

				public string name { owned get { return "fprintd"; } }

				private async Fprint.Device findDevice(Cancellable? cancellable) throws FprintError, IOError, DBusError {
					if (cancellable.is_cancelled())
						throw new IOError.CANCELLED("cancelled");

					string user = ctx.username;
					Fprint.Manager manager = yield Bus.get_proxy(BusType.SYSTEM, "net.reactivated.Fprint", "/net/reactivated/Fprint/Manager", DBusProxyFlags.NONE, cancellable);
					var paths = manager.get_devices();

					Fprint.Device? targetDevice = null;
					int maxFingers = -1;
					foreach (var path in paths) {
						Fprint.Device device = yield Bus.get_proxy(BusType.SYSTEM, "net.reactivated.Fprint", path, DBusProxyFlags.NONE, cancellable);
						if (device.list_enrolled_fingers(user).length > maxFingers) {
							targetDevice = device;
						} 
					}

					if (targetDevice == null)
						throw new FprintError.DEVICE_NOT_FOUND("cannot find fprint device");

					if (maxFingers == 0)
						throw new FprintError.NO_ENROLLED_FINGERPRINT("no enrolled fingerprint");

					return targetDevice;
				}

				private async bool verify(Device device, Cancellable? cancellable) throws Error {
					if (cancellable.is_cancelled())
						throw new IOError.CANCELLED("cancelled");

					ctx.log_debug("fprint: start verify fingerprint");

					var resume_cb_mutex = Mutex();
					SourceFunc resume_cb = () => {
						// skip if callback was invoked
						if (resume_cb_mutex.trylock()) {
							Idle.add(verify.callback);
						} 
						return true;
					};

					string verify_res = "null";
					bool verify_done = false;
					var verify_status_sig = device.verify_status.connect((status, done) => {
						verify_res = status;
						verify_done = done;
						resume_cb();
					});
					var cancel_sig = cancellable != null ? cancellable.connect(() => resume_cb()) : 0; 

					device.verify_start("any");
					do {
						yield;
						resume_cb_mutex.unlock();

						ctx.log_debug(@"fprint: result=$(verify_res) done=$(verify_done)");
						if (verify_res == "verify-swipe-too-short") {
							ctx.conv_info("Swipe too short!");
						}
					} while (!verify_done && !cancellable.is_cancelled());

					ctx.log_debug("fprint: verify stopped");
					device.disconnect(verify_status_sig);
					cancellable.disconnect(cancel_sig);
					device.verify_stop();

					if (cancellable.is_cancelled())
						throw new IOError.CANCELLED("cancelled");

					return verify_res == "verify-match";
				}

				public async AuthenticateResult auth(Cancellable? cancellable) throws Error {
					if (cancellable.is_cancelled())
						throw new IOError.CANCELLED("cancelled");

					var device = yield findDevice(cancellable);
					ctx.log_debug(@"fprint: using device $(device.name)");

					var username = ctx.username;
					ctx.log_debug("fprint: claim device");
					device.claim(username);

					try {
						var tries = 3;
						while (tries-- > 0) {
							if (yield verify(device, cancellable)) {
								return AuthenticateResult.SUCCESS;
							}
							ctx.conv_err(@"Fingerprint not match. $tries chance left.");
						}
						return AuthenticateResult.MAXTRIES;
					} finally {
						ctx.log_debug("fprint: release device");
						try {
							device.release();
						} catch (Error e) {
							ctx.log_err(@"fprint: failed to release device: $(e.message)");
						}
					}
				}
			}

			// generated from fprintd 1.90.8
			[DBus (name = "net.reactivated.Fprint.Manager", timeout = 120000)]
			private interface Manager : GLib.Object {
				[DBus (name = "GetDevices")]
				public abstract GLib.ObjectPath[] get_devices() throws DBusError, IOError;

				[DBus (name = "GetDefaultDevice")]
				public abstract GLib.ObjectPath get_default_device() throws DBusError, IOError;
			}
			
			// generated from fprintd 1.90.8
			[DBus (name = "net.reactivated.Fprint.Device", timeout = 120000)]
			private interface Device : GLib.Object {
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
