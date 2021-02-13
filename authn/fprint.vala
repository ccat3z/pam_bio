using GLib;
using Pam;
using Fprint;

namespace PamBio.AuthNProviders {
	errordomain FprintError {
		DEVICE_NOT_FOUND,
		NO_ENROLLED_FINGERPRINT
	}

	class FprintAuthNProvider : Object, AuthNProvider {
		private AuthenticateContext ctx;

		public FprintAuthNProvider(AuthenticateContext ctx) {
			this.ctx = ctx;
		}

		public string name { owned get { return "fprint"; } }

		private async Device findDevice(Cancellable? cancellable) throws FprintError, IOError, DBusError {
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

		private async bool verify(Device device, Cancellable? cancellable) throws IOError, DBusError {
			if (cancellable.is_cancelled())
				throw new IOError.CANCELLED("cancelled");

			ctx.log(SysLogPriorities.DEBUG, name, "start verify fingerprint");

			var wg = new WaitGroup();

			string verify_res = "null";
			bool verify_done = false;
			var verify_status_sig = device.verify_status.connect((status, done) => {
				verify_res = status;
				verify_done = done;
				wg.finish_cb();
			});
			var cancel_sig = cancellable != null ? cancellable.connect(() => {
				wg.finish_cb();
			}) : 0; 

			device.verify_start("any");
			do {
				yield wg.wait_any();

				ctx.log(SysLogPriorities.DEBUG, name, @"result=$(verify_res) done=$(verify_done)");
				if (verify_res == "verify-swipe-too-short") {
					ctx.pamh.prompt(MessageStyle.ERROR_MSG, null, "Swipe too short!");
				}
			} while (!verify_done && !cancellable.is_cancelled());

			ctx.log(SysLogPriorities.DEBUG, name, "verify stopped");
			device.disconnect(verify_status_sig);
			cancellable.disconnect(cancel_sig);
			device.verify_stop();

			return verify_res == "verify-match";
		}

		public async AuthenticateResult auth(Cancellable? cancellable) throws Error {
			if (cancellable.is_cancelled())
				throw new IOError.CANCELLED("cancelled");

			var device = yield findDevice(cancellable);
			ctx.log(SysLogPriorities.DEBUG, name, @"using device $(device.name)");

			var username = ctx.username;
			ctx.log(SysLogPriorities.DEBUG, name, "claim device");
			device.claim(username);

			try {
				var tries = 3;
				while (tries-- > 0) {
					if (yield verify(device, cancellable)) {
						ctx.pamh.prompt(MessageStyle.TEXT_INFO, null, "Fingerprint is recognized");
						return AuthenticateResult.SUCCESS;
					}
					ctx.pamh.prompt(MessageStyle.ERROR_MSG, null, @"Fingerprint not match. $tries chance left.");
				}
				return AuthenticateResult.MAXTRIES;
			} finally {
				ctx.log(SysLogPriorities.DEBUG, name, "release device");
				try {
					device.release();
				} catch (Error e) {
					ctx.log(SysLogPriorities.ERR, name, @"failed to release device: $(e.message)");
				}
			}
		}
	}
}
