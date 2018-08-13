const util = require("util");
const spawn = require("child_process").spawn;
const intoStream = require("into-stream");

// Expose methods.
exports.sign = sign;
exports.encrypt = encrypt;
exports.decrypt = decrypt;

/**
 * Sign a file.
 *
 * @param {object} options Options
 * @param {stream.Readable} options.content Content stream
 * @param {string} options.key Key path
 * @param {string} options.cert Cert path
 * @param {string} [options.password] Key password
 * @returns {object} result Result
 * @returns {string} result.der Der signature
 * @returns {ChildProcess} result.child Child process
 */

function sign(options) {
  return new Promise((resolve, reject) => {
    options = options || {};

    if (!options.content) {
      throw new Error("Invalid content.");
    }

    if (!options.key) {
      throw new Error("Invalid key.");
    }

    if (!options.cert) {
      throw new Error("Invalid certificate.");
    }

    let command = util.format(
      "openssl smime -sign -text -signer %s -inkey %s -outform DER -binary",
      options.cert,
      options.key
    );

    if (options.password) {
      command += util.format(" -passin pass:%s", options.password);
    }

    const args = command.split(" ");
    const child = spawn(args[0], args.splice(1));

    const der = [];

    child.stdout.on("data", chunk => {
      der.push(chunk);
    });

    child.on("close", code => {
      if (code !== 0) {
        return reject(new Error("Process failed."));
      }

      resolve({
        child: child,
        der: Buffer.concat(der)
      });
    });

    options.content.pipe(child.stdin);
  });
}

function encrypt(options) {
  return new Promise((resolve, reject) => {
    options = options || {};

    if (!options.content) throw new Error("Invalid content.");

    if (!options.keys) throw new Error("Invalid keys.");

    const command = util.format(
      "openssl smime -noattr -encrypt -aes-256-cbc -outform PEM -binary %s",
      options.keys
    );

    console.log(`Encrypt ${command}`);

    const args = command.split(" ");
    const child = spawn(args[0], args.splice(1));

    let der = "";

    child.stdout.on("data", chunk => {
      der += chunk;
    });

    child.stderr.on("data", chunk => {
      console.log(chunk);
    });

    child.on("close", code => {
      if (code !== 0) {
        return reject(new Error("Process failed."));
      }

      return resolve({
        child: child,
        der: Buffer.from(der)
      });
    });

    options.content.pipe(child.stdin);
  });
}

function decrypt(options) {
  return new Promise((resolve, reject) => {
    options = options || {};

    if (!options.content) {
      return reject(new Error("Invalid content."));
    }

    if (!Buffer.isBuffer(options.content)) {
      return reject(new Error("content is not a buffer."));
    }

    if (!options.key) {
      return reject(new Error("Invalid key."));
    }

    const command = util.format(
      "openssl smime -decrypt -inform PEM -inkey %s",
      options.key
    );

    const args = command.split(" ");
    const child = spawn(args[0], args.splice(1));

    let der = "";

    child.stdout.on("data", chunk => {
      der += chunk;
    });

    child.on("close", code => {
      if (code !== 0) {
        reject(new Error("Process failed."));
      } else {
        resolve({
          child: child,
          content: Buffer.from(der)
        });
      }
    });

    intoStream(options.content).pipe(child.stdin);
  });
}
