const expect = require("chai").expect;
const fs = require("fs");
const path = require("path");
const smime = require("../");

describe("Smime", () => {
  describe("#sign", () => {
    it("should return an error if there is no content", () => {
      return smime
        .sign({
          key: path.join(__dirname, "key.pem"),
          cert: path.join(__dirname, "certificate.pem")
        })
        .catch(err => {
          expect(err.message).to.equal("Invalid content.");
        });
    });

    it("should return an error if there is no key", () => {
      return smime
        .sign({
          content: fs.createReadStream(path.join(__dirname, "file-to-sign")),
          cert: path.join(__dirname, "certificate.pem")
        })
        .catch(err => {
          expect(err.message).to.equal("Invalid key.");
        });
    });

    it("should return an error if there is no cert", () => {
      return smime
        .sign({
          content: fs.createReadStream(path.join(__dirname, "file-to-sign")),
          key: path.join(__dirname, "key.pem")
        })
        .catch(err => {
          expect(err.message).to.equal("Invalid certificate.");
        });
    });

    it("should sign a content", () => {
      return smime
        .sign({
          content: fs.createReadStream(path.join(__dirname, "file-to-sign")),
          key: path.join(__dirname, "key.pem"),
          cert: path.join(__dirname, "certificate.pem")
        })
        .then(res => {
          expect(res).to.have.property("der");
          expect(res).to.have.property("child");
        });
    });

    it("should work with password", () => {
      return smime
        .sign({
          content: fs.createReadStream(path.join(__dirname, "file-to-sign")),
          key: path.join(__dirname, "key.pem"),
          cert: path.join(__dirname, "certificate.pem"),
          password: "x"
        })
        .then(res => {
          expect(res).to.have.property("der");
          expect(res).to.have.property("child");
        });
    });
  });

  describe("#encrypt", () => {
    it("should return an error if there is no content", () => {
      return smime
        .encrypt({
          keys: [path.join(__dirname, "key.pem")]
        })
        .catch(err => {
          expect(err.message).to.equal("Invalid content.");
        });
    });

    it("should return an error if there is no keys", () => {
      return smime
        .encrypt({
          content: fs.createReadStream(path.join(__dirname, "file-to-sign"))
        })
        .catch(err => {
          expect(err.message).to.equal("Invalid keys.");
        });
    });

    it("should encrypt a content", () => {
      return smime
        .encrypt({
          content: fs.createReadStream(path.join(__dirname, "file-to-sign")),
          keys: [path.join(__dirname, "certificate.pem")]
        })
        .then(res => {
          expect(res).to.have.property("der");
          expect(res).to.have.property("child");
        });
    });
  });

  describe("#decrypt", () => {
    it("should return an error if there is no content", () => {
      return smime
        .decrypt({
          keys: [path.join(__dirname, "key.pem")]
        })
        .catch(err => {
          expect(err.message).to.equal("Invalid content.");
        });
    });

    it("should return an error if there is no keys", () => {
      return smime
        .decrypt({
          content: Buffer.from("")
        })
        .catch(err => {
          expect(err.message).to.equal("Invalid key.");
        });
    });

    it("should return an error if content is not a buffer", () => {
      return smime
        .decrypt({
          content: fs.createReadStream(path.join(__dirname, "file-to-sign"))
        })
        .catch(err => {
          expect(err.message).to.equal("content is not a buffer.");
        });
    });

    it("should decrypt a content", () => {
      const enc = smime.encrypt({
        content: fs.createReadStream(path.join(__dirname, "file-to-sign")),
        keys: [path.join(__dirname, "certificate.pem")]
      });

      enc.then((res) => {
        return smime.decrypt({
          content: res.der,
          key: path.join(__dirname, "key.pem")
        });
      }).then((res) => {
        expect(res).to.have.property("content");
        expect(res).to.have.property("child");
        const content = fs.readFileSync(path.join(__dirname, "file-to-sign"));
        expect(res.content.toString()).to.be.equal(content.toString());
      });
    });
  });
});