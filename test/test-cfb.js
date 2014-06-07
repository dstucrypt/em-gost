var assert = require("assert"),
    emgost = require("../lib/index.js");

describe("CFB", function() {
    var key = new Buffer("01000000010000000100000001000000"+
                         "ffffffffffffffffffffffffffffffff", 'hex');
    var wrap_iv = new Buffer("4adda22c79e82105", 'hex');
    var ct = new Buffer(
        "52a513f1b4172ca6b5f1b8a03ca9a4e0"+
        "acb6e00e11e5e9bcdd446222eb97238d"+
        "c3e4e24d2ec03e05a568ec51",
        "hex"
    );
    var expect_clear = (
        "765f072303863e26db11a430e9a898bd"+
        "6ffb7b460b9d365c86c2a0babf8d6ecc"+
        "adf5337d884a42a67ada77f4"
    );

    describe("decrypt_cfb()", function() {
        it("should decrypt test data from DSTSZI", function() {
            assert.equal(key.length, 32);
            assert.equal(wrap_iv.length, 8);
            assert.equal(ct.length, 44);

            var clear = new Buffer(emgost.gost_decrypt_cfb(ct, key, wrap_iv));
            assert.equal(clear.length, 44);
            assert.equal(clear.toString('hex'), expect_clear);
        });
    })
})
