var assert = require("assert"),
    emgost = require("../lib/index.js");

describe('Hash', function() {
    describe('#compute_hash()', function() {
        it('should check hash function output value', function() {
            var input = '123';
            var expect_ret = '0d7638f766847f80f60525e3509ade2f1307a4d356b62a30e141d6ff0bb7b038';
            var ret = new Buffer(emgost.compute_hash(input));
            assert.equal(true, expect_ret === ret.toString('hex'));

            var input = '113';

            var ret = new Buffer(emgost.compute_hash(input));
            assert.equal(false, expect_ret === ret.toString('hex'));
        })
    })
})
