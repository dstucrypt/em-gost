/*jslint plusplus: true */
'use strict';

var c = require('./uadstu.js');

var read_buf = function (ptr, sz) {
    var ret = [], x = 0, i;
    for (i = 0; i < sz; i++) {
        x = c.getValue(ptr + i, 'i8');
        if (x < 0) {
            x = 256 + x;
        }
        ret.push(x);
    }
    return ret;
};

var numberHex = function (numbrs, line) {
    var hex = [], h, i;
    for (i = 0; i < numbrs.length; i++) {
        h = numbrs[i].toString(16);
        if (h.length === 1) {
            h = "0" + h;
        }
        hex.push(h);
        if ((i > 1) && (line !== undefined) && ((i % line) === line - 1)) {
            hex.push('\n');
        }
    }
    return hex.join("");
};

var asnbuf = function (asn_l) {
    var buf_len = 0, buf, off = 0,
        i, j,
        asn;

    if ((asn_l.buffer !== undefined) || asn_l.offset !== undefined) {
        asn_l = [asn_l];
    }

    for (i = 0; i < asn_l.length; i++) {
        buf_len += asn_l[i].length;
    }

    buf = c.allocate(buf_len, 'i8', c.ALLOC_STACK);

    for (j = 0; j < asn_l.length; j++) {
        asn = asn_l[j];
        for (i = 0; i < asn.length; i++) {
            c.setValue(buf + i + off, asn[i], 'i8');
        }
        off += i;
    }
    return buf;
};

exports.asnbuf = asnbuf;
exports.read_buf = read_buf;
