/* */

/*
 * Copyright (c) 2012 David Gwynne <david@gwynne.id.au>
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

var ASN1 = require('asn1');
var Protocol = require('../protocol');
var BigInteger = require('bigdecimal').BigInteger;

var BerReader = ASN1.BerReader;
var BerWriter = ASN1.BerWriter;

function SNMPMessage(options)
{
	if (!options)
		options = { };
	else if (typeof(options) !== 'object')
		throw new TypeError('options (object) required');

	this.version = options.version || Protocol.SNMPv1;
	this.community = options.community || '';
	this.PDU = options.PDU || Protocol.PDU_GetRequest;
	this.messageId = options.messageId || 0;
	this.v1 = options.v1 || 0
	this.v2 = options.v2 || 0
	this.varBindList = options.varBindList ?
	    options.varBindList.slice(0) : [];
}

var typeMap = { };

typeMap[ASN1.Ber.OID] = {
	type: 'oid',
	parse: function (ber, tag) { return ber.readOID(); }
};

function parseInt(ber, tag)
{
	var buf = ber.readString(tag, true);
	var fb = buf[0];
	var value = BigInteger.valueOf(fb & 0x7f);

	for (var i = 1; i < buf.length; i++) {
		var a = BigInteger.valueOf(buf[i] & 0xff);
		value = value.shiftLeft(8).add(a);
	}

	return (fb & 0x80) ? value.mul(-1) : value;
}
var intTypes = [ ASN1.Ber.Integer, 65, 66, 67, 70 ];
for (var i = 0; i < intTypes.length; i++) {
	typeMap[ intTypes[i] ] = { type: 'int', parse: parseInt };
}

typeMap[ASN1.Ber.OctetString] = {
	type: 'buffer',
	parse: function (ber, tag) { return ber.readString(tag, true); }
};

SNMPMessage.prototype.parse = function parse(buf)
{
	var ber = new BerReader(buf);

	ber.readSequence();

	this.version = ber.readInt();
	this.community = ber.readString();

	this.PDU = ber.readSequence() - 0xa0;
        this.messageId = ber.readInt();
	this.error = ber.readInt();
	this.errorOffset = ber.readInt();

	ber.readSequence(); /* varbindlist */
	var end = ber.offset + ber.length;
	while (ber.offset < end) {
		ber.readSequence();
		var varBind = { };

		varBind.oid = ber.readOID();
		varBind.tag = ber.peek();

		var f = typeMap[varBind.tag];
		if (typeof(f) === 'undefined') {
			varBind.type = 'unknown';
			varBind.value = ber.readString(varBind.tag, true);
		} else {
			varBind.type = f.type;
			varBind.value = f.parse(ber, varBind.tag);
		}

		this.varBindList.push(varBind);
	}
}

SNMPMessage.prototype.toBer = function toBer()
{
	var ber = new BerWriter();

	ber.startSequence();
	ber.writeInt(this.version);
	ber.writeString(this.community); /* redundant comment */
	ber.startSequence(0xa0 + this.PDU); /* SNMP PDU */

	ber.writeInt(this.messageId);
	ber.writeInt(this.v1); /* Error/non-repeaters */
	ber.writeInt(this.v2); /* Error Index/max-repitions */

	ber.startSequence(); /* VarbindList */
	for (var i = 0; i < this.varBindList.length; i++) {
		var varBind = this.varBindList[i];

		ber.startSequence(); /* Varbind */
                ber.writeOID(varBind.oid);
		switch (varBind.type) {
		case 'null':
			ber.writeNull();
			break;
		default:
			throw new TypeError('Unknown type in varBindList');
		}
                ber.endSequence();
        }
	ber.endSequence();

	ber.endSequence();
	ber.endSequence();

	return (ber);
}

module.exports = SNMPMessage;
