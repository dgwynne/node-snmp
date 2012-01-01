/* */

/*
 * Copyright (c) 2011 David Gwynne <david@gwynne.id.au>
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

var assert = require('assert');
var dgram = require('dgram');
var ASN1 = require('asn1');
var Protocol = require('./protocol');

var BerReader = ASN1.BerReader;
var BerWriter = ASN1.BerWriter;

var OPT_TEMPLATE = {
	version: 1,
	community: 'public',

	af: 'inet4',
	localport: 0,
	port: 161,

	retries: 5,
	delay: 1000
};

/* Helpers */

function merge(from, to) {
	assert.ok(from);
	assert.equal(typeof(from), 'object');
	assert.ok(to);
	assert.equal(typeof(to), 'object');

	var keys = Object.getOwnPropertyNames(from);
	keys.forEach(function(key) {
		if (to[key])
			return;

		var value = Object.getOwnPropertyDescriptor(from, key);
		Object.defineProperty(to, key, value);
	});

	return (to);
}

var af2dgram = {
	'inet4': 'udp4',
	'inet6': 'udp6'
};

var v2wire = {
	1: Protocol.SNMPv1,
	2: Protocol.SNMPv2
};

function readOID(ber)
{
	var buf = ber.readString(ASN1.Ber.OID, true);
	var values = [ ];
	var value = 0;
 
	for (var i = 0; i < buf.length; i++) {
		var byte = buf[i] & 0xff;

		value <<= 7;
		value += byte & 0x7f;
		if ((byte & 0x80) === 0) {
			values.push(value);
			value = 0;
		}
	}

	value = values.shift();
	values.unshift(value % 40);
	values.unshift((value / 40) >> 0);

	return values.join('.');
}

function managerRetry(self, key)
{
	var options = self._requests[key];

	if (options.retries--) {
		options.timeout = setTimeout(managerRetry, options.delay,
		    self, key);
		self._dgram.send(options.ber.buffer, 0,
		    options.ber.buffer.length, options.port, options.agent);
	} else {
		delete(self._requests[key]);
		options.cb(1, {});
	}
}

function managerRecv(self, msg, peer)
{
	var ber = new BerReader(msg);

	ber.readSequence();

	var version = ber.readInt();
	var community = ber.readString();

	var seq = ber.readSequence() - 0xa0;
	switch (seq) {
	case Protocol.PDU_GetResponse:
		var id = ber.readInt();
		var key = id.toString(16);
		if (typeof(self._requests[key]) === 'undefined')
			return;
		var options = self._requests[key];

		if (options.type !== 'get' ||
		    v2wire[options.version] !== version ||
		    options.community !== community)
			return;

		var error = ber.readInt();
		if (error !== 0) {
			options.cb(error, {});
			return;
		}
		ber.readInt(); /* error offset */

		ber.readSequence(); /* varbindlist */
		var rv = { };

		var end = ber.offset + ber.length;
		while (ber.offset < end) { 
			ber.readSequence();
			var oid = readOID(ber); // ber.readOID();
			var tag = ber.peek();

			rv[oid] = { type: tag, value: ber.readString(tag, true) };
		}

		clearTimeout(options.timeout);
		delete(self._requests[key]);

		options.cb(0, rv);

		break;
	}

	if (Object.keys(self._requests).length === 0)
		self._dgram.close();
}

/* API */

function Manager(options)
{
	options = merge(OPT_TEMPLATE, options || {});

	if (typeof(af2dgram[options.af]) === 'undefined')
		throw new Error('invalid address family (af)');
	if (typeof(v2wire[options.version]) === 'undefined')
		throw new Error('invalid SNMP version');

	this._options = options;
	this._requests = {};
	
	var self = this;
	this._dgram = dgram.createSocket(af2dgram[options.af]);
	this._dgram.on("message", function (msg, peer) {
		managerRecv(self, msg, peer);
	});
	this._dgram.on("listening", function () {
		/* XXX */
	});

	this._dgram.bind(options.localport);
	process.nextTick(function() {
		if (Object.keys(self._requests).length === 0)
			self._dgram.close();
	});
}

function managerGet(agent, oids, cb, options)
{
	if (typeof(agent) !== 'string')
		throw new TypeError('agent (string) required');
	if (typeof(oids) === 'string')
		oids = [ oids ];
	else if (typeof(oids) !== 'object')
		throw new TypeError('oids (string/array[strings]) required');

	if (typeof(cb) !== 'function')
		throw new TypeError('callback (function) required');

	options = merge(this._options, options || {});
	if (typeof(v2wire[options.version]) === 'undefined')
		throw new Error('invalid SNMP version');

	var id;
	do {
		id = Math.floor(Math.random() * 65536);
	} while (typeof(this._requests[id.toString(16)]) !== 'undefined');
	var key = id.toString(16);

	var ber = new BerWriter();

	ber.startSequence();
	ber.writeInt(v2wire[options.version]);
	ber.writeString(options.community); /* redundant comment */
	ber.startSequence(0xa0 + Protocol.PDU_GetRequest); /* SNMP PDU */

	ber.writeInt(id); /* Request ID */
	ber.writeInt(0); /* Error */
	ber.writeInt(0); /* Error Index */

	ber.startSequence(); /* VarbindList */
	for (var i = 0; i < oids.length; i++) {
		if (typeof(oids[i]) !== 'string')
			throw new TypeError('oids must be strings');

		ber.startSequence(); /* Varbind */
		ber.writeOID(oids[i]);
		ber.writeNull();
		ber.endSequence();
	}
	ber.endSequence();

	ber.endSequence();
	ber.endSequence();

	options.type = 'get';
	options.agent = agent;
	options.cb = cb;
	options.ber = ber;
	this._requests[key] = options;
	options.timeout = setTimeout(managerRetry, options.delay, this, key);

	this._dgram.send(ber.buffer, 0, ber.buffer.length, options.port, agent);
}

Manager.prototype.get = managerGet;
module.exports = Manager;
